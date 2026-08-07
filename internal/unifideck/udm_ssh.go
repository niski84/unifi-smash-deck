package unifideck

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// UDMProcess is one entry from `ps aux` on the UDM Pro.
type UDMProcess struct {
	PID     int     `json:"pid"`
	User    string  `json:"user"`
	CPUPct  float64 `json:"cpu_pct"`
	MemPct  float64 `json:"mem_pct"`
	RSS     int64   `json:"rss_kb"`
	Command string  `json:"command"` // short name (argv[0] basename)
	Cmdline string  `json:"cmdline"` // full command line (truncated)
}

// BinaryInfo holds file metadata + hash for a key executable.
type BinaryInfo struct {
	Path     string `json:"path"`
	Size     int64  `json:"size_bytes"`
	Modified string `json:"modified"`
	MD5      string `json:"md5"`
	IsLink   bool   `json:"is_symlink"`
	LinkDest string `json:"link_dest,omitempty"`
}

// MemInfo holds parsed /proc/meminfo fields in kB.
type MemInfo struct {
	Total     int64   `json:"total_kb"`
	Free      int64   `json:"free_kb"`
	Available int64   `json:"available_kb"`
	Buffers   int64   `json:"buffers_kb"`
	Cached    int64   `json:"cached_kb"`
	SwapTotal int64   `json:"swap_total_kb"`
	SwapFree  int64   `json:"swap_free_kb"`
	UsedPct   float64 `json:"used_pct"`
}

// DiskEntry is one `df -h` row.
type DiskEntry struct {
	Filesystem string `json:"filesystem"`
	Size       string `json:"size"`
	Used       string `json:"used"`
	Avail      string `json:"avail"`
	UsePct     string `json:"use_pct"`
	Mounted    string `json:"mounted"`
}

// UDMFinding is a single analysis finding from the process scan.
type UDMFinding struct {
	Severity   string `json:"severity"` // critical | warning | info
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Suggestion string `json:"suggestion"`
	Process    string `json:"process,omitempty"`
}

// UDMProcessScan is the full result returned by GET /api/udm-process-scan.
type UDMProcessScan struct {
	RunAt      time.Time    `json:"run_at"`
	Host       string       `json:"host"`
	Configured bool         `json:"configured"`
	Mem        MemInfo      `json:"mem"`
	Disk       []DiskEntry  `json:"disk"`
	Processes  []UDMProcess `json:"processes"` // top 20 by RSS
	Binaries   []BinaryInfo `json:"binaries"`  // key executables with MD5
	Findings   []UDMFinding `json:"findings"`  // automated analysis
	Error      string       `json:"error,omitempty"`
}

// key binaries to stat + hash on every scan
var udmKeyBinaries = []string{
	"/usr/bin/unifi-protect",
	"/usr/share/unifi-protect/bin/unifi-protect",
	"/usr/lib/unifi/lib/ace.jar",
	"/usr/bin/mongod",
	"/usr/bin/suricata",
	"/usr/bin/unifi-core",
	"/usr/sbin/ulp-go-app",
	"/usr/bin/mst",
	"/usr/bin/ms",
}

// ── SSH dialer ────────────────────────────────────────────────────────────────

func udmSSHClient(cfg AppConfig) (*ssh.Client, error) {
	if cfg.SSHHost == "" {
		return nil, fmt.Errorf("SSH host not configured (UNIFICERT_SSH_HOST)")
	}

	var authMethods []ssh.AuthMethod

	// Key-based auth (preferred)
	if cfg.SSHKeyPath != "" {
		keyPath := cfg.SSHKeyPath
		if strings.HasPrefix(keyPath, "~/") {
			home, _ := os.UserHomeDir()
			keyPath = filepath.Join(home, keyPath[2:])
		}
		pemBytes, err := os.ReadFile(keyPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(pemBytes)
			if err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	// ssh-agent (handles passphrase-protected keys)
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}

	// Password fallback
	if cfg.SSHPassword != "" {
		authMethods = append(authMethods, ssh.Password(cfg.SSHPassword))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH auth methods available (set UNIFICERT_SSH_KEY or UNIFICERT_SSH_PASSWORD)")
	}

	// Host key verification
	var hostKeyCallback ssh.HostKeyCallback
	if cfg.SSHKnownHosts != "" {
		khPath := cfg.SSHKnownHosts
		if strings.HasPrefix(khPath, "~/") {
			home, _ := os.UserHomeDir()
			khPath = filepath.Join(home, khPath[2:])
		}
		cb, err := knownhosts.New(khPath)
		if err == nil {
			hostKeyCallback = cb
		}
	}
	if hostKeyCallback == nil {
		hostKeyCallback = ssh.InsecureIgnoreHostKey() // fallback if known_hosts not set
	}

	user := cfg.SSHUser
	if user == "" {
		user = "root"
	}
	port := cfg.SSHPort
	if port == "" {
		port = "22"
	}

	sshCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	return ssh.Dial("tcp", net.JoinHostPort(cfg.SSHHost, port), sshCfg)
}

// udmRun runs a single command over an existing SSH client.
func udmRun(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var buf bytes.Buffer
	sess.Stdout = &buf
	_ = sess.Run(cmd)
	return buf.String(), nil
}

// ── Process scan ──────────────────────────────────────────────────────────────

func RunUDMProcessScan(ctx context.Context, cfg AppConfig) (*UDMProcessScan, error) {
	scan := &UDMProcessScan{
		RunAt:      time.Now().UTC(),
		Host:       cfg.SSHHost,
		Configured: cfg.SSHHost != "",
	}
	if !scan.Configured {
		return scan, nil
	}

	client, err := udmSSHClient(cfg)
	if err != nil {
		scan.Error = err.Error()
		return scan, nil // return partial result, not a fatal error
	}
	defer client.Close()

	// Run all commands; ignore individual errors (best-effort)
	memRaw, _ := udmRun(client, "cat /proc/meminfo")
	dfRaw, _ := udmRun(client, "df -h")
	psRaw, _ := udmRun(client, "ps aux --sort=-%mem")

	// Build binary list: stat + md5sum in one round-trip
	binPaths := strings.Join(udmKeyBinaries, " ")
	statRaw, _ := udmRun(client, "stat "+binPaths+" 2>/dev/null")
	md5Raw, _ := udmRun(client, "md5sum "+binPaths+" 2>/dev/null")
	linkRaw, _ := udmRun(client, "readlink -f "+binPaths+" 2>/dev/null; echo END")

	scan.Mem = parseMemInfo(memRaw)
	scan.Disk = parseDf(dfRaw)
	scan.Processes = parsePS(psRaw, 20)
	scan.Binaries = parseBinaries(statRaw, md5Raw, linkRaw)
	scan.Findings = AnalyzeUDMScan(scan)

	return scan, nil
}

// AnalyzeUDMScan inspects a completed scan and returns actionable findings.
func AnalyzeUDMScan(scan *UDMProcessScan) []UDMFinding {
	var findings []UDMFinding
	add := func(sev, title, detail, suggestion, process string) {
		findings = append(findings, UDMFinding{
			Severity:   sev,
			Title:      title,
			Detail:     detail,
			Suggestion: suggestion,
			Process:    process,
		})
	}

	// ── Disk ──────────────────────────────────────────────────────────────────
	for _, d := range scan.Disk {
		pct := 0
		fmt.Sscanf(strings.TrimSuffix(d.UsePct, "%"), "%d", &pct)
		// Skip read-only and loop filesystems — full by design
		if strings.HasPrefix(d.Filesystem, "/dev/loop") || d.Mounted == "/mnt/.rofs" {
			continue
		}
		// /boot/firmware (root partition) is small and typically 99% — low signal
		if d.Mounted == "/boot/firmware" {
			if pct >= 99 {
				add("info", "Boot partition nearly full",
					fmt.Sprintf("%s mounted at %s is %s used (%s/%s)", d.Filesystem, d.Mounted, d.UsePct, d.Used, d.Size),
					"This is normal for UDM Pro — the firmware partition is read-only in normal operation. No action needed.",
					"")
			}
			continue
		}
		if pct >= 95 {
			sev := "critical"
			if pct < 98 {
				sev = "warning"
			}
			add(sev, fmt.Sprintf("Disk nearly full: %s", d.Mounted),
				fmt.Sprintf("%s (%s) is %s used — only %s free of %s total", d.Filesystem, d.Mounted, d.UsePct, d.Avail, d.Size),
				"Protect will stop recording when storage is full. Review retention settings under Protect → Storage, or add/replace the drive.",
				"")
		}
	}

	// ── Memory ────────────────────────────────────────────────────────────────
	if scan.Mem.Total > 0 {
		swapUsed := scan.Mem.SwapTotal - scan.Mem.SwapFree
		swapUsedPct := float64(0)
		if scan.Mem.SwapTotal > 0 {
			swapUsedPct = float64(swapUsed) / float64(scan.Mem.SwapTotal) * 100
		}

		if scan.Mem.UsedPct >= 90 {
			add("critical", fmt.Sprintf("Memory critically high: %.1f%% used", scan.Mem.UsedPct),
				fmt.Sprintf("Only %d MB available of %d MB total RAM. System is actively swapping, degrading performance.", scan.Mem.Available/1024, scan.Mem.Total/1024),
				"Immediate actions: (1) Lower Suricata to Balanced in Network → Security → Threat Management. "+
					"(2) Set unifi.xmx=512, unifi.xms=256, db.mongo.wt.cache_size=128 in /usr/lib/unifi/data/system.properties + restart unifi. "+
					"(3) Consider deploying udm-pro-memory-monitor (github.com/pridkett/udm-pro-memory-monitor) as a leak backstop.",
				"")
		} else if scan.Mem.UsedPct >= 80 {
			add("warning", fmt.Sprintf("Memory pressure: %.1f%% used", scan.Mem.UsedPct),
				fmt.Sprintf("%d MB available of %d MB total. High memory is normal on a 4 GB UDM Pro running Network + Protect + IPS, but this is in the warning zone.", scan.Mem.Available/1024, scan.Mem.Total/1024),
				"To reclaim 300–500 MB: set db.mongo.wt.cache_size=128 and unifi.xmx=512 in /usr/lib/unifi/data/system.properties, "+
					"and lower Suricata to Balanced in the UI.",
				"")
		}

		if swapUsed > 512*1024 { // > 512 MB swap in use
			add("warning", fmt.Sprintf("Swap in use: %d MB (%.0f%% of swap)", swapUsed/1024, swapUsedPct),
				"Active swap degrades router and firewall performance. Known memory leaks in unifi-protect and ace.jar cause gradual growth over 12–24 hours.",
				"Apply system.properties tuning (see other findings). Deploy github.com/pridkett/udm-pro-memory-monitor "+
					"to auto-restart UniFi OS when free memory drops below 512 MB.",
				"")
		}
	}

	// ── Per-process analysis ───────────────────────────────────────────────────
	for _, p := range scan.Processes {
		switch {

		case p.Command == "suricata" || strings.Contains(p.Cmdline, "suricata"):
			if strings.Contains(p.Cmdline, "_high.yaml") {
				add("warning", "Suricata IPS running on HIGH profile",
					fmt.Sprintf("suricata is consuming %d MB RSS (%.1f%% of RAM) using suricata_ubios_high.yaml. "+
						"The high profile sets large memcaps — particularly stream.reassembly.memcap (≥256 MB) — "+
						"which is the single largest contributor to Suricata's memory footprint.", p.RSS/1024, p.MemPct),
					"Switch to Balanced in Network → Security → Threat Management → Intrusion Prevention → Performance. "+
						"The balanced profile reduces stream reassembly limits to ~64–128 MB, typically saving 100–150 MB RAM. "+
						"For a home/SOHO network the detection coverage difference is negligible.",
					"suricata")
			}

		case p.Command == "java" || strings.Contains(p.Cmdline, "ace.jar"):
			if p.RSS > 600*1024 {
				add("info", fmt.Sprintf("UniFi Network app (Java) using %d MB RSS", p.RSS/1024),
					fmt.Sprintf("ace.jar is using %d MB RSS. The default JVM heap is unifi.xmx=1024 (1 GB), "+
						"which on a 4 GB UDM Pro running Protect + IPS leaves very little headroom.", p.RSS/1024),
					"Edit /usr/lib/unifi/data/system.properties and set:\n"+
						"  unifi.xmx=512\n  unifi.xms=256\n  db.mongo.wt.cache_size=128\n"+
						"Then: systemctl restart unifi\n"+
						"Use unifios-utilities (github.com/unifi-utilities/unifios-utilities) to persist these across firmware updates.",
					"java (ace.jar)")
			}

		case p.Command == "mongod":
			add("info", fmt.Sprintf("MongoDB WiredTiger cache may be uncapped (%d MB RSS)", p.RSS/1024),
				"MongoDB WiredTiger defaults to 50%% of RAM minus 1 GB (~1 GB on a 4 GB system). "+
					"For a small home network, 128 MB is sufficient and frees significant RAM.",
				"Add db.mongo.wt.cache_size=128 to /usr/lib/unifi/data/system.properties then: systemctl restart unifi. "+
					"Community reports show mongod dropping from 400–800 MB to under 200 MB with this change.",
				"mongod")

		case p.Command == "ms" && p.CPUPct > 10:
			add("warning", fmt.Sprintf("Media Server (ms) high CPU: %.1f%%", p.CPUPct),
				"The UniFi media server (ms/mst) handles Protect video transcoding. Elevated CPU is normal during active viewing "+
					"or motion event processing but may indicate too many concurrent streams.",
				"Check active Protect streams/exports. Reducing camera resolution or frame rate lowers transcoding load. "+
					"High-quality exports running in the background are a common cause.",
				"ms")
		}
	}

	// Order: critical first, then warning, then info
	order := map[string]int{"critical": 0, "warning": 1, "info": 2}
	sort.Slice(findings, func(i, j int) bool {
		return order[findings[i].Severity] < order[findings[j].Severity]
	})
	return findings
}

// handleUDMProcessScan scans running UDM processes over SSH and returns the findings.
func (s *HTTPServer) handleUDMProcessScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cfg := s.snapshotCfg()
	scan, err := RunUDMProcessScan(ctx, cfg)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResp{Success: true, Data: scan})
}

// ── Parsers ───────────────────────────────────────────────────────────────────

func parseMemInfo(raw string) MemInfo {
	m := MemInfo{}
	fields := map[string]*int64{
		"MemTotal":     &m.Total,
		"MemFree":      &m.Free,
		"MemAvailable": &m.Available,
		"Buffers":      &m.Buffers,
		"Cached":       &m.Cached,
		"SwapTotal":    &m.SwapTotal,
		"SwapFree":     &m.SwapFree,
	}
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		if ptr, ok := fields[key]; ok {
			v, _ := strconv.ParseInt(parts[1], 10, 64)
			*ptr = v
		}
	}
	if m.Total > 0 {
		used := m.Total - m.Available
		m.UsedPct = float64(used) / float64(m.Total) * 100
		m.UsedPct = float64(int(m.UsedPct*10)) / 10
	}
	return m
}

func parseDf(raw string) []DiskEntry {
	var out []DiskEntry
	for i, line := range strings.Split(raw, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		out = append(out, DiskEntry{
			Filesystem: parts[0],
			Size:       parts[1],
			Used:       parts[2],
			Avail:      parts[3],
			UsePct:     parts[4],
			Mounted:    parts[5],
		})
	}
	return out
}

func parsePS(raw string, limit int) []UDMProcess {
	var out []UDMProcess
	for i, line := range strings.Split(raw, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		// USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND...
		parts := strings.Fields(line)
		if len(parts) < 11 {
			continue
		}
		pid, _ := strconv.Atoi(parts[1])
		cpu, _ := strconv.ParseFloat(parts[2], 64)
		mem, _ := strconv.ParseFloat(parts[3], 64)
		rss, _ := strconv.ParseInt(parts[5], 10, 64)

		cmdFull := strings.Join(parts[10:], " ")
		cmdName := filepath.Base(parts[10])
		if len(cmdFull) > 120 {
			cmdFull = cmdFull[:120] + "…"
		}

		out = append(out, UDMProcess{
			PID:     pid,
			User:    parts[0],
			CPUPct:  cpu,
			MemPct:  mem,
			RSS:     rss,
			Command: cmdName,
			Cmdline: cmdFull,
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func parseBinaries(statRaw, md5Raw, linkRaw string) []BinaryInfo {
	// Parse md5sum output into map[path]hash
	hashes := map[string]string{}
	for _, line := range strings.Split(md5Raw, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			hashes[parts[1]] = parts[0]
		}
	}

	// Parse readlink output into map[path]realpath
	links := map[string]string{}
	linkLines := strings.Split(linkRaw, "\n")
	for i, orig := range udmKeyBinaries {
		if i < len(linkLines) {
			dest := strings.TrimSpace(linkLines[i])
			if dest != "" && dest != "END" && dest != orig {
				links[orig] = dest
			}
		}
	}

	// Parse stat output; each file produces a block starting with "  File: "
	byPath := map[string]BinaryInfo{}
	var cur BinaryInfo
	for _, line := range strings.Split(statRaw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "File:") {
			// Save previous
			if cur.Path != "" {
				byPath[cur.Path] = cur
			}
			raw := strings.TrimPrefix(line, "File:")
			raw = strings.TrimSpace(raw)
			// May be "path -> dest" for symlinks
			if idx := strings.Index(raw, " -> "); idx >= 0 {
				cur = BinaryInfo{Path: raw[:idx], IsLink: true, LinkDest: raw[idx+4:]}
			} else {
				cur = BinaryInfo{Path: raw}
			}
			cur.MD5 = hashes[cur.Path]
			if d, ok := links[cur.Path]; ok {
				cur.IsLink = true
				cur.LinkDest = d
				// Use the real path's hash if the link itself has no md5
				if cur.MD5 == "" {
					cur.MD5 = hashes[d]
				}
			}
		} else if strings.HasPrefix(line, "Size:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				cur.Size, _ = strconv.ParseInt(parts[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "Modify:") {
			cur.Modified = strings.TrimPrefix(line, "Modify: ")
		}
	}
	if cur.Path != "" {
		byPath[cur.Path] = cur
	}

	// Return in canonical order
	var out []BinaryInfo
	seen := map[string]bool{}
	for _, path := range udmKeyBinaries {
		if b, ok := byPath[path]; ok && !seen[path] {
			seen[path] = true
			out = append(out, b)
		}
	}
	// Sort by path for determinism
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// ── Snapshot helpers ──────────────────────────────────────────────────────────

// UDMBinarySnapshot is the subset stored in config snapshots.
type UDMBinarySnapshot struct {
	CapturedAt string               `json:"captured_at"`
	Host       string               `json:"host"`
	Binaries   []BinaryInfo         `json:"binaries"`
	TopProcs   []UDMProcessSnapshot `json:"top_procs"`
}

type UDMProcessSnapshot struct {
	Command string  `json:"command"`
	User    string  `json:"user"`
	MemPct  float64 `json:"mem_pct"`
	RSS     int64   `json:"rss_kb"`
}

// CaptureUDMBinarySnapshot runs a process scan and returns the snapshot-ready form.
func CaptureUDMBinarySnapshot(ctx context.Context, cfg AppConfig) (*UDMBinarySnapshot, error) {
	scan, err := RunUDMProcessScan(ctx, cfg)
	if err != nil || !scan.Configured {
		return nil, err
	}
	snap := &UDMBinarySnapshot{
		CapturedAt: scan.RunAt.Format(time.RFC3339),
		Host:       scan.Host,
		Binaries:   scan.Binaries,
	}
	for _, p := range scan.Processes {
		snap.TopProcs = append(snap.TopProcs, UDMProcessSnapshot{
			Command: p.Command,
			User:    p.User,
			MemPct:  p.MemPct,
			RSS:     p.RSS,
		})
		if len(snap.TopProcs) >= 10 {
			break
		}
	}
	return snap, nil
}

// MD5String returns an MD5 hex digest of the given string (for internal use).
func MD5String(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
