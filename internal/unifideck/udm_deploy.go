package unifideck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ── Remote watchdog deploy/undeploy/status via SSH ────────────────────────────

const (
	watchdogRepo     = "niski84/udm-pro-memory-monitor"
	watchdogBinary   = "udm-pro-memory-monitor-arm64"
	watchdogRemote   = "/data/udm-pro-memory-monitor/udm-pro-memory-monitor"
	watchdogLogPath  = "/data/udm-pro-memory-monitor/watchdog.log"
	watchdogService  = "udm-pro-memory-monitor"
)

// WatchdogDeployStatus is the state of the remote watchdog on the UDM Pro.
type WatchdogDeployStatus struct {
	Installed     bool   `json:"installed"`
	ServiceStatus string `json:"service_status"` // active|inactive|failed|not-found
	MemAvailMB    int    `json:"mem_avail_mb"`
	MemTotalMB    int    `json:"mem_total_mb"`
	MemUsedPct    string `json:"mem_used_pct"`
	SwapUsedMB    int    `json:"swap_used_mb"`
	PID           string `json:"pid,omitempty"`
	RSS           string `json:"rss_kb,omitempty"`
	RecentLog     string `json:"recent_log,omitempty"` // last 15 lines
	Version       string `json:"version,omitempty"`
}

// getRemoteWatchdogStatus checks the UDM Pro for the watchdog's state.
func getRemoteWatchdogStatus(cfg AppConfig) (*WatchdogDeployStatus, error) {
	client, err := udmSSHClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("SSH: %w", err)
	}
	defer client.Close()

	status := &WatchdogDeployStatus{}

	// Check if binary exists
	out, _ := udmRun(client, "test -x "+watchdogRemote+" && echo yes || echo no")
	status.Installed = strings.TrimSpace(out) == "yes"

	// Service status
	out, _ = udmRun(client, "systemctl is-active "+watchdogService+" 2>/dev/null || echo not-found")
	status.ServiceStatus = strings.TrimSpace(out)

	// Version
	if status.Installed {
		out, _ = udmRun(client, watchdogRemote+" version 2>/dev/null")
		status.Version = strings.TrimSpace(out)
	}

	// Memory
	memRaw, _ := udmRun(client, "cat /proc/meminfo")
	mem := parseMemInfo(memRaw)
	status.MemAvailMB = int(mem.Available / 1024)
	status.MemTotalMB = int(mem.Total / 1024)
	if mem.Total > 0 {
		status.MemUsedPct = fmt.Sprintf("%.1f%%", mem.UsedPct)
	}
	status.SwapUsedMB = int((mem.SwapTotal - mem.SwapFree) / 1024)

	// Watchdog process info (exclude the grep/ssh session itself)
	out, _ = udmRun(client, "pgrep -x udm-memory-w 2>/dev/null || pgrep -f '[u]dm-memory-watchdog run' 2>/dev/null")
	if pid := strings.TrimSpace(out); pid != "" {
		status.PID = pid
		rss, _ := udmRun(client, "ps -o rss= -p "+pid+" 2>/dev/null")
		status.RSS = strings.TrimSpace(rss)
	}

	// Recent log
	out, _ = udmRun(client, "tail -15 "+watchdogLogPath+" 2>/dev/null")
	status.RecentLog = strings.TrimSpace(out)

	return status, nil
}

// watchdogReleaseURL is the GitHub releases download URL for the ARM64 binary.
const watchdogReleaseURL = "https://github.com/niski84/udm-pro-memory-monitor/releases/latest/download/udm-pro-memory-monitor-arm64"

// deployWatchdog downloads (or cross-compiles) the watchdog binary and installs it on the UDM Pro.
func deployWatchdog(ctx context.Context, cfg AppConfig, wdCfg WatchdogCfg) error {
	binPath := "/tmp/udm-pro-memory-monitor-arm64"

	// 1. Obtain the ARM64 binary.
	//    Primary:  download from GitHub releases (works on any machine).
	//    Fallback: cross-compile from local source (dev convenience).
	if err := downloadBinary(ctx, watchdogReleaseURL, binPath); err != nil {
		// Fall back to local cross-compile if source checkout exists.
		localSrc := "/home/nick/goprojects/udm-pro-memory-monitor"
		if _, statErr := os.Stat(localSrc); statErr != nil {
			return fmt.Errorf("binary download failed (%w) and local source not found at %s", err, localSrc)
		}
		cmd := exec.CommandContext(ctx, "go", "build", "-ldflags=-s -w", "-o", binPath, ".")
		cmd.Dir = localSrc
		cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64")
		if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
			return fmt.Errorf("cross-compile failed: %s: %w", string(out), buildErr)
		}
	}

	// 2. SCP the binary to the UDM Pro.
	sshArgs := sshBaseArgs(cfg)
	target := fmt.Sprintf("%s@%s:/tmp/udm-pro-memory-monitor", cfg.SSHUser, cfg.SSHHost)
	scpCmd := exec.CommandContext(ctx, "scp", append(sshArgs, binPath, target)...)
	if out, err := scpCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("scp failed: %s: %w", string(out), err)
	}

	// 3. SSH in and run the install command.
	client, err := udmSSHClient(cfg)
	if err != nil {
		return fmt.Errorf("SSH: %w", err)
	}
	defer client.Close()

	installCmd := fmt.Sprintf("chmod +x /tmp/udm-pro-memory-monitor && /tmp/udm-pro-memory-monitor install --threshold %d --interval %d --max-restarts %d",
		wdCfg.ThresholdMB, wdCfg.IntervalSecs, wdCfg.MaxRestartsDay)
	if wdCfg.DryRun {
		installCmd += " --dry-run"
	}

	out, _ := udmRun(client, installCmd)
	if !strings.Contains(out, "installed successfully") && !strings.Contains(out, "enabling") {
		// Try to detect failure
		status, _ := udmRun(client, "systemctl is-active "+watchdogService+" 2>/dev/null")
		if strings.TrimSpace(status) != "active" {
			return fmt.Errorf("install may have failed. Output: %s", out)
		}
	}

	return nil
}

// undeployWatchdog uninstalls the watchdog from the UDM Pro.
func undeployWatchdog(cfg AppConfig) error {
	client, err := udmSSHClient(cfg)
	if err != nil {
		return fmt.Errorf("SSH: %w", err)
	}
	defer client.Close()

	out, _ := udmRun(client, watchdogRemote+" uninstall --remove-binary 2>/dev/null || echo 'binary not found, cleaning up manually'")
	if strings.Contains(out, "binary not found") {
		// Manual cleanup
		udmRun(client, "systemctl stop "+watchdogService+" 2>/dev/null; systemctl disable "+watchdogService+" 2>/dev/null")
		udmRun(client, "rm -f /etc/systemd/system/"+watchdogService+".service")
		udmRun(client, "rm -f /data/on_boot.d/50-"+watchdogService+".sh")
		udmRun(client, "rm -rf /data/udm-memory-watchdog")
		udmRun(client, "systemctl daemon-reload")
	}

	return nil
}

// downloadBinary fetches a URL to a local file path, making it executable.
func downloadBinary(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

// sshBaseArgs returns common SCP/SSH flags for the configured host.
func sshBaseArgs(cfg AppConfig) []string {
	args := []string{"-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"}
	port := cfg.SSHPort
	if port == "" {
		port = "22"
	}
	args = append(args, "-P", port)
	if cfg.SSHKeyPath != "" {
		args = append(args, "-i", cfg.SSHKeyPath)
	}
	return args
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func (s *HTTPServer) handleUDMDeploy(w http.ResponseWriter, r *http.Request) {
	cfg := s.snapshotCfg()
	if cfg.SSHHost == "" {
		writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "SSH not configured"})
		return
	}

	switch r.Method {

	case http.MethodGet:
		// Get remote watchdog status
		status, err := getRemoteWatchdogStatus(cfg)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: status})

	case http.MethodPost:
		var body struct {
			Action string       `json:"action"` // deploy | undeploy
			Config *WatchdogCfg `json:"config,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}

		switch body.Action {

		case "deploy":
			wdCfg := defaultWatchdogCfg()
			if body.Config != nil {
				wdCfg = *body.Config
			}
			if wdCfg.ThresholdMB <= 0 {
				wdCfg.ThresholdMB = 512
			}
			if wdCfg.IntervalSecs < 30 {
				wdCfg.IntervalSecs = 240
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
			defer cancel()
			if err := deployWatchdog(ctx, cfg, wdCfg); err != nil {
				writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
				return
			}
			// Return fresh status
			status, _ := getRemoteWatchdogStatus(cfg)
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
				"message": "Watchdog deployed and running",
				"status":  status,
			}})

		case "undeploy":
			if err := undeployWatchdog(cfg); err != nil {
				writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
				"message": "Watchdog uninstalled",
			}})

		default:
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "action must be 'deploy' or 'undeploy'"})
		}

	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

// readBody reads and returns the request body as a string (limited to 1MB).
func readBody(r *http.Request) string {
	var buf bytes.Buffer
	io.Copy(&buf, io.LimitReader(r.Body, 1<<20))
	return buf.String()
}
