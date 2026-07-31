package unifideck

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// fakeBanners are sent immediately on connection to make the honeypot look real
// and encourage the scanner to send credentials/payloads we can log.
var fakeBanners = map[int]string{
	21:   "220 FTP server ready\r\n",
	22:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
	23:   "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f", // Telnet IAC options
	25:   "220 mail.local ESMTP Postfix (Ubuntu)\r\n",
	110:  "+OK POP3 server ready\r\n",
	143:  "* OK IMAP4rev1 Service Ready\r\n",
	2222: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
	2121: "220 FTP server ready\r\n",
	3306: "\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x32\x37\x00", // MySQL greeting start
	3389: "",                                                 // RDP — no plain-text banner; just accept the connection
	5900: "RFB 003.008\n",                                    // VNC
	8080: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\nContent-Length: 0\r\n\r\n",
}

// HoneypotServer listens on configurable TCP ports and logs any connection
// attempts to ThreatStore. Any hit is definitively suspicious because no
// legitimate traffic should ever reach these ports.
type HoneypotServer struct {
	store     *ThreatStore
	tracker   *ClientTracker
	webhookFn func(ThreatEvent)
	profile   AdaptixProfile

	mu        sync.Mutex
	listeners map[int]net.Listener
}

func NewHoneypotServer(store *ThreatStore, tracker *ClientTracker, webhookFn func(ThreatEvent)) *HoneypotServer {
	return &HoneypotServer{
		store:     store,
		tracker:   tracker,
		webhookFn: webhookFn,
		listeners: make(map[int]net.Listener),
	}
}

func (h *HoneypotServer) SetAdaptixProfile(profile AdaptixProfile) {
	h.mu.Lock()
	h.profile = profile
	h.mu.Unlock()
}

func (h *HoneypotServer) adaptixProfile() AdaptixProfile {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.profile
}

// UpdatePorts reconciles the running listeners with the desired port list.
// Ports no longer in the list are closed; new ports are opened.
func (h *HoneypotServer) UpdatePorts(ports []int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	desired := make(map[int]bool, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			log.Printf("[honeypot] ignoring invalid port %d", p)
			continue
		}
		desired[p] = true
	}

	// Close removed ports.
	for port, ln := range h.listeners {
		if !desired[port] {
			ln.Close()
			delete(h.listeners, port)
			log.Printf("[honeypot] stopped port %d", port)
		}
	}

	// Open new ports.
	for port := range desired {
		if _, running := h.listeners[port]; running {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Printf("[honeypot] cannot bind port %d: %v", port, err)
			continue
		}
		h.listeners[port] = ln
		log.Printf("[honeypot] listening on port %d", port)
		go h.serve(ln, port)
	}
}

func (h *HoneypotServer) ConfiguredPorts(ports []int) []int {
	valid := make([]int, 0, len(ports))
	for _, p := range ports {
		if p >= 1 && p <= 65535 {
			valid = append(valid, p)
		}
	}
	return valid
}

// StopAll closes every active listener.
func (h *HoneypotServer) StopAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for port, ln := range h.listeners {
		ln.Close()
		delete(h.listeners, port)
		log.Printf("[honeypot] stopped port %d", port)
	}
}

// ActivePorts returns the ports currently being listened on.
func (h *HoneypotServer) ActivePorts() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]int, 0, len(h.listeners))
	for p := range h.listeners {
		out = append(out, p)
	}
	return out
}

func (h *HoneypotServer) serve(ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener was closed — exit quietly.
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Printf("[honeypot] accept error port %d: %v", port, err)
			return
		}
		go h.handle(conn, port)
	}
}

func (h *HoneypotServer) handle(conn net.Conn, port int) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	srcIP, _, _ := net.SplitHostPort(remoteAddr)

	log.Printf("[honeypot] HIT port=%d src=%s", port, srcIP)

	// Send fake service banner if we have one for this port.
	if banner, ok := fakeBanners[port]; ok && banner != "" {
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		conn.Write([]byte(banner))                             //nolint:errcheck
	}

	// Read up to 512 bytes of what the client sends (credentials, payloads, etc.).
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	buf := make([]byte, 512)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	buf = buf[:n]

	// Encode raw bytes as hex so control chars don't corrupt JSON/logs.
	bannerData := ""
	if n > 0 {
		bannerData = hex.EncodeToString(buf)
	}

	te := ThreatEvent{
		ID:           fmt.Sprintf("hp-%d-%s-%d", time.Now().UnixMilli(), srcIP, rand.Intn(100000)),
		Kind:         ThreatKindHoneypot,
		Timestamp:    time.Now().UnixMilli(),
		SrcIP:        srcIP,
		DstPort:      port,
		Severity:     1, // honeypot hits are always critical
		Category:     "Honeypot",
		Signature:    fmt.Sprintf("Connection to honeypot port %d", port),
		Action:       "honeypot",
		HoneypotPort: port,
		BytesRecv:    n,
		BannerData:   bannerData,
	}
	if fp := FingerprintAdaptix(port, buf, h.adaptixProfile()); fp != nil {
		te.Fingerprint = fp.Name
		te.Confidence = fp.Confidence
		te.Evidence = fp.Evidence
		te.Category = "AdaptixC2"
		te.Signature = fp.Name
	}

	// Resolve src IP to client identity.
	if client, ok := h.ipSnapshot()[srcIP]; ok {
		te.ClientMAC = client.MAC
		te.ClientName = client.Name
	}

	if h.store.Add(te) && h.webhookFn != nil {
		h.webhookFn(te)
	}
}

func (h *HoneypotServer) ipSnapshot() map[string]struct{ MAC, Name string } {
	h.tracker.mu.Lock()
	defer h.tracker.mu.Unlock()
	m := make(map[string]struct{ MAC, Name string }, len(h.tracker.known))
	for _, tc := range h.tracker.known {
		if tc.IP == "" {
			continue
		}
		name := tc.Name
		if name == "" {
			name = tc.Hostname
		}
		if name == "" {
			name = tc.MAC
		}
		m[tc.IP] = struct{ MAC, Name string }{tc.MAC, name}
	}
	return m
}
