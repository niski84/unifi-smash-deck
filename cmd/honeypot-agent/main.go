// Command honeypot-agent runs the shared deception engine on a VLAN-local
// host and forwards normalized events to a Smash Deck controller.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/niski84/unifi-smash-deck/internal/unifideck"
)

func main() {
	controller := flag.String("controller", os.Getenv("HONEYPOT_CONTROLLER"), "Smash Deck base URL")
	token := flag.String("token", os.Getenv("HONEYPOT_TOKEN"), "agent ingest token")
	agentID := flag.String("id", hostname(), "stable agent ID")
	agentName := flag.String("name", hostname(), "display name")
	portsRaw := flag.String("ports", "2222,4444,8888,1135,1445,13389,15985,18080", "comma-separated listener ports")
	dataDir := flag.String("data-dir", "./data", "local agent data directory")
	flag.Parse()
	if strings.TrimSpace(*controller) == "" || strings.TrimSpace(*token) == "" {
		log.Fatal("-controller and -token (or HONEYPOT_CONTROLLER/HONEYPOT_TOKEN) are required")
	}
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatal(err)
	}
	ports := parsePorts(*portsRaw)
	store := unifideck.NewThreatStore(*dataDir)
	tracker := unifideck.NewClientTracker(*dataDir)
	client := &http.Client{Timeout: 10 * time.Second}
	server := unifideck.NewHoneypotServer(store, tracker, func(e unifideck.ThreatEvent) {
		payload := map[string]any{"agent_id": *agentID, "agent_name": *agentName, "event": e}
		body, _ := json.Marshal(payload)
		url := strings.TrimRight(*controller, "/") + "/api/security/agents/events"
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Printf("agent event: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Honeypot-Agent-Token", *token)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("agent delivery: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Printf("agent delivery HTTP %d", resp.StatusCode)
		}
	})
	server.SetWindowsProfile(unifideck.DefaultWindowsProfile())
	server.UpdatePorts(ports)
	log.Printf("honeypot agent %s listening on %v", *agentName, ports)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	server.StopAll()
}

func parsePorts(raw string) []int {
	var out []int
	for _, part := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}
func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "honeypot-agent"
	}
	return h
}
