package unifideck

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"
)

// TestScenario is a named honeypot probe or synthetic IPS event.
type TestScenario struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`    // "honeypot" or "ips"
	Payload string `json:"payload"` // honeypot: bytes sent; ips: description
}

// builtinScenarios covers common attacker behaviours across different honeypot types.
var builtinScenarios = []TestScenario{
	{
		Name:    "FTP credential stuffing",
		Kind:    "honeypot",
		Payload: "USER administrator\r\nPASS Password1!\r\nUSER root\r\nPASS toor\r\nUSER admin\r\nPASS admin\r\n",
	},
	{
		Name:    "SSH version probe + auth",
		Kind:    "honeypot",
		Payload: "SSH-2.0-OpenSSH_7.9\r\n\x00\x00\x01\x14\x14", // version banner + partial KEX
	},
	{
		Name:    "HTTP admin panel brute",
		Kind:    "honeypot",
		Payload: "POST /admin/login HTTP/1.1\r\nHost: 192.168.1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 33\r\n\r\nusername=admin&password=admin123\r\n",
	},
	{
		Name:    "Malware C2 beacon",
		Kind:    "honeypot",
		Payload: "GET /gate.php?id=WIN-INFECTED&ver=2.4.1&os=10&av=0 HTTP/1.0\r\nUser-Agent: Mozilla/4.0\r\nHost: 192.168.1.1\r\n\r\n",
	},
	{
		Name:    "Telnet default credentials",
		Kind:    "honeypot",
		Payload: "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27admin\r\npassword\r\n",
	},
	{
		Name:    "Lateral movement — SMB-style probe",
		Kind:    "honeypot",
		Payload: "\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8WORKGROUP\x00INFECTED-PC\x00",
	},
	{
		Name:    "IPS: botnet C2 traffic (severity 1)",
		Kind:    "ips",
		Payload: "ET MALWARE Botnet C2 Checkin (Test Injection)",
	},
	{
		Name:    "IPS: port scan detected (severity 2)",
		Kind:    "ips",
		Payload: "ET SCAN Nmap Scripting Engine User-Agent Detected (Test)",
	},
}

// tempHoneypotPort is used exclusively by the test harness to avoid stomping user config.
const tempHoneypotPort = 19991

// RunTestScenarios runs every built-in scenario against the honeypot server and
// threat store, returning the list of ThreatEvents that were generated.
func (s *HTTPServer) RunTestScenarios() []ThreatEvent {
	// Temporarily add our dedicated test port.
	existing := s.honeypotSrv.ActivePorts()
	withTest := append(existing, tempHoneypotPort)
	s.honeypotSrv.UpdatePorts(withTest)

	// Give the listener a moment to bind.
	time.Sleep(80 * time.Millisecond)

	defer func() {
		// Remove the test port, restore only user-configured ones.
		s.honeypotSrv.UpdatePorts(existing)
	}()

	var results []ThreatEvent

	for _, sc := range builtinScenarios {
		switch sc.Kind {
		case "honeypot":
			e, err := s.probeHoneypot(tempHoneypotPort, sc.Payload)
			if err != nil {
				log.Printf("[harness] scenario %q failed: %v", sc.Name, err)
				continue
			}
			if e != nil {
				// Annotate with the scenario name so the UI is descriptive.
				e.Signature = sc.Name
				results = append(results, *e)
			}
			time.Sleep(150 * time.Millisecond)

		case "ips":
			sev := 1
			if sc.Name != "" && len(sc.Name) > 0 {
				// severity 2 for scan, 1 for malware
				if containsAny(sc.Name, "scan", "probe") {
					sev = 2
				}
			}
			e := s.injectIPSEvent("10.0.254."+fmt.Sprint(rand.Intn(254)+1), sev, sc.Payload, categoryForSeverity(sev))
			results = append(results, e)
			time.Sleep(50 * time.Millisecond)
		}
	}

	return results
}

// probeHoneypot dials the given local honeypot port, sends payload, waits for
// the event to be written to ThreatStore, then returns it.
func (s *HTTPServer) probeHoneypot(port int, payload string) (*ThreatEvent, error) {
	beforeCount := len(s.threatStore.Recent(maxThreatEvents))

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial port %d: %w", port, err)
	}

	// Read the fake service banner (we don't need its content, just drain it).
	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond)) //nolint:errcheck
	drain := make([]byte, 256)
	conn.Read(drain) //nolint:errcheck

	// Send the attacker payload.
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	conn.Write([]byte(payload))                            //nolint:errcheck
	conn.Close()

	// Allow the honeypot handler goroutine to finish and write to the store.
	time.Sleep(250 * time.Millisecond)

	events := s.threatStore.Recent(maxThreatEvents)
	if len(events) <= beforeCount {
		return nil, nil // nothing new (shouldn't happen)
	}
	e := events[0] // newest-first
	return &e, nil
}

// injectIPSEvent injects a synthetic IDS/IPS event for testing.
func (s *HTTPServer) injectIPSEvent(srcIP string, severity int, signature, category string) ThreatEvent {
	e := ThreatEvent{
		ID:        fmt.Sprintf("test-ips-%d-%d", time.Now().UnixMilli(), rand.Intn(99999)),
		Kind:      ThreatKindIPS,
		Timestamp: time.Now().UnixMilli(),
		SrcIP:     srcIP,
		DstIP:     "8.8.8.8",
		SrcPort:   rand.Intn(50000) + 10000,
		DstPort:   80,
		Proto:     "TCP",
		Severity:  severity,
		Category:  category,
		Signature: signature,
		Action:    "drop",
	}
	if client, ok := s.threatPoller.ipSnapshot()[srcIP]; ok {
		e.ClientMAC = client.MAC
		e.ClientName = client.Name
	}
	s.threatStore.Add(e)
	if severity == 1 {
		s.fireSecurityWebhook(e)
	}
	log.Printf("[harness] injected IPS event src=%s sig=%q sev=%d", srcIP, signature, severity)
	return e
}

func categoryForSeverity(sev int) string {
	switch sev {
	case 1:
		return "Malware Command and Control Activity Detected"
	case 2:
		return "Attempted Information Leak"
	default:
		return "Potentially Bad Traffic"
	}
}

func containsAny(s string, words ...string) bool {
	for _, w := range words {
		for i := 0; i <= len(s)-len(w); i++ {
			if s[i:i+len(w)] == w {
				return true
			}
		}
	}
	return false
}
