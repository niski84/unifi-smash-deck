package unifideck

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
)

// AdaptixProfile contains the operator-controlled values from an Adaptix HTTP
// listener profile. Adaptix deliberately lets operators customize these values,
// so matching should use the generated profile when available rather than a
// brittle hard-coded URI or User-Agent.
type AdaptixProfile struct {
	HTTPPaths      []string `json:"http_paths,omitempty"`
	HTTPHeader     string   `json:"http_header,omitempty"`
	HTTPUserAgents []string `json:"http_user_agents,omitempty"`
	DNSSuffixes    []string `json:"dns_suffixes,omitempty"`
}

type AdaptixFingerprint struct {
	Name       string `json:"name"`
	Confidence int    `json:"confidence"`
	Evidence   string `json:"evidence"`
}

var encodedValueRE = regexp.MustCompile(`^[A-Za-z0-9+/_=-]{24,}$`)

// FingerprintAdaptix returns a candidate fingerprint. It never decrypts,
// executes, or treats a match as proof; it only records observable wire traits.
func FingerprintAdaptix(port int, payload []byte, profile AdaptixProfile) *AdaptixFingerprint {
	if len(payload) == 0 {
		return nil
	}
	if fp := fingerprintHTTP(payload, profile); fp != nil {
		return fp
	}
	if fp := fingerprintTCP(payload); fp != nil {
		return fp
	}
	return nil
}

func fingerprintHTTP(payload []byte, profile AdaptixProfile) *AdaptixFingerprint {
	if !bytes.Contains(payload, []byte("HTTP/1.")) || !bytes.Contains(payload, []byte("\r\n")) {
		return nil
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil || req.URL == nil {
		return nil
	}
	score := 0
	var evidence []string
	path := req.URL.Path
	for _, candidate := range profile.HTTPPaths {
		if strings.TrimSpace(candidate) == path {
			score += 55
			evidence = append(evidence, "configured callback URI")
			break
		}
	}
	if profile.HTTPHeader != "" && req.Header.Get(profile.HTTPHeader) != "" {
		score += 25
		evidence = append(evidence, "configured heartbeat header")
	}
	for _, ua := range profile.HTTPUserAgents {
		if strings.EqualFold(strings.TrimSpace(ua), req.UserAgent()) {
			score += 20
			evidence = append(evidence, "configured User-Agent")
			break
		}
	}
	encoded := false
	for key, values := range req.URL.Query() {
		for _, value := range values {
			if encodedValueRE.MatchString(value) {
				encoded = true
				evidence = append(evidence, "encoded callback parameter "+key)
			}
		}
	}
	if req.Body != nil {
		var body bytes.Buffer
		_, _ = body.ReadFrom(req.Body)
		for _, value := range strings.FieldsFunc(body.String(), func(r rune) bool { return r == '&' || r == '=' || r == ' ' || r == '\n' }) {
			if encodedValueRE.MatchString(value) {
				encoded = true
				evidence = append(evidence, "encoded callback body")
				break
			}
		}
	}
	if encoded {
		score += 30
	}
	if score < 45 {
		return nil
	}
	if score > 100 {
		score = 100
	}
	return &AdaptixFingerprint{Name: "Adaptix HTTP callback candidate", Confidence: score, Evidence: strings.Join(uniqueStrings(evidence), "; ")}
}

func fingerprintTCP(payload []byte) *AdaptixFingerprint {
	if len(payload) < 16 || printableRatio(payload) > 0.35 || shannonEntropy(payload) < 4.5 {
		return nil
	}
	return &AdaptixFingerprint{
		Name:       "Adaptix TCP encrypted-frame candidate",
		Confidence: 55,
		Evidence:   fmt.Sprintf("%d-byte high-entropy binary opening; consistent with RC4-framed agent metadata", len(payload)),
	}
}

func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 1
	}
	n := 0
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			n++
		}
	}
	return float64(n) / float64(len(b))
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var entropy float64
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / float64(len(b))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
