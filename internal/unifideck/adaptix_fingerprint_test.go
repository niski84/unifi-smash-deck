package unifideck

import (
	"strings"
	"testing"
)

func TestFingerprintAdaptixHTTPProfile(t *testing.T) {
	payload := "POST /c2/check HTTP/1.1\r\nHost: decoy\r\nX-Heartbeat: abc\r\nContent-Length: 32\r\n\r\n" + strings.Repeat("Q", 32)
	fp := FingerprintAdaptix(8080, []byte(payload), AdaptixProfile{
		HTTPPaths:  []string{"/c2/check"},
		HTTPHeader: "X-Heartbeat",
	})
	if fp == nil || fp.Confidence < 70 {
		t.Fatalf("expected strong HTTP profile match, got %#v", fp)
	}
}

func TestFingerprintAdaptixTCPEncryptedCandidate(t *testing.T) {
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i % 32)
	}
	fp := FingerprintAdaptix(2222, payload, AdaptixProfile{})
	if fp == nil || fp.Name != "Adaptix TCP encrypted-frame candidate" {
		t.Fatalf("expected TCP candidate, got %#v", fp)
	}
}

func TestFingerprintAdaptixRejectsPlainHTTP(t *testing.T) {
	payload := "GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: browser\r\n\r\n"
	if fp := FingerprintAdaptix(8080, []byte(payload), AdaptixProfile{}); fp != nil {
		t.Fatalf("ordinary HTTP should not be classified as Adaptix: %#v", fp)
	}
}
