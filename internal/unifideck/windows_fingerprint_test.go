package unifideck

import "testing"

func TestFingerprintWindowsSMBMS17010(t *testing.T) {
	p := DefaultWindowsProfile()
	p.Enabled = true
	payload := []byte{0, 0, 0, 0x60, 0xff, 'S', 'M', 'B', 0xa0, 0, 0, 0, 'I', 'P', 'C', '$'}
	fp := FingerprintWindows(1445, payload, p)
	if fp == nil || fp.Name != "MS17-010/EternalBlue check candidate" {
		t.Fatalf("unexpected fingerprint: %#v", fp)
	}
}

func TestFingerprintWindowsRDP(t *testing.T) {
	p := DefaultWindowsProfile()
	fp := FingerprintWindows(13389, []byte{3, 0, 0, 19, 14, 0, 0, 0, 0, 0, 0, 0, 1, 0, 8, 0}, p)
	if fp == nil || fp.Name != "RDP pre-auth/BlueKeep check candidate" {
		t.Fatalf("unexpected fingerprint: %#v", fp)
	}
}

func TestFingerprintWindowsRPCAndWinRM(t *testing.T) {
	p := DefaultWindowsProfile()
	if fp := FingerprintWindows(1135, []byte("\x05\x00 ncacn srvsvc \\pipe\\srvsvc"), p); fp == nil || fp.Name != "MS08-067/NetAPI RPC check candidate" {
		t.Fatalf("unexpected RPC fingerprint: %#v", fp)
	}
	if fp := FingerprintWindows(15985, []byte("POST /wsman HTTP/1.1\r\nAuthorization: Negotiate\r\n\r\n"), p); fp == nil || fp.Name != "WinRM/WS-Man management probe" {
		t.Fatalf("unexpected WinRM fingerprint: %#v", fp)
	}
}

func TestFingerprintWindowsIISLegacyPath(t *testing.T) {
	p := DefaultWindowsProfile()
	fp := FingerprintWindows(18080, []byte("PROPFIND /_vti_bin/..%2fcmd.exe HTTP/1.1\r\nHost: decoy\r\n\r\n"), p)
	if fp == nil || fp.Name != "IIS/WebDAV legacy exploit probe" {
		t.Fatalf("unexpected IIS fingerprint: %#v", fp)
	}
}

func TestFingerprintWindowsDisabled(t *testing.T) {
	p := DefaultWindowsProfile()
	p.Enabled = false
	if fp := FingerprintWindows(1445, []byte{0, 0, 0, 0xff, 0xff, 'S', 'M', 'B'}, p); fp != nil {
		t.Fatalf("disabled profile produced fingerprint: %#v", fp)
	}
}

func TestNormalizeWindowsPersonaPreset(t *testing.T) {
	p := normalizeWindowsProfile(WindowsProfile{Enabled: true, Persona: "server_2019"})
	if p.OS != "Windows Server 2019" || p.Build != "17763" || p.SMBV1 || p.RDPNLA != true || p.IISVersion != "IIS/10.0" {
		t.Fatalf("unexpected Server 2019 preset: %#v", p)
	}
}
