package unifideck

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

// WindowsProfile controls the identity presented by the Windows decoy. The
// profile changes classification and safe response metadata only; it never
// enables a real vulnerable implementation.
type WindowsProfile struct {
	Enabled      bool   `json:"enabled,omitempty"`
	Persona      string `json:"persona,omitempty"` // legacy_2008_r2 | server_2012_r2 | server_2019
	OS           string `json:"os,omitempty"`
	Build        string `json:"build,omitempty"`
	PatchLevel   string `json:"patch_level,omitempty"` // legacy | current | hardened
	SMBV1        bool   `json:"smbv1,omitempty"`
	RDPNLA       bool   `json:"rdp_nla,omitempty"`
	IISVersion   string `json:"iis_version,omitempty"`
	WinRMVersion string `json:"winrm_version,omitempty"`
}

func DefaultWindowsProfile() WindowsProfile {
	return WindowsProfile{
		Enabled: true, Persona: "legacy_2008_r2", OS: "Windows Server 2008 R2 SP1",
		Build: "7601", PatchLevel: "legacy", SMBV1: true, RDPNLA: false,
		IISVersion: "IIS/7.5", WinRMVersion: "Microsoft-HTTPAPI/2.0",
	}
}

func normalizeWindowsProfile(p WindowsProfile) WindowsProfile {
	if p.Persona == "" {
		p = DefaultWindowsProfile()
	}
	// A UI/API request commonly specifies only the persona. Apply its complete
	// preset in that case so selecting Server 2019 does not retain 2008 values.
	if p.OS == "" && p.Build == "" && p.PatchLevel == "" && p.IISVersion == "" && p.WinRMVersion == "" {
		enabled := p.Enabled
		switch p.Persona {
		case "server_2012_r2":
			p = WindowsProfile{Enabled: enabled, Persona: p.Persona, OS: "Windows Server 2012 R2", Build: "9600", PatchLevel: "transitional", SMBV1: true, RDPNLA: true, IISVersion: "IIS/8.5", WinRMVersion: "Microsoft-HTTPAPI/2.0"}
		case "server_2019":
			p = WindowsProfile{Enabled: enabled, Persona: p.Persona, OS: "Windows Server 2019", Build: "17763", PatchLevel: "current", SMBV1: false, RDPNLA: true, IISVersion: "IIS/10.0", WinRMVersion: "Microsoft-HTTPAPI/2.0"}
		default:
			p = DefaultWindowsProfile()
			p.Enabled = enabled
		}
	}
	if p.OS == "" || p.Build == "" || p.IISVersion == "" || p.WinRMVersion == "" {
		d := DefaultWindowsProfile()
		if p.OS == "" {
			p.OS = d.OS
		}
		if p.Build == "" {
			p.Build = d.Build
		}
		if p.IISVersion == "" {
			p.IISVersion = d.IISVersion
		}
		if p.WinRMVersion == "" {
			p.WinRMVersion = d.WinRMVersion
		}
	}
	return p
}

type WindowsFingerprint struct {
	Name       string
	Confidence int
	Evidence   string
	Assessment string
	Persona    string
}

// FingerprintWindows classifies safe, observable Windows service probes. It
// intentionally does not parse or execute exploit payloads.
func FingerprintWindows(port int, payload []byte, profile WindowsProfile) *WindowsFingerprint {
	if len(payload) == 0 || !profile.Enabled {
		return nil
	}
	p := normalizeWindowsProfile(profile)
	if port == 445 || port == 1445 {
		return fingerprintSMB(payload, p)
	}
	if port == 3389 || port == 13389 {
		return fingerprintRDP(payload, p)
	}
	if port == 135 || port == 1135 {
		return fingerprintRPC(payload, p)
	}
	if port == 5985 || port == 15985 || port == 5986 || port == 15986 {
		return fingerprintWinRM(payload, p)
	}
	if port == 80 || port == 8080 || port == 18080 || port == 443 || port == 18443 {
		return fingerprintIIS(payload, p)
	}
	return nil
}

func windowsResult(name string, confidence int, evidence string, p WindowsProfile) *WindowsFingerprint {
	assessment := "probe_observed_not_vulnerability_confirmed"
	if p.PatchLevel == "legacy" {
		assessment = "legacy_persona_probe_observed_not_vulnerability_confirmed"
	}
	return &WindowsFingerprint{Name: name, Confidence: confidence, Evidence: evidence, Assessment: assessment, Persona: p.Persona}
}

func fingerprintSMB(b []byte, p WindowsProfile) *WindowsFingerprint {
	if len(b) < 8 || !bytes.Contains(b, []byte("SMB")) {
		return nil
	}
	evidence := []string{"SMB protocol negotiation"}
	if len(b) > 7 && bytes.Contains(b[4:8], []byte("SMB")) {
		evidence = append(evidence, "SMBv1-compatible header")
	}
	if bytes.Contains(bytes.ToUpper(b), []byte("NTLMSSP")) {
		evidence = append(evidence, "NTLM negotiation")
	}
	upper := bytes.ToUpper(b)
	for _, share := range []string{"IPC$", "ADMIN$", "C$", "PRINT$"} {
		if bytes.Contains(upper, []byte(share)) {
			evidence = append(evidence, "Windows share probe "+share)
		}
	}
	if len(b) > 8 && b[8] == 0xa0 {
		return windowsResult("MS17-010/EternalBlue check candidate", 92, strings.Join(evidence, "; "), p)
	}
	if p.SMBV1 && len(b) > 7 && bytes.Contains(b[4:8], []byte("SMB")) {
		return windowsResult("Windows SMBv1 legacy probe", 78, strings.Join(evidence, "; "), p)
	}
	if bytes.Contains(upper, []byte("NTLMSSP")) || len(evidence) > 1 {
		return windowsResult("Windows SMB enumeration candidate", 68, strings.Join(evidence, "; "), p)
	}
	return windowsResult("Windows SMB protocol probe", 55, strings.Join(evidence, "; "), p)
}

func fingerprintRDP(b []byte, p WindowsProfile) *WindowsFingerprint {
	if len(b) < 7 || b[0] != 0x03 || b[1] != 0x00 {
		return nil
	}
	evidence := "RDP TPKT/X.224 connection negotiation"
	if bytes.Contains(bytes.ToLower(b), []byte("mstshash")) {
		evidence += "; RDP cookie"
	}
	return windowsResult("RDP pre-auth/BlueKeep check candidate", 82, evidence, p)
}

func fingerprintRPC(b []byte, p WindowsProfile) *WindowsFingerprint {
	if !bytes.Contains(b, []byte("\x05\x00")) && !bytes.Contains(bytes.ToLower(b), []byte("ncacn")) {
		return nil
	}
	evidence := "DCE/RPC endpoint-mapper probe"
	lower := bytes.ToLower(b)
	for _, service := range []string{"srvsvc", "wkssvc", "browser", "\x5cpipe\x5c"} {
		if bytes.Contains(lower, []byte(service)) {
			evidence += "; NetAPI/SMB named-pipe reference"
			return windowsResult("MS08-067/NetAPI RPC check candidate", 84, evidence, p)
		}
	}
	return windowsResult("Windows RPC endpoint enumeration", 65, evidence, p)
}

func fingerprintWinRM(b []byte, p WindowsProfile) *WindowsFingerprint {
	if !bytes.Contains(bytes.ToUpper(b), []byte("HTTP/1.")) {
		return nil
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
	if err != nil || req.URL == nil {
		return nil
	}
	evidence := "Windows HTTP management probe"
	if strings.EqualFold(req.URL.Path, "/wsman") || strings.Contains(strings.ToLower(req.URL.Path), "wsman") {
		evidence += "; WS-Man endpoint"
	}
	if req.Header.Get("Authorization") != "" {
		evidence += "; authentication attempt"
	}
	return windowsResult("WinRM/WS-Man management probe", 74, evidence, p)
}

func fingerprintIIS(b []byte, p WindowsProfile) *WindowsFingerprint {
	if !bytes.Contains(bytes.ToUpper(b), []byte("HTTP/1.")) {
		return nil
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
	if err != nil || req.URL == nil {
		return nil
	}
	path := strings.ToLower(req.URL.RequestURI())
	if req.Method == "PROPFIND" || req.Method == "OPTIONS" || strings.Contains(path, "webdav") || strings.Contains(path, "..") || strings.Contains(path, "cmd.exe") || strings.Contains(path, "/msadc") || strings.Contains(path, "/_vti_bin") {
		return windowsResult("IIS/WebDAV legacy exploit probe", 80, fmt.Sprintf("HTTP %s %s; IIS legacy path or method", req.Method, req.URL.RequestURI()), p)
	}
	return windowsResult("IIS service/version probe", 58, fmt.Sprintf("HTTP %s %s", req.Method, req.URL.RequestURI()), p)
}
