package unifideck

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ── system.properties editor/backup ──────────────────────────────────────────

const udmSysPropsPath = "/usr/lib/unifi/data/system.properties"
const udmBackupDir = "/data/unifideck-backups"

// handleUDMSysConfig handles GET/POST /api/udm-sysconfig.
func (s *HTTPServer) handleUDMSysConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case http.MethodGet:
		// Fetch current system.properties via SSH.
		cfg := s.snapshotCfg()
		if cfg.SSHHost == "" {
			writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "SSH not configured"})
			return
		}
		client, err := udmSSHClient(cfg)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: "SSH: " + err.Error()})
			return
		}
		defer client.Close()

		content, _ := udmRun(client, "cat "+udmSysPropsPath+" 2>/dev/null")
		backupList, _ := udmRun(client, "ls -1t "+udmBackupDir+"/system.properties.*.bak 2>/dev/null | head -10")

		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
			"path":    udmSysPropsPath,
			"content": content,
			"backups": strings.Fields(strings.TrimSpace(backupList)),
		}})

	case http.MethodPost:
		var body struct {
			Action  string `json:"action"`  // "backup" | "apply" | "restore"
			Content string `json:"content"` // file content for apply; backup path for restore
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}

		cfg := s.snapshotCfg()
		if cfg.SSHHost == "" {
			writeJSON(w, http.StatusServiceUnavailable, apiResp{Success: false, Error: "SSH not configured"})
			return
		}
		client, err := udmSSHClient(cfg)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, apiResp{Success: false, Error: "SSH: " + err.Error()})
			return
		}
		defer client.Close()

		ts := time.Now().Format("20060102-150405")
		backupCmd := fmt.Sprintf("mkdir -p %s && cp %s %s/system.properties.%s.bak",
			udmBackupDir, udmSysPropsPath, udmBackupDir, ts)

		switch body.Action {

		case "backup":
			out, _ := udmRun(client, backupCmd)
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
				"backup_path": fmt.Sprintf("%s/system.properties.%s.bak", udmBackupDir, ts),
				"output":      strings.TrimSpace(out),
			}})

		case "apply":
			if body.Content == "" {
				writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "content required"})
				return
			}
			// Auto-backup before writing.
			_, _ = udmRun(client, backupCmd)

			// Write via a here-doc so we don't need to escape content.
			writeCmd := fmt.Sprintf("cat > %s << 'UNIFIDECK_EOF'\n%s\nUNIFIDECK_EOF",
				udmSysPropsPath, body.Content)
			out, _ := udmRun(client, writeCmd)

			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
				"backup_path": fmt.Sprintf("%s/system.properties.%s.bak", udmBackupDir, ts),
				"output":      strings.TrimSpace(out),
				"note":        "Run 'systemctl restart unifi' on the UDM Pro for changes to take effect.",
			}})

		case "restore":
			// body.Content holds the backup file path.
			if body.Content == "" {
				writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "content (backup path) required"})
				return
			}
			// Validate path to prevent traversal.
			if !strings.HasPrefix(body.Content, udmBackupDir+"/system.properties.") {
				writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid backup path"})
				return
			}
			_, _ = udmRun(client, backupCmd) // backup current before restoring
			out, _ := udmRun(client, fmt.Sprintf("cp %s %s", body.Content, udmSysPropsPath))
			writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
				"restored_from": body.Content,
				"output":        strings.TrimSpace(out),
				"note":          "Run 'systemctl restart unifi' on the UDM Pro for changes to take effect.",
			}})

		default:
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "unknown action"})
		}

	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}
