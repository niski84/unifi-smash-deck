package unifideck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// maskedSite returns a client-safe copy with the token redacted.
func maskedSite(s SiteConnection) SiteConnection {
	s.Token = maskKey(s.Token)
	return s
}

// handleSites serves list + create.
//
//	GET  /api/sites        → { sites: [...], active_site_id: "..." }
//	POST /api/sites        → body: SiteConnection (no ID) → returns created site
func (s *HTTPServer) handleSites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.snapshotCfg()
		out := make([]SiteConnection, 0, len(cfg.Sites))
		for _, site := range cfg.Sites {
			out = append(out, maskedSite(site))
		}
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]any{
			"sites":          out,
			"active_site_id": cfg.ActiveSiteID,
		}})

	case http.MethodPost:
		var body SiteConnection
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}
		body.Name = strings.TrimSpace(body.Name)
		body.Host = strings.TrimRight(strings.TrimSpace(body.Host), "/")
		body.Type = strings.ToLower(strings.TrimSpace(body.Type))
		body.SiteName = strings.TrimSpace(body.SiteName)
		if body.Name == "" || body.Host == "" {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "name and host are required"})
			return
		}
		if body.Type != "unifi" && body.Type != "uisp" {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "type must be 'unifi' or 'uisp'"})
			return
		}
		body.ID = newSiteID()
		if body.Type == "unifi" && body.SiteName == "" {
			body.SiteName = "default"
		}

		cur := s.snapshotCfg()
		cur.Sites = append(cur.Sites, body)
		if cur.ActiveSiteID == "" {
			cur.ActiveSiteID = body.ID
		}
		if err := SaveAppConfig(s.settingsPath, cur); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.replaceCfg(cur)
		s.logger.Info("site added: id=%s name=%q type=%s", body.ID, body.Name, body.Type)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: maskedSite(body)})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: "method not allowed"})
	}
}

// handleSiteByID serves /api/sites/{id} and /api/sites/{id}/{action}.
//
//	PUT    /api/sites/{id}              → update fields (partial)
//	DELETE /api/sites/{id}              → remove
//	POST   /api/sites/{id}/activate     → switch active site
//	POST   /api/sites/{id}/test         → test connectivity using stored creds
func (s *HTTPServer) handleSiteByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/sites/")
	parts := strings.SplitN(strings.Trim(path, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "missing site id"})
		return
	}
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	cur := s.snapshotCfg()
	idx := -1
	for i, site := range cur.Sites {
		if site.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		writeJSON(w, http.StatusNotFound, apiResp{Success: false, Error: "site not found"})
		return
	}

	switch {
	case action == "activate" && r.Method == http.MethodPost:
		cur.ActiveSiteID = id
		if err := SaveAppConfig(s.settingsPath, cur); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.replaceCfg(cur)
		s.logger.Info("site activated: id=%s name=%q", id, cur.Sites[idx].Name)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"active_site_id": id}})

	case action == "test" && r.Method == http.MethodPost:
		site := cur.Sites[idx]
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		status, err := testSiteConnection(ctx, site)
		if err != nil {
			writeJSON(w, http.StatusOK, apiResp{Success: false, Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"status": status}})

	case action == "" && r.Method == http.MethodPut:
		var body SiteConnection
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResp{Success: false, Error: "invalid JSON"})
			return
		}
		if body.Name != "" {
			cur.Sites[idx].Name = strings.TrimSpace(body.Name)
		}
		if body.Host != "" {
			cur.Sites[idx].Host = strings.TrimRight(strings.TrimSpace(body.Host), "/")
		}
		if body.Token != "" && !isMasked(body.Token) {
			cur.Sites[idx].Token = body.Token
		}
		if body.SiteName != "" {
			cur.Sites[idx].SiteName = strings.TrimSpace(body.SiteName)
		}
		if err := SaveAppConfig(s.settingsPath, cur); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.replaceCfg(cur)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: maskedSite(cur.Sites[idx])})

	case action == "" && r.Method == http.MethodDelete:
		removed := cur.Sites[idx]
		cur.Sites = append(cur.Sites[:idx], cur.Sites[idx+1:]...)
		if cur.ActiveSiteID == id {
			cur.ActiveSiteID = ""
			if len(cur.Sites) > 0 {
				cur.ActiveSiteID = cur.Sites[0].ID
			}
		}
		if err := SaveAppConfig(s.settingsPath, cur); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResp{Success: false, Error: err.Error()})
			return
		}
		s.replaceCfg(cur)
		s.logger.Info("site removed: id=%s name=%q", removed.ID, removed.Name)
		writeJSON(w, http.StatusOK, apiResp{Success: true, Data: map[string]string{"removed_id": id}})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, apiResp{Success: false, Error: fmt.Sprintf("unsupported: %s /api/sites/%s/%s", r.Method, id, action)})
	}
}

// testSiteConnection pings the appropriate API for the site's type.
func testSiteConnection(ctx context.Context, site SiteConnection) (string, error) {
	switch site.Type {
	case "unifi":
		siteName := site.SiteName
		if siteName == "" {
			siteName = "default"
		}
		c := NewUnifiClient(site.Host, site.Token, siteName)
		if !c.IsConfigured() {
			return "", fmt.Errorf("host or token is empty")
		}
		return c.TestConnection(ctx)
	case "uisp":
		return testUISPConnection(ctx, site.Host, site.Token)
	default:
		return "", fmt.Errorf("unknown site type: %s", site.Type)
	}
}
