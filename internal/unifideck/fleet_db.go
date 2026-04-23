package unifideck

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SiteSnapshot represents a point-in-time snapshot of a site's health metrics.
type SiteSnapshot struct {
	SiteID       string
	SiteName     string
	TS           int64
	DeviceCount  int
	ClientCount  int
	AlertCount   int
	WanLatencyMS float64
	WanLossPct   float64
	WanIsUp      bool
	ISPLabel     string
}

// DeviceSnapshot represents a point-in-time snapshot of a device's metrics.
type DeviceSnapshot struct {
	DeviceID    string
	SiteID      string
	Name        string
	Model       string
	Firmware    string
	DeviceType  string
	TS          int64
	Status      int // 0=disconnected, 1=connected
	CPUPct      float64
	RAMPct      float64
	UptimeS     int64
	PoeDraw_W   float64
	PoeBudget_W float64
	TempC       float64
	ULMbps      float64
	DLMbps      float64
}

// WANSnapshot represents a point-in-time snapshot of WAN health.
type WANSnapshot struct {
	SiteID    string
	TS        int64
	LatencyMS float64
	LossPct   float64
	DNSFails  int
	ISPLabel  string
	IsUp      bool
}

// FleetSummary aggregates fleet-wide metrics from the latest snapshots.
type FleetSummary struct {
	TotalSites    int   `json:"total_sites"`
	SitesOK       int   `json:"sites_ok"`
	SitesWarn     int   `json:"sites_warn"`
	SitesCritical int   `json:"sites_critical"`
	TotalDevices  int   `json:"total_devices"`
	TotalClients  int   `json:"total_clients"`
	LastPollTS    int64 `json:"last_poll_ts"`
}

// FleetDB manages SQLite storage for time-series fleet data.
type FleetDB struct {
	mu sync.Mutex
	db *sql.DB
}

// OpenFleetDB opens or creates the SQLite database at dataDir/fleet.db.
func OpenFleetDB(dataDir string) (*FleetDB, error) {
	dbPath := filepath.Join(dataDir, "fleet.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open fleet DB: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping fleet DB: %w", err)
	}

	// Run migrations
	if err := migrateFleet(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return &FleetDB{db: db}, nil
}

// migrateFleet creates all necessary tables and indices.
func migrateFleet(db *sql.DB) error {
	// Define all statements to run
	stmts := []string{
		// site_snapshots table
		`CREATE TABLE IF NOT EXISTS site_snapshots (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			site_id      TEXT NOT NULL,
			site_name    TEXT,
			ts           INTEGER NOT NULL,
			device_count INTEGER,
			client_count INTEGER,
			alert_count  INTEGER,
			wan_latency_ms REAL,
			wan_loss_pct REAL,
			wan_is_up    INTEGER,
			isp_label    TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ss_site_ts ON site_snapshots(site_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_ss_ts ON site_snapshots(ts)`,

		// fleet_device_snapshots table
		`CREATE TABLE IF NOT EXISTS fleet_device_snapshots (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id   TEXT NOT NULL,
			site_id     TEXT NOT NULL,
			name        TEXT,
			model       TEXT,
			firmware    TEXT,
			device_type TEXT,
			ts          INTEGER NOT NULL,
			status      INTEGER,
			cpu_pct     REAL,
			ram_pct     REAL,
			uptime_s    INTEGER,
			poe_draw_w  REAL,
			poe_budget_w REAL,
			temp_c      REAL,
			ul_mbps     REAL,
			dl_mbps     REAL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fds_device_ts ON fleet_device_snapshots(device_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_fds_site_ts ON fleet_device_snapshots(site_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_fds_ts ON fleet_device_snapshots(ts)`,

		// wan_health table
		`CREATE TABLE IF NOT EXISTS wan_health (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			site_id    TEXT NOT NULL,
			ts         INTEGER NOT NULL,
			latency_ms REAL,
			loss_pct   REAL,
			dns_fails  INTEGER,
			isp_label  TEXT,
			is_up      INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_wh_site_ts ON wan_health(site_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_wh_ts ON wan_health(ts)`,
	}

	// Run each statement
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("exec failed: %w (stmt: %s)", err, stmt)
		}
	}

	// Upgrade existing DBs by adding new columns (ignore errors if they already exist)
	_, _ = db.Exec(`ALTER TABLE fleet_device_snapshots ADD COLUMN temp_c REAL`)
	_, _ = db.Exec(`ALTER TABLE fleet_device_snapshots ADD COLUMN ul_mbps REAL`)
	_, _ = db.Exec(`ALTER TABLE fleet_device_snapshots ADD COLUMN dl_mbps REAL`)

	return nil
}

// Close closes the database connection.
func (f *FleetDB) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.db != nil {
		return f.db.Close()
	}
	return nil
}

// PruneOlderThan removes records older than the specified number of days.
func (f *FleetDB) PruneOlderThan(table string, days int) error {
	// Whitelist tables to prevent SQL injection
	validTables := map[string]bool{
		"site_snapshots":           true,
		"fleet_device_snapshots":   true,
		"wan_health":               true,
	}
	if !validTables[table] {
		return fmt.Errorf("invalid table name: %s", table)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -days).Unix()
	query := fmt.Sprintf("DELETE FROM %s WHERE ts < ?", table)
	_, err := f.db.Exec(query, cutoff)
	return err
}

// SnapshotSite inserts a site snapshot into the database.
func (f *FleetDB) SnapshotSite(s SiteSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	query := `INSERT INTO site_snapshots
		(site_id, site_name, ts, device_count, client_count, alert_count, wan_latency_ms, wan_loss_pct, wan_is_up, isp_label)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := f.db.Exec(query, s.SiteID, s.SiteName, s.TS, s.DeviceCount, s.ClientCount, s.AlertCount,
		s.WanLatencyMS, s.WanLossPct, boolToInt(s.WanIsUp), s.ISPLabel)
	return err
}

// SnapshotDevices batch-inserts device snapshots using a transaction.
func (f *FleetDB) SnapshotDevices(devs []DeviceSnapshot) error {
	if len(devs) == 0 {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	tx, err := f.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO fleet_device_snapshots
		(device_id, site_id, name, model, firmware, device_type, ts, status, cpu_pct, ram_pct, uptime_s, poe_draw_w, poe_budget_w, temp_c, ul_mbps, dl_mbps)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, dev := range devs {
		_, err := stmt.Exec(dev.DeviceID, dev.SiteID, dev.Name, dev.Model, dev.Firmware, dev.DeviceType,
			dev.TS, dev.Status, dev.CPUPct, dev.RAMPct, dev.UptimeS, dev.PoeDraw_W, dev.PoeBudget_W, dev.TempC, dev.ULMbps, dev.DLMbps)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// SnapshotWAN inserts a WAN health snapshot into the database.
func (f *FleetDB) SnapshotWAN(w WANSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	query := `INSERT INTO wan_health
		(site_id, ts, latency_ms, loss_pct, dns_fails, isp_label, is_up)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := f.db.Exec(query, w.SiteID, w.TS, w.LatencyMS, w.LossPct, w.DNSFails, w.ISPLabel, boolToInt(w.IsUp))
	return err
}

// QueryFleetSummary queries the latest fleet metrics from the database.
func (f *FleetDB) QueryFleetSummary() (*FleetSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	summary := &FleetSummary{}
	now := time.Now().Unix()
	dayAgo := now - 86400 // 24 hours

	// Count distinct sites in the last 24h
	var totalSites int
	err := f.db.QueryRow(`SELECT COUNT(DISTINCT site_id) FROM site_snapshots WHERE ts > ?`, dayAgo).Scan(&totalSites)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	summary.TotalSites = totalSites

	// Categorize sites by alert count
	var sitesOK, sitesWarn, sitesCritical int
	rows, err := f.db.Query(`
		SELECT site_id, MAX(alert_count) as max_alerts
		FROM site_snapshots
		WHERE ts > ?
		GROUP BY site_id
	`, dayAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var siteID string
		var alertCount int
		if err := rows.Scan(&siteID, &alertCount); err != nil {
			return nil, err
		}
		if alertCount > 5 {
			sitesCritical++
		} else if alertCount > 0 {
			sitesWarn++
		} else {
			sitesOK++
		}
	}

	summary.SitesOK = sitesOK
	summary.SitesWarn = sitesWarn
	summary.SitesCritical = sitesCritical

	// Sum device counts from the latest snapshot per site
	rows, err = f.db.Query(`
		SELECT SUM(device_count) FROM (
			SELECT DISTINCT ON (site_id) device_count
			FROM site_snapshots
			WHERE ts > ?
			ORDER BY site_id, ts DESC
		)
	`, dayAgo)
	if err == nil {
		defer rows.Close()
		if rows.Next() {
			var totalDevices sql.NullInt64
			rows.Scan(&totalDevices)
			if totalDevices.Valid {
				summary.TotalDevices = int(totalDevices.Int64)
			}
		}
	}

	// Sum client counts similarly
	rows, err = f.db.Query(`
		SELECT SUM(client_count) FROM (
			SELECT DISTINCT ON (site_id) client_count
			FROM site_snapshots
			WHERE ts > ?
			ORDER BY site_id, ts DESC
		)
	`, dayAgo)
	if err == nil {
		defer rows.Close()
		if rows.Next() {
			var totalClients sql.NullInt64
			rows.Scan(&totalClients)
			if totalClients.Valid {
				summary.TotalClients = int(totalClients.Int64)
			}
		}
	}

	// Get the latest timestamp
	err = f.db.QueryRow(`SELECT MAX(ts) FROM site_snapshots WHERE ts > ?`, dayAgo).Scan(&summary.LastPollTS)
	if err != nil && err != sql.ErrNoRows {
		summary.LastPollTS = 0
	}

	return summary, nil
}

// Helper function to convert bool to int (0=false, 1=true)
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
