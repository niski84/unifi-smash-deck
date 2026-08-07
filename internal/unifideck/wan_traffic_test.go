package unifideck

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestComputeTodayTrafficUsesLocalMidnight(t *testing.T) {
	loc, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 7, 8, 0, 0, 0, loc)
	beforeMidnight := time.Date(2026, time.August, 6, 23, 45, 0, 0, loc).Unix()
	afterMidnight := time.Date(2026, time.August, 7, 0, 15, 0, 0, loc).Unix()
	latest := time.Date(2026, time.August, 7, 7, 45, 0, 0, loc).Unix()

	rx, tx := computeTodayTrafficAt([]WANTrafficSample{
		{TS: beforeMidnight, RXBytes: 100, TXBytes: 200},
		{TS: afterMidnight, RXBytes: 150, TXBytes: 260},
		{TS: latest, RXBytes: 1_150, TXBytes: 460},
	}, now)
	if rx != 1000 || tx != 200 {
		t.Fatalf("traffic since local midnight = (%d, %d), want (1000, 200)", rx, tx)
	}
}

func TestFetchWANTrafficRejectsNonWANGatewayInterface(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[{"type":"udm","uplink":{"name":"br0","comment":"LAN","rx_bytes":900,"tx_bytes":800},"port_table":[{"is_uplink":true,"rx_bytes":900,"tx_bytes":800}]}]}`)
	}))
	defer server.Close()

	_, err := FetchWANTraffic(context.Background(), SiteConnection{Host: server.URL, SiteName: "default"})
	if err == nil {
		t.Fatal("FetchWANTraffic accepted a LAN gateway interface")
	}
}

func TestFetchWANTrafficReportsValidatedWANSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[{"type":"udm","uplink":{"name":"eth8","comment":"WAN","rx_bytes":900,"tx_bytes":800}}]}`)
	}))
	defer server.Close()

	sample, err := FetchWANTraffic(context.Background(), SiteConnection{Host: server.URL, SiteName: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if sample.Interface != "eth8" || sample.Source != "gateway WAN uplink" {
		t.Fatalf("source metadata = (%q, %q), want (eth8, gateway WAN uplink)", sample.Interface, sample.Source)
	}
}
