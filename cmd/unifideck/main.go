package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/niski84/unifi-smash-deck/internal/unifideck"
	unifiweb "github.com/niski84/unifi-smash-deck/web"
)

func main() {
	dataDir := unifideck.DataDir()
	settingsPath := unifideck.DefaultSettingsPath()

	cfg := unifideck.LoadAppConfig(settingsPath)
	port := cfg.Port
	if port == "" {
		port = "8099"
	}

	log.Printf("[unifideck] data directory : %s", dataDir)
	log.Printf("[unifideck] settings file  : %s", settingsPath)
	if cfg.UnifiHost != "" {
		log.Printf("[unifideck] unifi host     : %s (site=%s)", cfg.UnifiHost, cfg.UnifiSite)
	} else {
		log.Printf("[unifideck] unifi host     : (not configured — use the Settings tab)")
	}

	// Strip the "unifideck/" prefix so index.html is served at /.
	webFS, err := fs.Sub(unifiweb.FS, "unifideck")
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed FS error: %v\n", err)
		os.Exit(1)
	}

	srv := unifideck.NewHTTPServer(cfg)
	handler := srv.Routes(webFS)
	srv.StartScheduler()

	httpSrv := &http.Server{
		Addr:         net.JoinHostPort("", port),
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  90 * time.Second,
	}

	go func() {
		log.Printf("[unifideck] listening on :%s", port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	srv.StopScheduler()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	log.Println("[unifideck] shutdown complete")
}
