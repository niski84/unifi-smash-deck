package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nicholasgasior/unifi-smash-deck/internal/unifideck"
)

func main() {
	cfg := unifideck.LoadAppConfig(unifideck.DefaultSettingsPath())
	port := cfg.Port
	if port == "" {
		port = "8099"
	}

	srv := unifideck.NewHTTPServer(cfg)
	handler := srv.Routes("web/unifideck")
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
