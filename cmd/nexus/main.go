package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ER-brocode/nexus-git-registry/pkg/proxy"
)

func main() {
	port := flag.Int("port", 5000, "Registry listen HTTP port")
	baseDir := flag.String("data-dir", "./data/nexus", "Base directory for blob storage")
	gitDir := flag.String("git-dir", "./data/git-meta", "Directory for Git-native manifest tree")
	peers := flag.String("peers", "", "Comma-separated list of peer container cache endpoints")
	realm := flag.String("auth-realm", "http://localhost:5000/v2/token", "Authentication realm endpoint")
	requireAuth := flag.Bool("require-auth", false, "Require authentication for registry operations")
	flag.Parse()

	log.Printf("----------------------------------------------------------------")
	log.Printf("Nexus Git Registry: Distributed Git-Native Artifact Registry")
	log.Printf("OCI Image Spec v1.1.0 | Git Tree Storage | FastCDC Deduplication")
	log.Printf("----------------------------------------------------------------")

	var peerList []string
	if *peers != "" {
		peerList = strings.Split(*peers, ",")
	}

	cfg := proxy.Config{
		BaseDir:  *baseDir,
		GitDir:   *gitDir,
		Realm:    *realm,
		Service:  "nexus-git-registry",
		P2PPeers:    peerList,
		RequireAuth: *requireAuth,
	}

	server, err := proxy.NewServer(cfg)
	if err != nil {
		log.Fatalf("Fatal: failed to initialize Nexus engine: %v", err)
	}

	if *requireAuth {
		username := os.Getenv("NEXUS_ADMIN_USERNAME")
		password := os.Getenv("NEXUS_ADMIN_PASSWORD")
		if username == "" || password == "" {
			log.Fatal("NEXUS_ADMIN_USERNAME and NEXUS_ADMIN_PASSWORD must be set when -require-auth is enabled")
		}
		server.Authenticator().AddUser(username, password)
	}

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      server,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		log.Printf("Nexus Git Registry listening on :%d (Ready for docker / nerdctl / podman / cosign)", *port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down Nexus Registry...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Nexus Registry gracefully exited.")
}
