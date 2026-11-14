// Command shipshape-server is the licence server behind the Team plan.
//
//	shipshape-server keygen   print a new key pair
//	shipshape-server          serve, configured by environment variables:
//
//	STRIPE_WEBHOOK_SECRET   signing secret of the Stripe webhook endpoint (whsec_...)
//	SHIPSHAPE_PRIVATE_KEY   private key printed by keygen
//	DATA_FILE               where accounts are stored (default /data/accounts.json)
//	PORT                    port to listen on (default 8080)
//	CLIENT_IP_HEADER        header your proxy sets to the caller's address,
//	                        used for rate limiting (Fly.io: Fly-Client-IP)
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/20041540MichaelKelly/shipshape/internal/license"
	"github.com/20041540MichaelKelly/shipshape/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		pub, priv, err := license.Keygen()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Public key  (put in internal/license/license.go, safe to commit):\n  %s\n\n", pub)
		fmt.Printf("Private key (set as SHIPSHAPE_PRIVATE_KEY on the server, never commit):\n  %s\n", priv)
		return
	}

	secret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if secret == "" {
		log.Fatal("STRIPE_WEBHOOK_SECRET is not set")
	}
	priv, err := license.ParsePrivate(os.Getenv("SHIPSHAPE_PRIVATE_KEY"))
	if err != nil {
		log.Fatal("SHIPSHAPE_PRIVATE_KEY: ", err)
	}
	path := os.Getenv("DATA_FILE")
	if path == "" {
		path = "/data/accounts.json"
	}
	store, err := server.OpenStore(path)
	if err != nil {
		log.Fatal("opening ", path, ": ", err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           (&server.Server{Store: store, WebhookSecret: secret, Private: priv, ClientIPHeader: os.Getenv("CLIENT_IP_HEADER")}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Printf("shipshape-server listening on :%s, %d account(s) loaded", port, len(store.Accounts))
	log.Fatal(srv.ListenAndServe())
}
