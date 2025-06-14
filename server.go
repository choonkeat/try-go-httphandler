package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/alvinchoong/go-httphandler"
	"github.com/go-webauthn/webauthn/webauthn"
)

func httpServerFunc(ctx context.Context, config Config) error {
	// Initialize WebAuthn
	var err error
	webAuthnInstance, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Go HTTP Handler Demo",
		RPID:          config.Host,
		RPOrigins:     []string{fmt.Sprintf("http://%s:%d", config.Host, config.Port)},
	})
	if err != nil {
		return fmt.Errorf("failed to create WebAuthn: %w", err)
	}

	// Create pipelines
	sessionPipeline := httphandler.NewPipeline1(decodeSession)
	loginFormPipeline := httphandler.NewPipeline1(decodeLoginForm)
	credentialPipeline := httphandler.NewPipeline1(decodeCredentialDataOnly)
	sessionCredentialPipeline := httphandler.NewPipeline2(decodeSession, decodeCredentialData)

	mux := http.NewServeMux()

	// Routes using go-httphandler pipelines
	mux.Handle("/", httphandler.HandlePipeline1(sessionPipeline, homeHandler))
	mux.Handle("/login", httphandler.HandlePipeline1(loginFormPipeline, loginHandler))
	mux.Handle("/dashboard", httphandler.HandlePipeline1(sessionPipeline, dashboardHandler))
	mux.HandleFunc("/logout", logoutHandler)
	
	// WebAuthn routes
	mux.Handle("/passkey/register/begin", httphandler.HandlePipeline1(sessionPipeline, passkeyRegisterBeginHandler))
	mux.Handle("/passkey/register/finish", httphandler.HandlePipeline2(sessionCredentialPipeline, passkeyRegisterFinishHandler))
	mux.Handle("/passkey/login/begin", httphandler.HandlePipeline1(loginFormPipeline, passkeyLoginBeginHandler))
	mux.Handle("/passkey/login/finish", httphandler.HandlePipeline1(loginFormPipeline, passkeyLoginFinishHandler))
	mux.Handle("/passkey/primary/begin", httphandler.HandlePipeline1(loginFormPipeline, passkeyPrimaryBeginHandler))
	mux.Handle("/passkey/primary/finish", httphandler.HandlePipeline1(credentialPipeline, passkeyPrimaryFinishHandler))

	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("Server starting on http://%s", addr)

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Graceful shutdown
	log.Println("Server shutting down...")
	return server.Shutdown(context.Background())
}