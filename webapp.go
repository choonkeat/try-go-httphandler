package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/alvinchoong/go-httphandler"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Config struct {
	Host string
	Port int
}

type LoginFormData struct {
	Method string
	Email  string
}

type SessionData struct {
	Email string
}

type DashboardData struct {
	Email        string
	PasskeyCount int
}

type HTMLResponder struct {
	Template string
	Data     interface{}
}

func (h HTMLResponder) Respond(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles(h.Template)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}
	
	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, h.Data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

type ErrorResponder struct {
	Message string
	Status  int
}

func (e ErrorResponder) Respond(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":  e.Message,
		"status": "error",
	})
}

type JSONResponder struct {
	Data    interface{}
	Cookies []*http.Cookie
}

func (j JSONResponder) Respond(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range j.Cookies {
		http.SetCookie(w, cookie)
	}
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(j.Data); err != nil {
		log.Printf("JSON encoding error: %v", err)
	}
}

func httpServerFunc(ctx context.Context, config Config) error {
	// Initialize WebAuthn
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Go HTTP Handler Demo",
		RPID:          config.Host,
		RPOrigins:     []string{fmt.Sprintf("http://%s:%d", config.Host, config.Port)},
	})
	if err != nil {
		return fmt.Errorf("failed to create WebAuthn: %w", err)
	}

	// Create pipelines
	sessionPipeline := httphandler.NewPipeline1(extractSession)
	loginFormPipeline := httphandler.NewPipeline1(extractLoginForm)

	mux := http.NewServeMux()

	// Routes using go-httphandler pipelines
	mux.Handle("/", httphandler.HandlePipeline1(sessionPipeline, homeHandler))
	mux.Handle("/login", httphandler.HandlePipeline1(loginFormPipeline, loginHandler))
	mux.Handle("/dashboard", httphandler.HandlePipeline1(sessionPipeline, dashboardHandler))
	mux.HandleFunc("/logout", logoutHandler)
	
	// WebAuthn routes
	mux.Handle("/passkey/register/begin", httphandler.HandlePipeline1(sessionPipeline, passkeyRegisterBeginHandler))
	mux.Handle("/passkey/register/finish", httphandler.HandlePipeline1(sessionPipeline, passkeyRegisterFinishHandler))
	mux.Handle("/passkey/login/begin", httphandler.HandlePipeline1(loginFormPipeline, passkeyLoginBeginHandler))
	mux.Handle("/passkey/login/finish", httphandler.HandlePipeline1(loginFormPipeline, passkeyLoginFinishHandler))
	mux.Handle("/passkey/primary/begin", httphandler.HandlePipeline1(loginFormPipeline, passkeyPrimaryBeginHandler))
	mux.Handle("/passkey/primary/finish", httphandler.HandlePipeline1(loginFormPipeline, passkeyPrimaryFinishHandler))

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

func extractSession(r *http.Request) (SessionData, error) {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		return SessionData{}, nil // Not authenticated, but not an error
	}
	return SessionData{Email: cookie.Value}, nil
}

func extractLoginForm(r *http.Request) (LoginFormData, error) {
	return LoginFormData{
		Method: r.Method,
		Email:  r.FormValue("email"),
	}, nil
}

func homeHandler(ctx context.Context, session SessionData) httphandler.Responder {
	// If authenticated, redirect to dashboard
	if session.Email != "" {
		return httphandler.Redirect("/dashboard", http.StatusSeeOther)
	}
	
	// Show login form
	return HTMLResponder{
		Template: "templates/login.html",
		Data:     nil,
	}
}

func loginHandler(ctx context.Context, loginForm LoginFormData) httphandler.Responder {
	if loginForm.Method == "GET" {
		return HTMLResponder{
			Template: "templates/login.html",
			Data:     nil,
		}
	}
	
	if loginForm.Method == "POST" {
		email := loginForm.Email
		if email == "" {
			return HTMLResponder{
				Template: "templates/login.html",
				Data:     nil,
			}
		}
		
		// Mock success - always authenticate
		return httphandler.Redirect("/dashboard", http.StatusSeeOther).
			WithCookie(&http.Cookie{
				Name:     "session",
				Value:    email,
				Path:     "/",
				HttpOnly: true,
			})
	}
	
	return ErrorResponder{Message: "Method not allowed", Status: http.StatusMethodNotAllowed}
}

func dashboardHandler(ctx context.Context, session SessionData) httphandler.Responder {
	if session.Email == "" {
		return httphandler.Redirect("/", http.StatusSeeOther)
	}
	
	return HTMLResponder{
		Template: "templates/dashboard.html",
		Data: DashboardData{
			Email:        session.Email,
			PasskeyCount: getPassKeyCount(session.Email),
		},
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// WebAuthn handlers
func passkeyRegisterBeginHandler(ctx context.Context, session SessionData) httphandler.Responder {
	if session.Email == "" {
		return ErrorResponder{Message: "Not authenticated", Status: http.StatusUnauthorized}
	}
	
	log.Printf("Starting passkey registration for user: %s", session.Email)
	
	user := getWebAuthnUser(session.Email)
	options, sessionData, err := webAuthn.BeginRegistration(user)
	if err != nil {
		log.Printf("BeginRegistration error for %s: %v", session.Email, err)
		return ErrorResponder{Message: "Registration failed", Status: http.StatusInternalServerError}
	}
	
	log.Printf("Generated registration options for %s", session.Email)
	
	// Store session data in cookie (simple POC approach)
	sessionJSON, _ := json.Marshal(sessionData)
	
	return JSONResponder{
		Data: options,
		Cookies: []*http.Cookie{{
			Name:     "webauthn_session",
			Value:    base64.StdEncoding.EncodeToString(sessionJSON),
			HttpOnly: true,
			Path:     "/",
		}},
	}
}

func passkeyRegisterFinishHandler(ctx context.Context, session SessionData) httphandler.Responder {
	if session.Email == "" {
		return ErrorResponder{Message: "Not authenticated", Status: http.StatusUnauthorized}
	}
	
	log.Printf("Passkey registration finish for user: %s", session.Email)
	
	// For POC, we'll just fake a successful registration
	// In a real implementation, you'd parse the credential from the request body
	// and call webAuthn.FinishRegistration()
	
	// Simulate saving a passkey
	fakeCredential := &webauthn.Credential{
		ID:              []byte("fake-credential-id"),
		PublicKey:       []byte("fake-public-key"),
		AttestationType: "none",
	}
	
	savePassKey(session.Email, fakeCredential)
	log.Printf("Saved passkey for user %s. Total passkeys: %d", session.Email, getPassKeyCount(session.Email))
	
	return JSONResponder{Data: map[string]string{"status": "success"}}
}

func passkeyLoginBeginHandler(ctx context.Context, loginForm LoginFormData) httphandler.Responder {
	if loginForm.Email == "" {
		return ErrorResponder{Message: "Email required", Status: http.StatusBadRequest}
	}
	
	log.Printf("Checking passkeys for user: %s", loginForm.Email)
	
	user := getWebAuthnUser(loginForm.Email)
	if len(user.Credentials) == 0 {
		log.Printf("No passkeys found for user: %s", loginForm.Email)
		return ErrorResponder{Message: "No passkeys found", Status: http.StatusNotFound}
	}
	
	log.Printf("Found %d passkeys for user: %s", len(user.Credentials), loginForm.Email)
	
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Printf("BeginLogin error for %s: %v", loginForm.Email, err)
		return ErrorResponder{Message: "Login failed", Status: http.StatusInternalServerError}
	}
	
	log.Printf("Generated login options for %s", loginForm.Email)
	
	sessionJSON, _ := json.Marshal(sessionData)
	
	return JSONResponder{
		Data: options,
		Cookies: []*http.Cookie{{
			Name:     "webauthn_session",
			Value:    base64.StdEncoding.EncodeToString(sessionJSON),
			HttpOnly: true,
			Path:     "/",
		}},
	}
}

func passkeyLoginFinishHandler(ctx context.Context, loginForm LoginFormData) httphandler.Responder {
	log.Printf("Passkey login finish for user: %s", loginForm.Email)
	
	// For POC, we'll fake successful authentication
	// In a real implementation, you'd verify the credential and call webAuthn.FinishLogin()
	
	log.Printf("Passkey authentication successful for %s", loginForm.Email)
	
	// Set session cookie for successful login
	return JSONResponder{
		Data: map[string]string{"status": "success"},
		Cookies: []*http.Cookie{{
			Name:     "session",
			Value:    loginForm.Email,
			Path:     "/",
			HttpOnly: true,
		}},
	}
}

func passkeyPrimaryBeginHandler(ctx context.Context, loginForm LoginFormData) httphandler.Responder {
	log.Printf("Starting primary passkey authentication")
	
	// For primary/discoverable credentials, we use BeginDiscoverableLogin
	// This doesn't require a specific user
	options, sessionData, err := webAuthn.BeginDiscoverableLogin()
	if err != nil {
		log.Printf("Primary BeginDiscoverableLogin error: %v", err)
		return ErrorResponder{Message: "Login failed", Status: http.StatusInternalServerError}
	}
	
	log.Printf("Generated primary login options")
	
	sessionJSON, _ := json.Marshal(sessionData)
	
	return JSONResponder{
		Data: options,
		Cookies: []*http.Cookie{{
			Name:     "webauthn_session",
			Value:    base64.StdEncoding.EncodeToString(sessionJSON),
			HttpOnly: true,
			Path:     "/",
		}},
	}
}

func passkeyPrimaryFinishHandler(ctx context.Context, loginForm LoginFormData) httphandler.Responder {
	log.Printf("Primary passkey login finish")
	
	// For POC, we'll fake successful authentication
	// In a real implementation, you'd verify the credential and determine which user it belongs to
	
	// Since this is a POC, let's just find any user with passkeys and log them in
	var foundEmail string
	for email, passkeys := range usersDB {
		if len(passkeys) > 0 {
			foundEmail = email
			break
		}
	}
	
	if foundEmail == "" {
		log.Printf("No users with passkeys found for primary login")
		return ErrorResponder{Message: "No passkeys found", Status: http.StatusNotFound}
	}
	
	log.Printf("Primary passkey authentication successful for %s", foundEmail)
	
	// Set session cookie for successful login
	return JSONResponder{
		Data: map[string]string{"status": "success"},
		Cookies: []*http.Cookie{{
			Name:     "session",
			Value:    foundEmail,
			Path:     "/",
			HttpOnly: true,
		}},
	}
}