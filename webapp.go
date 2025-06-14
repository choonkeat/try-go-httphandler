package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/alvinchoong/go-httphandler"
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
	Email string
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
	http.Error(w, e.Message, e.Status)
}

func httpServerFunc(ctx context.Context, config Config) error {
	// Create pipelines
	sessionPipeline := httphandler.NewPipeline1(extractSession)
	loginFormPipeline := httphandler.NewPipeline1(extractLoginForm)

	mux := http.NewServeMux()

	// Routes using go-httphandler pipelines
	mux.Handle("/", httphandler.HandlePipeline1(sessionPipeline, homeHandler))
	mux.Handle("/login", httphandler.HandlePipeline1(loginFormPipeline, loginHandler))
	mux.Handle("/dashboard", httphandler.HandlePipeline1(sessionPipeline, dashboardHandler))
	mux.HandleFunc("/logout", logoutHandler)

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
		Data:     DashboardData{Email: session.Email},
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