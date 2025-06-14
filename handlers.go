package main

import (
	"context"
	"net/http"

	"github.com/alvinchoong/go-httphandler"
)

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
			PasskeyCount: getPasskeyCount(session.Email),
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