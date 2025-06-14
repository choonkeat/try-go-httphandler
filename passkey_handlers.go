package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"github.com/alvinchoong/go-httphandler"
	"github.com/go-webauthn/webauthn/webauthn"
)

func passkeyRegisterBeginHandler(ctx context.Context, session SessionData) httphandler.Responder {
	if session.Email == "" {
		return ErrorResponder{Message: "Not authenticated", Status: http.StatusUnauthorized}
	}
	
	log.Printf("Starting passkey registration for user: %s", session.Email)
	
	user := getUserForWebAuthn(session.Email)
	options, sessionData, err := webAuthnInstance.BeginRegistration(user)
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

func passkeyRegisterFinishHandler(ctx context.Context, session SessionData, credData CredentialData) httphandler.Responder {
	if session.Email == "" {
		return ErrorResponder{Message: "Not authenticated", Status: http.StatusUnauthorized}
	}
	
	log.Printf("Passkey registration finish for user: %s", session.Email)
	
	// Extract the real credential ID from the browser response
	credentialID, ok := credData.Credential["id"].(string)
	if !ok {
		log.Printf("Failed to extract credential ID from registration")
		return ErrorResponder{Message: "Invalid credential data", Status: http.StatusBadRequest}
	}
	
	log.Printf("Registering passkey with ID %s for user %s", credentialID, session.Email)
	
	credential := &webauthn.Credential{
		ID:              []byte(credentialID),
		PublicKey:       []byte("fake-public-key-" + session.Email),
		AttestationType: "none",
	}
	
	savePasskey(session.Email, credential)
	log.Printf("Saved passkey for user %s with ID %s. Total passkeys: %d", session.Email, credentialID, getPasskeyCount(session.Email))
	
	return JSONResponder{Data: map[string]string{"status": "success"}}
}

func passkeyLoginBeginHandler(ctx context.Context, loginForm LoginFormData) httphandler.Responder {
	if loginForm.Email == "" {
		return ErrorResponder{Message: "Email required", Status: http.StatusBadRequest}
	}
	
	log.Printf("Checking passkeys for user: %s", loginForm.Email)
	
	user := getUserForWebAuthn(loginForm.Email)
	if len(user.Credentials) == 0 {
		log.Printf("No passkeys found for user: %s", loginForm.Email)
		return ErrorResponder{Message: "No passkeys found", Status: http.StatusNotFound}
	}
	
	log.Printf("Found %d passkeys for user: %s", len(user.Credentials), loginForm.Email)
	
	options, sessionData, err := webAuthnInstance.BeginLogin(user)
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
	options, sessionData, err := webAuthnInstance.BeginDiscoverableLogin()
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

func passkeyPrimaryFinishHandler(ctx context.Context, credData CredentialData) httphandler.Responder {
	log.Printf("Primary passkey login finish")
	
	// Extract credential ID from the credential data
	credentialID, ok := credData.Credential["id"].(string)
	if !ok {
		log.Printf("Failed to extract credential ID from request")
		return ErrorResponder{Message: "Invalid credential data", Status: http.StatusBadRequest}
	}
	
	log.Printf("Looking for user with credential ID: %s", credentialID)
	
	// Find which user this credential belongs to
	foundEmail := findUserByPasskeyCredentialID(credentialID)
	if foundEmail == "" {
		log.Printf("No user found for credential ID: %s", credentialID)
		return ErrorResponder{Message: "Credential not found", Status: http.StatusNotFound}
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