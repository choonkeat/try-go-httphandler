package main

import (
	"encoding/json"
	"io"
	"net/http"
)

func decodeSession(r *http.Request) (SessionData, error) {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		return SessionData{}, nil // Not authenticated, but not an error
	}
	return SessionData{Email: cookie.Value}, nil
}

func decodeLoginForm(r *http.Request) (LoginFormData, error) {
	return LoginFormData{
		Method: r.Method,
		Email:  r.FormValue("email"),
	}, nil
}

func decodeCredentialData(r *http.Request, session SessionData) (CredentialData, error) {
	if r.Method != "POST" {
		return CredentialData{}, nil
	}
	
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return CredentialData{}, err
	}
	
	var credData CredentialData
	if err := json.Unmarshal(body, &credData); err != nil {
		return CredentialData{}, err
	}
	
	return credData, nil
}

func decodeCredentialDataOnly(r *http.Request) (CredentialData, error) {
	if r.Method != "POST" {
		return CredentialData{}, nil
	}
	
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return CredentialData{}, err
	}
	
	var credData CredentialData
	if err := json.Unmarshal(body, &credData); err != nil {
		return CredentialData{}, err
	}
	
	return credData, nil
}