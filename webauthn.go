package main

import (
	"crypto/rand"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type PassKey struct {
	ID              []byte
	PublicKey       []byte
	AttestationType string
	CreatedAt       time.Time
}

type WebAuthnUser struct {
	Email       string
	ID          []byte
	DisplayName string
	Credentials []webauthn.Credential
}

// Global storage for POC
var usersDB = make(map[string][]PassKey)
var webAuthn *webauthn.WebAuthn

// WebAuthn user interface implementation
func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.ID
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.Email
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

// Helper functions
func generateUserID() []byte {
	id := make([]byte, 32)
	rand.Read(id)
	return id
}

func getWebAuthnUser(email string) *WebAuthnUser {
	passkeys := usersDB[email]
	credentials := make([]webauthn.Credential, len(passkeys))
	
	for i, pk := range passkeys {
		credentials[i] = webauthn.Credential{
			ID:              pk.ID,
			PublicKey:       pk.PublicKey,
			AttestationType: pk.AttestationType,
		}
	}
	
	return &WebAuthnUser{
		Email:       email,
		ID:          generateUserID(),
		DisplayName: email,
		Credentials: credentials,
	}
}

func savePassKey(email string, credential *webauthn.Credential) {
	passkey := PassKey{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		CreatedAt:       time.Now(),
	}
	
	usersDB[email] = append(usersDB[email], passkey)
}

func getPassKeyCount(email string) int {
	return len(usersDB[email])
}