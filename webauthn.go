package main

import (
	"crypto/rand"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Passkey struct {
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
var userPasskeys = make(map[string][]Passkey)
var webAuthnInstance *webauthn.WebAuthn

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

func getUserForWebAuthn(email string) *WebAuthnUser {
	passkeys := userPasskeys[email]
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

func savePasskey(email string, credential *webauthn.Credential) {
	passkey := Passkey{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		CreatedAt:       time.Now(),
	}
	
	userPasskeys[email] = append(userPasskeys[email], passkey)
}

func getPasskeyCount(email string) int {
	return len(userPasskeys[email])
}

func findUserByPasskeyCredentialID(credentialID string) string {
	for email, passkeys := range userPasskeys {
		for _, passkey := range passkeys {
			// Compare the credential ID (convert to string for comparison)
			if string(passkey.ID) == credentialID {
				return email
			}
		}
	}
	return ""
}