package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Passkey struct {
	ID              []byte
	PublicKey       []byte
	AttestationType string
	Format          string
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
var passkeyJSONFilePath string

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

func loadPasskeysFromFile() error {
	if passkeyJSONFilePath == "" {
		return nil // No file specified, skip loading
	}
	
	data, err := os.ReadFile(passkeyJSONFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Passkey file %s does not exist, starting with empty storage", passkeyJSONFilePath)
			return nil // File doesn't exist yet, that's ok
		}
		return err
	}
	
	if err := json.Unmarshal(data, &userPasskeys); err != nil {
		return err
	}
	
	log.Printf("Loaded passkeys from %s", passkeyJSONFilePath)
	return nil
}

func savePasskeysToFile() error {
	if passkeyJSONFilePath == "" {
		return nil // No file specified, skip saving
	}
	
	data, err := json.MarshalIndent(userPasskeys, "", "  ")
	if err != nil {
		return err
	}
	
	if err := os.WriteFile(passkeyJSONFilePath, data, 0644); err != nil {
		return err
	}
	
	log.Printf("Saved passkeys to %s", passkeyJSONFilePath)
	return nil
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

func savePasskey(email string, credential *webauthn.Credential, format string) {
	passkey := Passkey{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Format:          format,
		CreatedAt:       time.Now(),
	}
	
	userPasskeys[email] = append(userPasskeys[email], passkey)
	
	// Save to file if specified
	if err := savePasskeysToFile(); err != nil {
		log.Printf("Failed to save passkeys to file: %v", err)
	}
}

func getPasskeyCount(email string) int {
	return len(userPasskeys[email])
}

func findUserByPasskeyCredentialID(credentialID string) string {
	// Convert incoming base64url credential ID to base64 for comparison
	// Browser sends base64url, but our stored IDs are raw bytes (which JSON encodes as base64)
	credentialIDBytes, err := base64.RawURLEncoding.DecodeString(credentialID)
	if err != nil {
		log.Printf("Failed to decode credential ID %s: %v", credentialID, err)
		return ""
	}
	
	for email, passkeys := range userPasskeys {
		for _, passkey := range passkeys {
			// Compare raw bytes using bytes.Equal
			if bytes.Equal(passkey.ID, credentialIDBytes) {
				log.Printf("Found matching credential for user %s", email)
				return email
			}
		}
	}
	
	log.Printf("No user found for credential ID: %s (decoded %d bytes)", credentialID, len(credentialIDBytes))
	return ""
}