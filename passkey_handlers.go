package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/alvinchoong/go-httphandler"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper functions for debugging
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getInterfaceMapKeys(m map[interface{}]interface{}) []interface{} {
	keys := make([]interface{}, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getSliceLen(v interface{}) int {
	if slice, ok := v.([]interface{}); ok {
		return len(slice)
	}
	if slice, ok := v.([]byte); ok {
		return len(slice)
	}
	return -1
}

type WebAuthnCredentialData struct {
	ID              []byte
	PublicKey       []byte
	AttestationType string
	Format          string
}

func extractWebAuthnCredential(credData CredentialData) (*WebAuthnCredentialData, error) {
	// Extract the response object
	response, ok := credData.Credential["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to extract response from credential data")
	}
	
	// Extract the attestationObject (base64 encoded)
	attestationObjectB64, ok := response["attestationObject"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to extract attestationObject from response")
	}
	
	// Decode from base64
	attestationObjectBytes, err := base64.StdEncoding.DecodeString(attestationObjectB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestationObject from base64: %w", err)
	}
	
	// Parse CBOR attestation object
	var attestationObject map[string]interface{}
	if err := cbor.Unmarshal(attestationObjectBytes, &attestationObject); err != nil {
		return nil, fmt.Errorf("failed to parse attestationObject CBOR: %w", err)
	}
	
	// DEBUG: Log exactly what browser sent
	log.Printf("🔍 Raw attestationObject keys: %v", getMapKeys(attestationObject))
	for key, value := range attestationObject {
		if key == "attStmt" {
			if attStmt, ok := value.(map[interface{}]interface{}); ok {
				log.Printf("🔍 attStmt keys: %v", getInterfaceMapKeys(attStmt))
				for k, v := range attStmt {
					log.Printf("🔍 attStmt[%v] = %T (len=%d if slice)", k, v, getSliceLen(v))
				}
			}
		} else {
			log.Printf("🔍 attestationObject[%s] = %T", key, value)
		}
	}
	
	// Extract format
	format, ok := attestationObject["fmt"].(string)
	if !ok {
		return nil, fmt.Errorf("no fmt field found in attestationObject")
	}
	
	log.Printf("🔍 Extracted format: %s", format)
	
	// Extract authData
	authDataBytes, ok := attestationObject["authData"].([]byte)
	if !ok {
		return nil, fmt.Errorf("failed to extract authData from attestationObject")
	}
	
	// Parse authData to extract credential ID and public key
	credentialID, publicKey, err := parseAuthData(authDataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authData: %w", err)
	}
	
	// Determine attestation type based on format and attestation statement
	attestationType := determineAttestationType(format, attestationObject)
	
	log.Printf("🔍 FINAL RESULT - Format: %s, Attestation: %s, CredID length: %d, PubKey length: %d", 
		format, attestationType, len(credentialID), len(publicKey))
	
	return &WebAuthnCredentialData{
		ID:              credentialID,
		PublicKey:       publicKey,
		AttestationType: attestationType,
		Format:          format,
	}, nil
}

func parseAuthData(authData []byte) (credentialID []byte, publicKey []byte, err error) {
	if len(authData) < 37 {
		return nil, nil, fmt.Errorf("authData too short: %d bytes", len(authData))
	}
	
	// Skip rpIdHash (32 bytes) and flags (1 byte) and signCount (4 bytes)
	offset := 37
	
	// Check if attestedCredentialData is present (AT flag in flags byte)
	flags := authData[32]
	if (flags & 0x40) == 0 {
		return nil, nil, fmt.Errorf("attestedCredentialData not present (AT flag not set)")
	}
	
	if len(authData) < offset+16+2 {
		return nil, nil, fmt.Errorf("authData too short for attestedCredentialData")
	}
	
	// Skip AAGUID (16 bytes)
	offset += 16
	
	// Read credential ID length (2 bytes, big endian)
	credentialIDLength := binary.BigEndian.Uint16(authData[offset : offset+2])
	offset += 2
	
	if len(authData) < offset+int(credentialIDLength) {
		return nil, nil, fmt.Errorf("authData too short for credential ID")
	}
	
	// Extract credential ID
	credentialID = authData[offset : offset+int(credentialIDLength)]
	offset += int(credentialIDLength)
	
	// The rest is the CBOR-encoded public key
	if offset >= len(authData) {
		return nil, nil, fmt.Errorf("no public key data found")
	}
	
	publicKeyBytes := authData[offset:]
	
	// Parse the CBOR public key to validate it's well-formed
	var publicKeyMap map[interface{}]interface{}
	if err := cbor.Unmarshal(publicKeyBytes, &publicKeyMap); err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key CBOR: %w", err)
	}
	
	log.Printf("Parsed public key with %d CBOR fields", len(publicKeyMap))
	
	return credentialID, publicKeyBytes, nil
}

func determineAttestationType(format string, attestationObject map[string]interface{}) string {
	attStmt, ok := attestationObject["attStmt"].(map[interface{}]interface{})
	if !ok {
		log.Printf("🔍 No attStmt found, defaulting to none")
		return "none"
	}
	
	log.Printf("🔍 Determining attestation type for format '%s' with attStmt keys: %v", format, getInterfaceMapKeys(attStmt))
	
	switch format {
	case "none":
		return "none"
		
	case "packed":
		// Check for certificates in attestation statement
		if certs, exists := attStmt["x5c"]; exists && certs != nil {
			if certArray, ok := certs.([]interface{}); ok && len(certArray) > 0 {
				return "basic" // Has attestation certificates
			}
		}
		// Check for self-attestation
		if _, exists := attStmt["sig"]; exists {
			return "self" // Self-signed
		}
		return "none"
		
	case "tpm":
		// TPM attestation typically provides basic attestation
		if certs, exists := attStmt["x5c"]; exists && certs != nil {
			return "basic"
		}
		return "none"
		
	case "fido-u2f":
		// FIDO U2F requires attestation certificate
		if certs, exists := attStmt["x5c"]; exists && certs != nil {
			if certArray, ok := certs.([]interface{}); ok && len(certArray) > 0 {
				return "basic"
			}
		}
		return "none"
		
	case "apple":
		// Apple attestation can be anonymous (none) or with certificates (basic)
		if certs, exists := attStmt["x5c"]; exists && certs != nil {
			if certArray, ok := certs.([]interface{}); ok && len(certArray) > 0 {
				return "basic"
			}
		}
		return "none"
		
	case "android-key", "android-safetynet":
		// Android attestation typically provides basic attestation
		if certs, exists := attStmt["x5c"]; exists && certs != nil {
			return "basic"
		}
		return "none"
		
	default:
		log.Printf("Unknown attestation format: %s, defaulting to none", format)
		return "none"
	}
}

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
	
	// Extract the real WebAuthn credential data from the attestation object
	webauthnCred, err := extractWebAuthnCredential(credData)
	if err != nil {
		log.Printf("Failed to extract WebAuthn credential: %v", err)
		return ErrorResponder{Message: "Invalid WebAuthn credential data", Status: http.StatusBadRequest}
	}
	
	log.Printf("Registering passkey for user %s - Format: %s, Attestation: %s, CredID: %x", 
		session.Email, webauthnCred.Format, webauthnCred.AttestationType, webauthnCred.ID[:min(8, len(webauthnCred.ID))])
	
	credential := &webauthn.Credential{
		ID:              webauthnCred.ID,
		PublicKey:       webauthnCred.PublicKey,
		AttestationType: webauthnCred.AttestationType,
	}
	
	savePasskey(session.Email, credential, webauthnCred.Format)
	log.Printf("Saved passkey for user %s with ID %x. Total passkeys: %d", session.Email, webauthnCred.ID[:min(8, len(webauthnCred.ID))], getPasskeyCount(session.Email))
	
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