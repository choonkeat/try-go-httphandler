# WebAuthn Passkey Implementation Plan

## Overview
Add WebAuthn passkey support to the existing email-only login web application. Users will be able to register passkeys after email login and use them for future authentication.

## Architecture

### Dependencies
- `github.com/go-webauthn/webauthn` - WebAuthn library for Go
- Existing application structure with go-httphandler Pipeline APIs

### Data Structure

#### In-Memory Users Database
```go
type PassKey struct {
    ID          []byte
    PublicKey   []byte
    AttestationType string
    Aaguid      []byte
    SignCount   uint32
    CreatedAt   time.Time
}

// Simple POC - no thread safety needed
var usersDB = make(map[string][]PassKey)  // email -> []PassKey
```

#### WebAuthn User Implementation
```go
type WebAuthnUser struct {
    Email       string
    ID          []byte
    DisplayName string
    Credentials []webauthn.Credential
}

// Implement webauthn.User interface
func (u *WebAuthnUser) WebAuthnID() []byte
func (u *WebAuthnUser) WebAuthnName() string
func (u *WebAuthnUser) WebAuthnDisplayName() string
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential
func (u *WebAuthnUser) WebAuthnIcon() string
```

## Implementation Plan

### Phase 1: Core WebAuthn Setup
1. **Add WebAuthn Configuration**
   - Initialize WebAuthn instance in webapp.go
   - Configure RPID, RPOrigin, RPDisplayName
   - Set up session management for WebAuthn challenges

2. **Database Layer**
   - Simple global map for storing passkeys (POC - no thread safety)
   - Helper functions: GetUserPassKeys, SavePassKey
   - Convert between internal PassKey and webauthn.Credential

3. **Session Enhancement**
   - Extend existing cookie-based sessions
   - Store WebAuthn challenge data during registration/authentication flows

### Phase 2: Registration Flow
1. **Dashboard Enhancement**
   - Add "Setup Passkey" section when user has no passkeys
   - Display existing passkeys list with management options
   - Add JavaScript-free fallback for browsers without WebAuthn support

2. **Registration Endpoints**
   - `POST /passkey/register/begin` - Start passkey registration
   - `POST /passkey/register/finish` - Complete passkey registration
   - Use go-httphandler Pipeline APIs with session validation

3. **Templates**
   - Add passkey setup UI to dashboard.html
   - Registration success/error feedback
   - Passkey management interface

### Phase 3: Authentication Flow
1. **Login Enhancement**
   - Modify login form to detect existing passkeys for email
   - Add "Use Passkey" option when available
   - Maintain email-only fallback

2. **Authentication Endpoints**
   - `POST /passkey/login/begin` - Start passkey authentication
   - `POST /passkey/login/finish` - Complete passkey authentication
   - Integrate with existing session management

3. **User Experience**
   - Progressive enhancement: show passkey option only if supported
   - Clear messaging about passkey benefits
   - Graceful fallback to email login

### Phase 4: Management Features (Optional for POC)
1. **Basic Passkey Management**
   - List registered passkeys on dashboard
   - Simple display of passkey count
   - Basic success/error messaging

## Technical Implementation Details

### WebAuthn Configuration
```go
func setupWebAuthn() (*webauthn.WebAuthn, error) {
    return webauthn.New(&webauthn.Config{
        RPDisplayName: "Go HTTP Handler Demo",
        RPID:          "localhost", // Change for production
        RPOrigin:      "http://localhost:8080", // Change for production
        Timeouts: webauthn.TimeoutsConfig{
            Login: webauthn.TimeoutConfig{
                Enforce:    true,
                Timeout:    60000,
            },
            Registration: webauthn.TimeoutConfig{
                Enforce:    true,
                Timeout:    60000,
            },
        },
    })
}
```

### Route Structure
```
POST /passkey/register/begin    - Begin passkey registration
POST /passkey/register/finish   - Complete passkey registration
POST /passkey/login/begin       - Begin passkey authentication
POST /passkey/login/finish      - Complete passkey authentication
```

### Pipeline Integration
- Use existing sessionPipeline for authentication checks
- Create passkeyPipeline for WebAuthn-specific operations
- Maintain go-httphandler Responder pattern for all endpoints

### JavaScript Requirements
WebAuthn requires minimal JavaScript for browser API calls:
- `navigator.credentials.create()` for registration
- `navigator.credentials.get()` for authentication
- Base64 encoding/decoding for credential data
- Keep JavaScript minimal and focused only on WebAuthn API calls

## UI/UX Design

### Dashboard Enhancements
1. **No Passkeys State**
   - Prominent "Set up passkey for faster login" card
   - Benefits explanation (faster, more secure)
   - Single "Set up passkey" button

2. **Existing Passkeys State**
   - Simple list of registered passkeys
   - Display passkey count
   - "Add another passkey" option

3. **Registration Flow**
   - Clear instructions during setup
   - Browser compatibility checks
   - Success confirmation with next steps

### Login Page Enhancements
1. **Passkey Detection**
   - Check for existing passkeys on email entry
   - Show "Use passkey" option dynamically
   - Maintain email-only option

2. **Authentication Flow**
   - Clear passkey authentication prompts
   - Fallback options if passkey fails
   - Progress indicators

## Security Considerations

### Data Protection
- Store only necessary credential data in simple map (POC)
- Use secure random generation for user IDs
- Implement proper session validation

### Error Handling
- Graceful WebAuthn failures
- Clear error messages for users
- Logging for debugging (no sensitive data)

### Browser Compatibility
- Feature detection for WebAuthn support
- Graceful degradation to email login
- Clear messaging about browser requirements

## Testing
Just test it manually in the browser - register a passkey, then use it to login. That's it!

## Implementation Steps

1. **Add WebAuthn dependency** - `go mod tidy`
2. **Basic setup** - WebAuthn config, global passkey map
3. **Registration** - `/passkey/register/begin` and `/finish` endpoints
4. **Authentication** - `/passkey/login/begin` and `/finish` endpoints
5. **Dashboard** - Show passkey setup button, add minimal JS
6. **Login page** - Add passkey option if user has keys
7. **Done!** - Simple WebAuthn POC ready

## Success Criteria
- Register passkey after email login ✓
- Use passkey to login ✓  
- Email fallback still works ✓

Simple WebAuthn POC - nothing fancy!