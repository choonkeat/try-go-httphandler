# Go HTTP Handler WebAuthn Demo

A proof-of-concept web application demonstrating production-quality WebAuthn passkey implementation using Go standard libraries and the [go-httphandler](https://github.com/alvinchoong/go-httphandler) pipeline framework.

## Features

- **Email-only login** with mock authentication
- **WebAuthn passkey registration** and authentication
- **Primary passkey login** (no email required)
- **Real credential extraction** from CBOR attestation objects
- **Proper attestation type determination** from attestation statements
- **JSON file persistence** for passkey storage
- **Production-quality WebAuthn parsing** with no hardcoded values

## Quick Start

```bash
# Build and run
make
./bin/app

# With passkey persistence
./bin/app -passkey-jsonfile passkeys.json

# Custom host/port
./bin/app -host localhost -port 8001
```

Visit http://localhost:8080 to test the application.

## Architecture

### Files
- `main.go` - Entry point with CLI flags and server bootstrap
- `server.go` - HTTP server setup and routing
- `handlers.go` - Basic HTTP handlers (login, dashboard, logout)
- `passkey_handlers.go` - WebAuthn passkey handlers with CBOR parsing
- `webauthn.go` - WebAuthn types and domain logic
- `http_responders.go` - HTTP response types
- `http_decoders.go` - HTTP request decoders for pipelines

### WebAuthn Implementation
- **Real public key extraction** from `authData` binary structure
- **Attestation type determination** by analyzing attestation statements
- **Format support**: `none`, `packed`, `apple`, `fido-u2f`, `tpm`, `android-key`
- **Credential ID encoding** handling (base64url from browser, base64 in storage)
- **CBOR parsing** for all WebAuthn data structures

## POC Philosophy

This demo maintains **production-quality WebAuthn implementation** while simplifying infrastructure:

### ✅ No Compromises On
- WebAuthn protocol correctness
- Credential data integrity
- Attestation parsing accuracy
- Security model adherence

### 📝 Simplified For Learning
- No mutex/thread safety
- JSON file persistence instead of database
- Basic error handling
- In-memory global storage

## Usage

1. **Register with email** - Enter any email to create a session
2. **Set up passkey** - Dashboard will prompt to register a passkey
3. **Login with passkey** - Use the "Login with Passkey" button for passwordless auth
4. **Multiple users** - Each email gets separate passkey storage

## Dependencies

- [go-httphandler](https://github.com/alvinchoong/go-httphandler) - Pipeline-based HTTP handler framework
- [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) - WebAuthn server library
- [fxamacker/cbor](https://github.com/fxamacker/cbor) - CBOR encoding for WebAuthn parsing

## Documentation

- `CODE.md` - Development patterns and preferences
- `PLAN.md` - Original design plan (historical)
- `PASSKEY.md` - WebAuthn implementation plan (historical)