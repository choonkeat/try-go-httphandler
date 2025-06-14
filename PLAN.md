# Go HTTP Web App Design Plan

## Overview
Build a minimal Go HTTP web application using stdlib, flags, and go-httphandler Pipeline APIs. The app will have a simple login flow with email-only authentication and a basic dashboard.

## Architecture

### Dependencies
- Go standard library (net/http, flag, html/template)
- `github.com/alvinchoong/go-httphandler` (Pipeline APIs and Responder only)
- shadcn/ui CSS for styling (via CDN)

### Application Structure
```
main.go              # Entry point with flags and HTTP server
handlers/            # HTTP handlers using go-httphandler
├── login.go         # Login form handler
├── auth.go          # Authentication handler  
└── dashboard.go     # Dashboard handler
templates/           # HTML templates
├── login.html       # Login form page
└── dashboard.html   # Dashboard page
```

## Features

### 1. Command Line Flags
- `-port`: Server port (default: 8080)
- `-host`: Server host (default: localhost)

### 2. Routes & Handlers
- `GET /` → Login form (if not authenticated)
- `POST /login` → Process login (mock success always)
- `GET /dashboard` → Dashboard page (if authenticated)

### 3. Authentication Flow
1. User visits `/` → sees login form
2. User enters email and submits
3. Server always returns success and sets session cookie
4. User redirected to `/dashboard`
5. Dashboard shows welcome message with email

### 4. UI Design
- Minimal HTML with shadcn/ui styling via CDN
- No JavaScript required
- Clean, responsive design
- Login form: email input + submit button
- Dashboard: welcome message + logout link

## Implementation Details

### go-httphandler Usage
- Use `NewPipeline1` for simple request context extraction
- Use `NewPipeline2` for complex flows (e.g., auth + form data)
- Implement `Responder` interface for all responses
- Use `HandlePipeline1/2` for route handlers

### Session Management
- Simple cookie-based sessions using HTTP-only cookies
- Store email in cookie (since this is a demo)
- No complex session storage needed

### Error Handling
- Graceful error pages using templates
- Proper HTTP status codes
- Logging to stdout

## Security Considerations
- HTTP-only cookies for session management
- Basic input validation
- CSRF protection not required for this demo
- No password handling simplifies security model

## Testing Strategy
- Manual testing via browser
- Test all routes and flows
- Verify session persistence
- Test flag parsing

This design prioritizes simplicity while demonstrating proper use of go-httphandler Pipeline APIs and maintaining clean separation of concerns.