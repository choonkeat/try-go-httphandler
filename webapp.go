package main

type Config struct {
	Host string
	Port int
}

type LoginFormData struct {
	Method string
	Email  string
}

type SessionData struct {
	Email string
}

type DashboardData struct {
	Email        string
	PasskeyCount int
}

type CredentialData struct {
	Credential map[string]interface{} `json:"credential"`
}