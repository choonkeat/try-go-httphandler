package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
)

type HTMLResponder struct {
	Template string
	Data     interface{}
}

func (h HTMLResponder) Respond(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles(h.Template)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}
	
	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, h.Data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

type ErrorResponder struct {
	Message string
	Status  int
}

func (e ErrorResponder) Respond(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":  e.Message,
		"status": "error",
	})
}

type JSONResponder struct {
	Data    interface{}
	Cookies []*http.Cookie
}

func (j JSONResponder) Respond(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range j.Cookies {
		http.SetCookie(w, cookie)
	}
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(j.Data); err != nil {
		log.Printf("JSON encoding error: %v", err)
	}
}