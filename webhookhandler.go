package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type webhookHandler interface {
	handleWebhook(context.Context, Message) error
}

func newHTTPHandler(wh webhookHandler, name, webhookValidatingSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Get the signature from the header
		signature := r.Header.Get("X-Obot-Signature-256")
		if signature == "" {
			http.Error(w, "Missing X-Obot-Signature-256 header", http.StatusBadRequest)
			return
		}

		// Validate the signature
		if !validateSignature(body, signature, webhookValidatingSecret) {
			http.Error(w, "Invalid signature", http.StatusBadRequest)
			return
		}

		// Parse the JSON payload
		var message Message
		if err := json.Unmarshal(body, &message); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		// Log the received message (optional)
		log.Printf("Received webhook: Method=%s, ID=%v", message.Method, message.ID)

		// Handle the webhook message
		if err := wh.handleWebhook(r.Context(), message); err != nil {
			fmt.Printf("webhook %s faled: %v\n", name, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Respond with a success status
		w.WriteHeader(http.StatusOK)
	}
}
