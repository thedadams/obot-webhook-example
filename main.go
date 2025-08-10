package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/zricethezav/gitleaks/v8/detect"
)

type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func main() {
	// Get webhook secret from environment variable
	secret := os.Getenv("WEBHOOK_SECRET")
	if secret == "" {
		log.Fatal("WEBHOOK_SECRET environment variable is required")
	}

	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		panic(err)
	}

	http.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Get the signature from the header
		signature := r.Header.Get("X-Obot-Signature-256")
		if signature == "" {
			http.Error(w, "Missing X-Obot-Signature-256 header", http.StatusBadRequest)
			return
		}

		// Validate the signature
		if !validateSignature(body, signature, secret) {
			http.Error(w, "Invalid signature", http.StatusBadRequest)
			return
		}

		// Parse the JSON payload
		var message Message
		if err := json.Unmarshal(body, &message); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		findings := detector.DetectBytes(message.Params)
		if len(findings) > 0 {
			log.Printf("found some secrets: %+v", findings)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(fmt.Appendf(nil, "found %d suspected secrets", len(findings)))
			return
		}

		// Log the received message (optional)
		log.Printf("Received valid webhook: Method=%s, ID=%v", message.Method, message.ID)

		// Return success
		_, _ = w.Write([]byte("Webhook received successfully"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	log.Printf("Starting webhook server on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func validateSignature(body []byte, signature, secret string) bool {
	// Remove "sha256=" prefix if present
	signature = strings.TrimPrefix(signature, "sha256=")

	// Create HMAC-SHA256 hash
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// Compare signatures using constant time comparison
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}
