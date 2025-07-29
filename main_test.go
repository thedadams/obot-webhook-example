package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestValidateSignature(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"jsonrpc":"2.0","method":"test","id":1}`)

	// Generate valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	validSignature := hex.EncodeToString(mac.Sum(nil))

	// Test with valid signature
	if !validateSignature(body, validSignature, secret) {
		t.Error("Valid signature should pass validation")
	}

	// Test with sha256= prefix
	if !validateSignature(body, "sha256="+validSignature, secret) {
		t.Error("Valid signature with sha256= prefix should pass validation")
	}

	// Test with invalid signature
	if validateSignature(body, "invalid-signature", secret) {
		t.Error("Invalid signature should fail validation")
	}

	// Test with wrong secret
	if validateSignature(body, validSignature, "wrong-secret") {
		t.Error("Signature with wrong secret should fail validation")
	}
}

func TestWebhookHandler(t *testing.T) {
	// Set up test environment
	os.Setenv("WEBHOOK_SECRET", "test-secret")
	defer os.Unsetenv("WEBHOOK_SECRET")

	secret := "test-secret"
	payload := `{"jsonrpc":"2.0","method":"test","id":1}`
	body := []byte(payload)

	// Generate valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))

	// Test valid request
	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req.Header.Set("X-Obot-Signature-256", "sha256="+signature)
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate the webhook handler logic
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		bodyBytes, _ := io.ReadAll(r.Body)
		headerSig := r.Header.Get("X-Obot-Signature-256")
		
		if headerSig == "" {
			http.Error(w, "Missing signature", http.StatusBadRequest)
			return
		}

		if !validateSignature(bodyBytes, headerSig, secret) {
			http.Error(w, "Invalid signature", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Webhook received successfully"))
	})

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	// Test invalid signature
	req2 := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
	req2.Header.Set("X-Obot-Signature-256", "invalid-signature")
	req2.Header.Set("Content-Type", "application/json")

	recorder2 := httptest.NewRecorder()
	handler.ServeHTTP(recorder2, req2)

	if recorder2.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid signature, got %d", recorder2.Code)
	}
}
