# Obot Webhook Server

A simple HTTP server in Go that validates webhook signatures using HMAC-SHA256.

## Features

- Accepts POST requests with JSON-RPC message payloads
- Validates webhook signatures using the `X-Obot-Signature-256` header
- Returns 200 for valid requests, 400 for invalid ones
- Secure signature validation using HMAC-SHA256

## Usage

1. Set the webhook secret as an environment variable:
   ```bash
   export WEBHOOK_SECRET="your-secret-key"
   ```

2. Run the server:
   ```bash
   go run .
   ```

3. The server will start on port 8082 by default. You can change this by setting the `PORT` environment variable.

## Testing

Run the tests to verify signature validation:
```bash
go test -v
```

## Example Request

The server expects a POST request to `/secrets-detector` with:

- **Header**: `X-Obot-Signature-256: sha256=<hmac-sha256-signature>`
- **Body**: JSON payload matching the Message struct

Example payload:
```json
{
  "jsonrpc": "2.0",
  "method": "example.method",
  "params": {"key": "value"},
  "id": 1
}
```

## Signature Generation

The signature is generated using HMAC-SHA256 of the request body with your secret key:

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
)

func generateSignature(body []byte, secret string) string {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(body)
    return hex.EncodeToString(mac.Sum(nil))
}
```

## Response Codes

- **200**: Valid signature and JSON payload
- **400**: Invalid signature, missing header, or malformed JSON
- **405**: Method not allowed (non-POST requests)
