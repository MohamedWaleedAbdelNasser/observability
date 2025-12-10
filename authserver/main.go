package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"pkce1/authserver/middleware"
	"pkce1/authserver/telemetry"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func getJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("ERROR: JWT_SECRET environment variable is not set. Please set it in .env file")
	}
	return secret
}

type AuthCodeData struct {
	CodeChallenge string
	ClientID      string
	RedirectURI   string
	Scopes        []string
	CreatedAt     time.Time
}

// Storage for pending authorization requests (before consent)
type PendingAuth struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Scopes              []string
	CreatedAt           time.Time
}

var (
	authCodes    = make(map[string]*AuthCodeData)
	pendingAuths = make(map[string]*PendingAuth)
	authMutex    sync.RWMutex
	pendingMutex sync.RWMutex
)

func generateAuthCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func authError(ctx context.Context, w http.ResponseWriter, clientID string, condition bool, logMsg, httpMsg string) bool {
	if !condition {
		return false
	}
	log.Printf("[AuthServer] ERROR: %s", logMsg)
	if telemetry.AuthorizationRequests != nil {
		telemetry.RecordAuthorizationRequest(ctx, clientID, false)
	}
	http.Error(w, httpMsg, http.StatusBadRequest)
	return true
}

func tokenError(ctx context.Context, w http.ResponseWriter, condition bool, logMsg, httpMsg, errorType string, statusCode int) bool {
	if !condition {
		return false
	}
	log.Printf("[AuthServer] ERROR: %s", logMsg)
	if telemetry.TokenExchanges != nil {
		telemetry.RecordTokenExchange(ctx, false, errorType)
	}
	http.Error(w, httpMsg, statusCode)
	return true
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateAccessToken(clientID string, scopes []string) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":    "http://localhost:8081",
		"sub":    "test@example.com",
		"aud":    clientID,
		"exp":    now.Add(1 * time.Hour).Unix(),
		"iat":    now.Unix(),
		"scope":  strings.Join(scopes, " "),
		"client": clientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(getJWTSecret()))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Consent page
func renderConsentPage(w http.ResponseWriter, sessionID, clientID string, scopes []string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Request</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .consent-box {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 450px;
            width: 100%%;
            overflow: hidden;
            animation: slideUp 0.3s ease-out;
        }
        @keyframes slideUp {
            from { transform: translateY(20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .header {
            background: #f8f9fa;
            padding: 30px;
            text-align: center;
            border-bottom: 1px solid #e9ecef;
        }
        .header h1 {
            font-size: 24px;
            color: #212529;
            margin-bottom: 8px;
        }
        .app-name {
            color: #667eea;
            font-weight: 600;
        }
        .content {
            padding: 30px;
        }
        .info {
            background: #e7f3ff;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 4px;
        }
        .info p {
            color: #495057;
            font-size: 14px;
            line-height: 1.5;
        }
        .scopes {
            margin-bottom: 25px;
        }
        .scopes h3 {
            font-size: 14px;
            color: #6c757d;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .scope-item {
            padding: 10px 0;
            color: #212529;
            font-size: 15px;
            display: flex;
            align-items: center;
        }
        .scope-item:before {
            content: "";
            color: #28a745;
            font-weight: bold;
            margin-right: 10px;
            font-size: 18px;
        }
        .actions {
            display: flex;
            gap: 12px;
        }
        .btn {
            flex: 1;
            padding: 14px;
            border: none;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-allow {
            background: #667eea;
            color: white;
        }
        .btn-allow:hover {
            background: #5568d3;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .btn-deny {
            background: #e9ecef;
            color: #495057;
        }
        .btn-deny:hover {
            background: #dee2e6;
        }
        .footer {
            padding: 20px;
            text-align: center;
            background: #f8f9fa;
            border-top: 1px solid #e9ecef;
        }
        .footer p {
            font-size: 12px;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="consent-box">
        <div class="header">
            <h1>🔐 Authorization Request</h1>
            <p><span class="app-name">%s</span> wants to access your account</p>
        </div>
        
        <div class="content">
            <div class="info">
                <p><strong>Review the permissions</strong> this application is requesting. Only approve if you trust this application.</p>
            </div>
            
            <div class="scopes">
                <h3>This app will be able to:</h3>
                <div class="scope-item">Read protected data</div>
                <div class="scope-item">Write/modify data</div>
                <div class="scope-item">Delete data</div>
            </div>
            
            <form method="POST" action="/consent">
                <input type="hidden" name="session_id" value="%s">
                <div class="actions">
                    <button type="submit" name="action" value="deny" class="btn btn-deny">
                        Deny
                    </button>
                    <button type="submit" name="action" value="allow" class="btn btn-allow">
                        Allow
                    </button>
                </div>
            </form>
        </div>
        
        <div class="footer">
            <p>By allowing access, you authorize <strong>%s</strong> to use your information.</p>
        </div>
    </div>
</body>
</html>
`, clientID, sessionID, clientID)
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Println("\n[AuthServer] ========================================")
	log.Println("[AuthServer] Received /authorize request")

	query := r.URL.Query()
	responseType := query.Get("response_type")
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")
	state := query.Get("state")

	log.Printf("[AuthServer] Parameters:")
	log.Printf("  - response_type: %s", responseType)
	log.Printf("  - client_id: %s", clientID)
	log.Printf("  - redirect_uri: %s", redirectURI)
	log.Printf("  - code_challenge: %s", codeChallenge)
	log.Printf("  - code_challenge_method: %s", codeChallengeMethod)
	log.Printf("  - state: %s", state)

	if authError(ctx, w, clientID, responseType != "code", "Invalid response_type", "Invalid response_type") {
		return
	}
	if authError(ctx, w, clientID, clientID == "", "Missing client_id", "Missing client_id") {
		return
	}
	if authError(ctx, w, clientID, redirectURI == "", "Missing redirect_uri", "Missing redirect_uri") {
		return
	}
	if authError(ctx, w, clientID, codeChallenge == "", "Missing code_challenge", "Missing code_challenge (PKCE required)") {
		return
	}
	if authError(ctx, w, clientID, codeChallengeMethod != "S256", "Invalid code_challenge_method, must be S256", "code_challenge_method must be S256") {
		return
	}

	log.Println("[AuthServer]  All parameters valid")
	log.Println("[AuthServer] Showing consent page to user...")

	sessionID := generateSessionID()

	pendingMutex.Lock()
	pendingAuths[sessionID] = &PendingAuth{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		State:               state,
		Scopes:              []string{"read", "write", "delete"},
		CreatedAt:           time.Now(),
	}
	pendingMutex.Unlock()

	log.Printf("[AuthServer]  Created session: %s", sessionID[:20]+"...")
	log.Println("[AuthServer] Waiting for user consent...")

	if telemetry.AuthorizationRequests != nil {
		telemetry.RecordAuthorizationRequest(ctx, clientID, true)
	}

	renderConsentPage(w, sessionID, clientID, []string{"read", "write", "delete"})
}

func handleConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Println("\n[AuthServer] ========================================")
	log.Println("[AuthServer] Received /consent request")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Printf("[AuthServer] ERROR: Failed to parse form: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	sessionID := r.FormValue("session_id")
	action := r.FormValue("action") // "allow" or "deny"

	log.Printf("[AuthServer] Session ID: %s", sessionID[:20]+"...")
	log.Printf("[AuthServer] User action: %s", action)

	pendingMutex.RLock()
	pending, exists := pendingAuths[sessionID]
	pendingMutex.RUnlock()

	if !exists {
		log.Println("[AuthServer] ERROR: Invalid or expired session")
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	log.Println("[AuthServer]  Valid session found")

	pendingMutex.Lock()
	delete(pendingAuths, sessionID)
	pendingMutex.Unlock()

	if telemetry.ConsentDecisions != nil {
		telemetry.RecordConsentDecision(ctx, action, pending.ClientID)
	}

	if action == "deny" {
		log.Println("[AuthServer] ✗ User denied authorization")
		redirectURL := fmt.Sprintf("%s?error=access_denied&error_description=User+denied+the+request&state=%s",
			pending.RedirectURI, pending.State)
		log.Printf("[AuthServer] Redirecting to: %s", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	log.Println("[AuthServer] User approved authorization")

	authCode := generateAuthCode()

	authMutex.Lock()
	authCodes[authCode] = &AuthCodeData{
		CodeChallenge: pending.CodeChallenge,
		ClientID:      pending.ClientID,
		RedirectURI:   pending.RedirectURI,
		Scopes:        pending.Scopes,
		CreatedAt:     time.Now(),
	}
	authMutex.Unlock()

	log.Printf("[AuthServer]  Generated authorization code: %s", authCode[:20]+"...")
	log.Printf("[AuthServer]  Stored PKCE code_challenge: %s", pending.CodeChallenge[:20]+"...")

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", pending.RedirectURI, authCode, pending.State)
	log.Printf("[AuthServer] Redirecting to: %s", redirectURL)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Println("\n[AuthServer] ========================================")
	log.Println("[AuthServer] Received /token request")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if tokenError(ctx, w, err != nil, fmt.Sprintf("Failed to parse form: %v", err), "Invalid request", "parse_error", http.StatusBadRequest) {
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	log.Printf("[AuthServer] Parameters:")
	log.Printf("  - grant_type: %s", grantType)
	log.Printf("  - code: %s", code[:20]+"...")
	log.Printf("  - client_id: %s", clientID)
	log.Printf("  - redirect_uri: %s", redirectURI)
	log.Printf("  - code_verifier: %s", codeVerifier[:20]+"...")

	if tokenError(ctx, w, grantType != "authorization_code", "Invalid grant_type", "Invalid grant_type", "invalid_grant_type", http.StatusBadRequest) {
		return
	}

	authMutex.RLock()
	authData, exists := authCodes[code]
	authMutex.RUnlock()

	if tokenError(ctx, w, !exists, "Invalid or expired authorization code", "Invalid authorization code", "invalid_code", http.StatusBadRequest) {
		return
	}

	log.Println("[AuthServer]  Authorization code found")

	if tokenError(ctx, w, authData.ClientID != clientID, "client_id mismatch", "Invalid client_id", "client_id_mismatch", http.StatusBadRequest) {
		return
	}
	if tokenError(ctx, w, authData.RedirectURI != redirectURI, "redirect_uri mismatch", "Invalid redirect_uri", "redirect_uri_mismatch", http.StatusBadRequest) {
		return
	}

	log.Println("[AuthServer]  client_id and redirect_uri validated")

	log.Println("[AuthServer] Verifying PKCE...")
	hash := sha256.Sum256([]byte(codeVerifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	log.Printf("[AuthServer] Stored code_challenge:   %s", authData.CodeChallenge[:20]+"...")
	log.Printf("[AuthServer] Computed from verifier:  %s", computedChallenge[:20]+"...")

	if computedChallenge != authData.CodeChallenge {
		log.Println("[AuthServer] ERROR: PKCE verification failed!")
		if telemetry.PKCEVerifications != nil {
			telemetry.RecordPKCEVerification(ctx, false)
			telemetry.RecordTokenExchange(ctx, false, "pkce_failed")
		}
		http.Error(w, "Invalid code_verifier", http.StatusBadRequest)
		return
	}

	log.Println("[AuthServer]  PKCE verification successful!")
	if telemetry.PKCEVerifications != nil {
		telemetry.RecordPKCEVerification(ctx, true)
	}

	authMutex.Lock()
	delete(authCodes, code)
	authMutex.Unlock()

	accessToken, err := generateAccessToken(authData.ClientID, authData.Scopes)
	if tokenError(ctx, w, err != nil, fmt.Sprintf("Failed to generate access token: %v", err), "Token generation failed", "token_generation_failed", http.StatusInternalServerError) {
		return
	}

	log.Printf("[AuthServer]  Issuing JWT access token")
	log.Printf("[AuthServer]  Token preview: %s", accessToken[:50]+"...")
	log.Printf("[AuthServer]  Scopes: %v", authData.Scopes)

	if telemetry.TokenExchanges != nil {
		telemetry.RecordTokenExchange(ctx, true, "")
	}

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(authData.Scopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Println("[AuthServer]  JWT token issued successfully")
	log.Println("[AuthServer] ========================================")
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found, using system environment variables")
	}

	_ = getJWTSecret()

	ctx := context.Background()

	otlpEndpoint := "localhost:4317"

	cfg := telemetry.Config{
		ServiceName:    "authserver",
		ServiceVersion: "1.0.0",
		Environment:    "development",
		OTLPEndpoint:   otlpEndpoint,
	}

	if err := telemetry.InitTelemetry(ctx, cfg); err != nil {
		log.Printf("Warning: Failed to initialize telemetry: %v", err)
		log.Println("Continuing without telemetry...")
	}

	r := mux.NewRouter()

	r.HandleFunc("/authorize", handleAuthorize).Methods("GET")
	r.HandleFunc("/consent", handleConsent).Methods("POST")
	r.HandleFunc("/token", handleToken).Methods("POST")

	handler := middleware.TelemetryMiddleware(r)

	server := &http.Server{
		Addr:    ":8081",
		Handler: handler,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("\n[AuthServer] Shutting down...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := telemetry.Shutdown(shutdownCtx); err != nil {
			log.Printf("[AuthServer] Error shutting down telemetry: %v", err)
		}

		server.Shutdown(shutdownCtx)
	}()

	fmt.Println("")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("AUTHORIZATION SERVER WITH OPENTELEMETRY")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("Server:            http://localhost:8081")
	fmt.Println("OTLP Endpoint:     " + otlpEndpoint)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  GET  /authorize - Authorization endpoint (shows consent page)")
	fmt.Println("  POST /consent   - User consent decision (allow/deny)")
	fmt.Println("  POST /token     - Token endpoint (validates PKCE)")
	fmt.Println("")
	fmt.Println("Metrics being collected:")
	fmt.Println("  • http_requests_total")
	fmt.Println("  • http_request_duration_seconds")
	fmt.Println("  • oauth_authorization_requests_total")
	fmt.Println("  • oauth_consent_decisions_total")
	fmt.Println("  • oauth_token_exchanges_total")
	fmt.Println("  • oauth_pkce_verifications_total")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("")

	log.Fatal(server.ListenAndServe())
}
