package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

type TokenClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Scope    string `json:"scope"`
	Client   string `json:"client"`
	jwt.RegisteredClaims
}

func validateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(getJWTSecret()), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			return nil, fmt.Errorf("token has expired")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

func hasScope(claims *TokenClaims, requiredScope string) bool {
	scopes := strings.Split(claims.Scope, " ")
	for _, scope := range scopes {
		if scope == requiredScope {
			return true
		}
	}
	return false
}

func handleUserData(w http.ResponseWriter, r *http.Request) {
	log.Println("\n[ResourceServer] ========================================")
	log.Println("[ResourceServer] Received /user/data request")

	authHeader := r.Header.Get("Authorization")
	log.Printf("[ResourceServer] Authorization header: %s", authHeader)

	if authHeader == "" {
		log.Println("[ResourceServer] ERROR: Missing Authorization header")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "missing_token",
			"error_description": "Authorization header is required",
		})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		log.Println("[ResourceServer] ERROR: Invalid Authorization header format")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "Authorization header must be 'Bearer <token>'",
		})
		return
	}

	token := parts[1]
	log.Printf("[ResourceServer] Extracted JWT token")
	log.Printf("[ResourceServer] Token preview: %s...", token[:50])

	claims, err := validateToken(token)
	if err != nil {
		log.Printf("[ResourceServer] ERROR: Token validation failed: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_token",
			"error_description": "The access token is invalid or expired",
		})
		return
	}

	log.Println("[ResourceServer]  JWT token validated successfully!")
	log.Printf("[ResourceServer]  Token Claims:")
	log.Printf("[ResourceServer]    - Issuer: %s", claims.Issuer)
	log.Printf("[ResourceServer]    - Subject (User): %s", claims.Subject)
	log.Printf("[ResourceServer]    - Audience (Client): %s", claims.Audience)
	log.Printf("[ResourceServer]    - Scopes: %s", claims.Scope)
	log.Printf("[ResourceServer]    - Expires: %v", claims.ExpiresAt.Time)

	if !hasScope(claims, "read") {
		log.Println("[ResourceServer] ERROR: Insufficient scope - 'read' scope required")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "insufficient_scope",
			"error_description": "The access token does not have the required 'read' scope",
		})
		return
	}

	log.Println("[ResourceServer]  Required 'read' scope verified")

	message := "OAuth2 test data - Access granted!"

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(message))

	log.Printf("[ResourceServer]  Returned message: %s", message)
	log.Println("[ResourceServer] ========================================")
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found, using system environment variables")
	}

	_ = getJWTSecret()

	r := mux.NewRouter()

	r.HandleFunc("/user/data", handleUserData).Methods("GET")

	fmt.Println("========================================")
	fmt.Println("RESOURCE SERVER")
	fmt.Println("========================================")
	fmt.Println("Starting Resource Server on http://localhost:8082")
	fmt.Println("✓ JWT_SECRET loaded from environment")
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  GET /user/data - Protected endpoint (requires Bearer token)")
	fmt.Println("")
	fmt.Println("Waiting for requests...")
	fmt.Println("========================================")

	log.Fatal(http.ListenAndServe(":8082", r))
}
