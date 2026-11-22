package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnauthorized   = errors.New("unauthorized")
	ErrTokenExpired   = errors.New("token has expired")
	ErrInvalidSignature = errors.New("invalid signature")
)

// Authenticator handles Bearer Token and Basic authentication for OCI V2.
type Authenticator struct {
	mu         sync.RWMutex
	secretKey  []byte
	users      map[string]string // username -> bcrypt/sha256 hash
	realm      string
	service    string
	tokenExpiry time.Duration
}

// TokenPayload represents the claims of a generated JWT-style Bearer token.
type TokenPayload struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  string          `json:"aud"`
	ExpiresAt int64           `json:"exp"`
	IssuedAt  int64           `json:"iat"`
	Access    []ResourceAccess `json:"access"`
}

// ResourceAccess specifies permission on an OCI repository.
type ResourceAccess struct {
	Type    string   `json:"type"`    // "repository"
	Name    string   `json:"name"`    // "org/repo"
	Actions []string `json:"actions"` // "pull", "push", "*"
}

// NewAuthenticator initializes an authenticator with a 256-bit signing key.
func NewAuthenticator(realm, service string) *Authenticator {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	auth := &Authenticator{
		secretKey:   secret,
		users:       make(map[string]string),
		realm:       realm,
		service:     service,
		tokenExpiry: 2 * time.Hour,
	}

	return auth
}

// AddUser registers a username and password (hashed with sha256).
func (a *Authenticator) AddUser(username, password string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h := sha256.Sum256([]byte(password))
	a.users[username] = hex.EncodeToString(h[:])
}

// VerifyBasicAuth checks username and password against credentials.
func (a *Authenticator) VerifyBasicAuth(username, password string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	h := sha256.Sum256([]byte(password))
	expectedHash, ok := a.users[username]
	if !ok {
		return false
	}
	return hmac.Equal([]byte(expectedHash), []byte(hex.EncodeToString(h[:])))
}

// IssueToken signs a standard JWT token for the granted scopes.
func (a *Authenticator) IssueToken(user string, access []ResourceAccess) (string, error) {
	header := map[string]string{
		"typ": "JWT",
		"alg": "HS256",
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	now := time.Now().UTC()
	payload := TokenPayload{
		Issuer:    a.service,
		Subject:   user,
		Audience:  a.service,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(a.tokenExpiry).Unix(),
		Access:    access,
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, a.secretKey)
	mac.Write([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sigB64, nil
}

// ValidateToken parses and verifies the signature and expiration of an access token.
func (a *Authenticator) ValidateToken(tokenStr string) (*TokenPayload, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token structure")
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, a.secretKey)
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, ErrInvalidSignature
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var payload TokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}

	if time.Now().UTC().Unix() > payload.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return &payload, nil
}

// AuthenticateRequest extracts and verifies Bearer or Basic authentication from HTTP headers.
func (a *Authenticator) AuthenticateRequest(r *http.Request) (*TokenPayload, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, ErrUnauthorized
	}

	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		return a.ValidateToken(tokenStr)
	}

	if strings.HasPrefix(authHeader, "Basic ") {
		user, pass, ok := r.BasicAuth()
		if !ok || !a.VerifyBasicAuth(user, pass) {
			return nil, ErrUnauthorized
		}
		// Generate an ephemeral token payload
		return &TokenPayload{
			Issuer:    a.service,
			Subject:   user,
			ExpiresAt: time.Now().Add(a.tokenExpiry).Unix(),
			Access: []ResourceAccess{
				{Type: "repository", Name: "*", Actions: []string{"pull", "push"}},
			},
		}, nil
	}

	return nil, ErrUnauthorized
}

// WriteAuthChallenge writes the standard 401 Www-Authenticate header.
func (a *Authenticator) WriteAuthChallenge(w http.ResponseWriter, repo, actions string) {
	scope := ""
	if repo != "" {
		scope = fmt.Sprintf(",scope=\"repository:%s:%s\"", repo, actions)
	}
	challenge := fmt.Sprintf("Bearer realm=\"%s\",service=\"%s\"%s", a.realm, a.service, scope)
	w.Header().Set("Www-Authenticate", challenge)
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"errors": []map[string]string{
			{
				"code":    "UNAUTHORIZED",
				"message": "authentication required",
			},
		},
	})
}
