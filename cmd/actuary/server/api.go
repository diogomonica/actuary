package server

import (
	"crypto/rand"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/diogomonica/actuary/cmd/actuary/server/handlers"
	"github.com/diogomonica/actuary/cmd/actuary/server/services"
	"github.com/gorilla/context"
	"log"
	"net/http"
	"strings"
)

// API holds the api handlers
type API struct {
	encryptionKey []byte
	AclService    services.ACLService
	Tokens        *handlers.Tokens
	Users         *handlers.Users
}

func randomize() []byte {
	c := 32
	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Could not randomize signing key: %v", err)
	}
	return b
}

// NewAPI creates a new API
func NewAPI(certPath, keyPath string) *API {
	var signingKey = randomize()
	aclService := services.NewACLService()
	tokenService := services.NewTokenService(signingKey)
	userService := services.NewUserService()

	return &API{
		encryptionKey: signingKey,
		AclService:    aclService,
		Tokens:        handlers.NewTokens(tokenService),
		Users:         handlers.NewUsers(userService),
	}
}

// Middleware
// Authenticate provides Authentication middleware for handlers
func (a *API) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		// Get token from the Authorization header
		// format: Authorization: Bearer <token>
		tokens, ok := r.Header["Authorization"]
		if ok && len(tokens) >= 1 {
			token = tokens[0]
			token = strings.TrimPrefix(token, "Bearer ")
		}
		// If the token is empty...
		if token == "" {
			// If we get here, the required token is missing
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Now parse the token
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				msg := fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				return nil, msg
			}
			return a.encryptionKey, nil
		})
		if err != nil {
			http.Error(w, "Error parsing token", http.StatusUnauthorized)
			return
		}
		// Check token is valid
		if parsedToken != nil && parsedToken.Valid {
			// Everything worked! Set the user in the context.
			context.Set(r, "user", parsedToken)
			next.ServeHTTP(w, r)
			return
		}
		// Token is invalid
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	})
}

// SecureHeaders adds secure headers to the API
func (a *API) SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Add security headers here
		next.ServeHTTP(w, r)
	})
}
