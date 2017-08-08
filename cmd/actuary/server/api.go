package server

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/diogomonica/actuary/cmd/actuary/server/handlers"
	"github.com/diogomonica/actuary/cmd/actuary/server/services"
	"github.com/gorilla/context"
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

// NewAPI creates a new API
func NewAPI(certPath, keyPath string) *API {
	aclService := services.NewACLService()
	tokenService := services.NewTokenService()
	userService := services.NewUserService()

	return &API{
		AclService: aclService,
		Tokens:     handlers.NewTokens(tokenService),
		Users:      handlers.NewUsers(userService),
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
			fmt.Println("test")
		}
		// Token is invalid
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	})
}

// Authorize provides authorization middleware for our handlers
func (a *API) Authorize(permissions ...services.Permission) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: Get User Information from Request
			user := &services.User{
				ID:        1,
				FirstName: "Admin",
				LastName:  "User",
				Roles:     []string{services.AdministratorRole},
			}
			for _, permission := range permissions {
				if err := a.AclService.CheckPermission(user, permission); err != nil {
					http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecureHeaders adds secure headers to the API
func (a *API) SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Add security headers here
		next.ServeHTTP(w, r)
	})
}
