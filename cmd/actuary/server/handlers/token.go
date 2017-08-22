package handlers

import (
	"github.com/diogomonica/actuary/cmd/actuary/server/services"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// Tokens exposes an API to the tokens service
type Tokens struct {
	Service services.TokenService
}

// NewTokens creates new handler for tokens
func NewTokens(s services.TokenService) *Tokens {
	return &Tokens{s}
}

// ServeHTTP will return tokens
func (t *Tokens) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var pw string
	var username string
	var ok bool

	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	// Password for comparison
	password, err := ioutil.ReadFile(os.Getenv("TOKEN_PASSWORD"))
	username, pw, ok = req.BasicAuth()

	pw = strings.TrimSpace(pw)
	passwordString := strings.TrimSpace(string(password))

	if err != nil {
		log.Fatalf("Could not read password: %v", err)
	}

	// Compare passed in password and username from basic auth
	if pw == passwordString && username == "defaultUser" && ok {
		switch req.Method {
		case "GET":
			token, err := t.Service.Get()
			if err != nil {
				http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			}
			w.Write([]byte(token))
		default:
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}
	} else {
		http.Error(w, "Unauthorized request", http.StatusForbidden)
	}
}
