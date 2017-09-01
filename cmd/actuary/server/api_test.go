package server

import (
	"github.com/diogomonica/actuary/cmd/actuary/server/handlers"
	"github.com/diogomonica/actuary/cmd/actuary/server/services"
	"github.com/stretchr/testify/assert"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAPI(t *testing.T) {
	apiTest := NewAPI("certPath", "keyPath")
	assert.NotEmpty(t, apiTest.encryptionKey)
	assert.NotEmpty(t, apiTest.Tokens)
}

func testHandler(w http.ResponseWriter, r *http.Request) {

}

func TestAuthenticatePass(t *testing.T) {
	tokenService := services.NewTokenService([]byte("key"))
	testAPI := API{[]byte("key"), handlers.NewTokens(tokenService)}
	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { testHandler(w, r) })
	handler := testAPI.Authenticate(test)
	r, err := http.NewRequest("GET", "https://server:8000/results", nil)
	r.Header.Set("Content-Type", "application/json")
	token, err := tokenService.Get()
	if err != nil {
		log.Fatalf("Could not create test token: %v", err)

	}
	var bearer = "Bearer " + token
	r.Header.Add("authorization", bearer)
	if err != nil {
		log.Fatalf("Could not create a new request: %v", err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, 200, w.Code, "Should authenticate this request")
}

func TestAuthenticateFail(t *testing.T) {
	tokenService := services.NewTokenService([]byte("notkey"))
	testAPI := API{[]byte("key"), handlers.NewTokens(tokenService)}
	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { testHandler(w, r) })
	handler := testAPI.Authenticate(test)
	r, err := http.NewRequest("GET", "https://server:8000/results", nil)
	if err != nil {
		log.Fatalf("Could not create request: %v", err)
	}
	r.Header.Set("Content-Type", "application/json")
	token, err := tokenService.Get()
	if err != nil {
		log.Fatalf("Could not create test token: %v", err)

	}
	var bearer = "Bearer " + token
	r.Header.Add("authorization", bearer)
	if err != nil {
		log.Fatalf("Could not create a new request: %v", err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, 401, w.Code, "Should authenticate this request")
}
