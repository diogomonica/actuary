package handlers

import (
	"github.com/diogomonica/actuary/cmd/actuary/server/services"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestServeHTTPPass(t *testing.T) {
	tokenService := services.NewTokenService([]byte("key"))
	tokens := NewTokens(tokenService)
	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "https://server:8000/results", nil)
	req.SetBasicAuth("defaultUser", "password")
	if err != nil {
		log.Fatalf("Could not create request: %v", err)
	}
	tmpfile, err := ioutil.TempFile("", "pw")
	if err != nil {
		log.Fatalf("Could not create password file %v", err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write([]byte("password")); err != nil {
		log.Fatal(err)
	}
	os.Setenv("TOKEN_PASSWORD", tmpfile.Name())

	tokens.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code, "Should authenticate this request")
}

func TestServeHTTPFail(t *testing.T) {
	tokenService := services.NewTokenService([]byte("key"))
	tokens := NewTokens(tokenService)
	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "https://server:8000/results", nil)
	req.SetBasicAuth("defaultUser", "notpassword")
	if err != nil {
		log.Fatalf("Could not create request: %v", err)
	}
	tmpfile, err := ioutil.TempFile("", "pw")
	if err != nil {
		log.Fatalf("Could not create password file %v", err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write([]byte("password")); err != nil {
		log.Fatal(err)
	}
	os.Setenv("TOKEN_PASSWORD", tmpfile.Name())

	tokens.ServeHTTP(w, req)
	log.Printf("CODE: %v", w.Code)
	assert.Equal(t, 403, w.Code, "Request should not be authenticated")
}
