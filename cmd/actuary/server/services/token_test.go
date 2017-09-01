package services

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewTokenService(t *testing.T) {
	key := []byte("Key")
	testTS := NewTokenService(key)
	realTS := tokenService{signingKey: []byte("Key")}
	var pointerTS = &realTS
	assert.Equal(t, testTS, pointerTS, "Signing key not passed correctly to new token service")
}

// Test for Get function, not good enough?
func TestGet(t *testing.T) {
	key := []byte("Key")
	tokenService := NewTokenService(key)
	tokenString, err := tokenService.Get()
	if err != nil {
		t.Errorf("Could not sign token: %s", err)
	}
	assert.NotEqual(t, "Key", tokenString, "Key should have been signed")
}
