package services

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// Token defines a token for our application
type Token string

// TokenService provides a token
type TokenService interface {
	Get() (string, error)
}

type tokenService struct {
	signingKey []byte
}

// NewTokenService creates a new service
func NewTokenService(key []byte) TokenService {
	return &tokenService{key}
}

func (s *tokenService) Get() (string, error) {
	// Create token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set token claims
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	// Sign token with key
	tokenString, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", errors.New("Failed to sign token")
	}
	return tokenString, nil
}
