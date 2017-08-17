package services

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// Set our secret.
// TODO: Use generated key from README

// Token defines a token for our application
type Token string

// TokenService provides a token
type TokenService interface {
	Get(u *User) (string, error)
}

type tokenService struct {
	signingKey []byte
}

// NewTokenService creates a new UserService
func NewTokenService(key []byte) TokenService {
	return &tokenService{key}
}

// Get retrieves a token for a user
func (s *tokenService) Get(u *User) (string, error) {
	// Create token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set token claims
	claims := token.Claims.(jwt.MapClaims)
	claims["admin"] = true
	claims["user"] = u
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	// Sign token with key
	tokenString, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", errors.New("Failed to sign token")
	}

	return tokenString, nil
}
