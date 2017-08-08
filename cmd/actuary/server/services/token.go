package services

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// Set our secret.
// TODO: Use generated key from README
var mySigningKey = []byte("secret")

// Token defines a token for our application
type Token string

// TokenService provides a token
type TokenService interface {
	Get(u *User) (string, error)
}

type tokenService struct {
	UserService UserService
}

// NewTokenService creates a new UserService
func NewTokenService() TokenService {
	return &tokenService{}
}

// Get retrieves a token for a user
func (s *tokenService) Get(u *User) (string, error) {
	// Create token
	token := jwt.New(jwt.SigningMethodHS256)

	// Try to log in the user
	user, err := s.UserService.Read(u.ID)
	if err != nil {
		return "", errors.New("Failed to retrieve user")
	}
	if user == nil {
		return "", errors.New("Failed to retrieve user")
	}

	// Set token claims
	claims := token.Claims.(jwt.MapClaims)
	claims["admin"] = true
	claims["user"] = u
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	// Sign token with key
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		return "", errors.New("Failed to sign token")
	}

	return tokenString, nil
}
