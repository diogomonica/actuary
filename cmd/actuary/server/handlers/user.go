package handlers

import (
	"github.com/diogomonica/actuary/cmd/actuary/server/services"
	"net/http"
)

// Users provides API access to the user service
type Users struct {
	Service services.UserService
}

// NewUsers creates a users handler
func NewUsers(s services.UserService) *Users {
	return &Users{s}
}

// Handler handles requests to /users
func (u *Users) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
	case "POST":
	case "PUT":
	case "DELETE":
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}
