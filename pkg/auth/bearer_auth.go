package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	logging "github.com/op/go-logging"
)

// BearerAuth - Performs an HTTP Bearer token auth validation.
type BearerAuth struct {
	usa UserServiceAdapter
	log *logging.Logger
}

// NewBearerAuth - constructs a BearerAuth instance.
func NewBearerAuth(userSvcAdapter UserServiceAdapter, log *logging.Logger) BearerAuth {
	return BearerAuth{usa: userSvcAdapter, log: log}
}

// GetPrincipal - returns the User Principal that matches the credentials in the
// Authorization header.
func (b BearerAuth) GetPrincipal(r *http.Request) (Principal, error) {
	const prefix = "Bearer "
	authheader := r.Header.Get("Authorization")
	if strings.HasPrefix(authheader, prefix) {
		token := authheader[len(prefix):]
		fmt.Println(token)
	}

	/*
		if username, password, ok := r.BearerAuth(); ok {
			if !b.usa.ValidateUser(username, password) {
				return nil, errors.New("invalid credentials")
			}
			return b.createPrincipal(username)
		}

	*/
	return nil, errors.New("invalid credentials, corrupt header")
}

func (b BearerAuth) createPrincipal(username string) (Principal, error) {
	// don't care about the user right now, just trying to see if it
	// exists. In the future we might want to check its permissions etc.
	_, err := b.usa.FindByLogin(username)
	if err != nil {
		return nil, err
	}
	return UserPrincipal{username: username}, nil
}
