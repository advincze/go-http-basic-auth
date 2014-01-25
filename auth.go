package auth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

type Auth struct {
	fn authFunc
}

func NewAuth(fn authFunc) *Auth {
	return &Auth{fn}
}

func NewConstantAuth(constuser, constpwd string) *Auth {
	a := &Auth{}
	a.setConstantAuth(constuser, constpwd)
	return a
}

func (a *Auth) setConstantAuth(constuser, constpwd string) {
	a.fn = func(user, pwd string) bool {
		if user == constuser && pwd == constpwd {
			return true
		}
		return false
	}
}

func (a *Auth) setAuth(fn authFunc) {
	a.fn = fn
}

func (a *Auth) BasicFunc(handlerFn http.HandlerFunc) http.HandlerFunc {
	return a.Basic(handlerFn)
}

func (a *Auth) Basic(handler http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if a.fn == nil {
			handler.ServeHTTP(w, req)
			return
		}

		// extract username and password
		authInfo := req.Header.Get("Authorization")
		if authInfo == "" {
			// No authorization info, return 401
			unauthorized(w)
			return
		}
		parts := strings.Split(authInfo, " ")
		if len(parts) != 2 {
			badRequest(w, "Bad authorization header")
			return
		}
		scheme := parts[0]
		creds, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			badRequest(w, "Bad credentials encoding")
			return
		}
		index := bytes.Index(creds, []byte(":"))
		if scheme != "Basic" || index < 0 {
			badRequest(w, "Bad authorization header")
			return
		}
		username, pwd := string(creds[:index]), string(creds[index+1:])
		if a.fn(username, pwd) {
			handler.ServeHTTP(w, req)
		} else {
			unauthorized(w)
		}
	})
}

type authFunc func(user, pwd string) bool

var defaultAuth = &Auth{}

func SetConstantAuth(constuser, constpwd string) {
	defaultAuth.setConstantAuth(constuser, constpwd)
}

func SetAuth(fn authFunc) {
	defaultAuth.setAuth(fn)
}

func BasicFunc(handlerFn http.HandlerFunc) http.HandlerFunc {
	return defaultAuth.BasicFunc(handlerFn)
}

func Basic(handler http.Handler) http.HandlerFunc {
	return defaultAuth.Basic(handler)
}

func badRequest(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	if msg == "" {
		msg = "Bad Request"
	}
	w.Write([]byte(msg))
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Www-Authenticate", fmt.Sprintf("Basic"))
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("Unauthorized"))
}
