package main

import (
	"fmt"
	"net/http"

	"github.com/advincze/auth"
	"github.com/gorilla/mux"
)

func main() {

	auth.SetConstantAuth("foo", "bar")

	type User struct {
		Usr string
		Pwd string
	}

	users := []*User{
		{"bob", "secret"},
		{"alice", "secret2"},
	}

	auth.SetAuth(func(usr, pwd string) bool {
		for _, user := range users {
			if user.Usr == usr && user.Pwd == pwd {
				return true
			}
		}
		return false
	})

	router := mux.NewRouter()

	au th1 := auth.NewConstantAuth("x", "y")
	router.HandleFunc("/foo", auth1.BasicFunc(foo))
	router.HandleFunc("/bar", auth1.BasicFunc(bar))

	router.HandleFunc("/foo2", auth.BasicFunc(foo))
	router.HandleFunc("/bar2", bar)

	http.ListenAndServe(":8080", router)
}

func foo(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "foo\n")

}

func bar(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "bar\n")
}
