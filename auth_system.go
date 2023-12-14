package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username     string
	PasswordHash string
}

var UsersDB = map[string]User{}

var Templates = template.Must(template.ParseFiles("login.html", "register.html"))

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		Templates.ExecuteTemplate(w, "register.html", nil)
	case "POST":
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		if _, exists := UsersDB[username]; exists {
			fmt.Fprintf(w, "User already exists!\n")
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		UsersDB[username] = User{Username: username, PasswordHash: string(hashedPassword)}
		fmt.Fprintf(w, "User registered successfully!\n")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		Templates.ExecuteTemplate(w, "login.html", nil)
	case "POST":
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		user, exists := UsersDB[username]
		if !exists {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}
		err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "Login successful! Welcome, %s!\n", username)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/login", LoginHandler)

	log.Println("Starting server on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
