package main

import (
	"database/sql"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"net/http"
	"strings"
)

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key         = []byte("super-secret-key")
	store       = sessions.NewCookieStore(key)
	cookie_name = "beep-beep"
)

var t *template.Template
var db *sql.DB

func normalizeEmail(e string) string {
	return strings.ToLower(e)
}

type LoginDetails struct {
	Email    string
	Password string
}

type LoginContext struct {
	Action string
}

func signup(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, cookie_name)

	if r.Method == http.MethodPost {

		details := LoginDetails{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		email := normalizeEmail(details.Email)

		password, err := bcrypt.GenerateFromPassword([]byte("abc123"), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}

		stmt, err := db.Prepare("INSERT INTO users(email, password) values(?,?)")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res, err := stmt.Exec(email, password)
		if err != nil {
			if err.Error() == "UNIQUE constraint failed: users.email" {
				http.Error(w, "Email already exists", http.StatusForbidden)
			} else {
				http.Error(w, "Error while trying to create account", http.StatusForbidden)
			}
			return
		}

		user_id, err := res.LastInsertId()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Values["user_id"] = user_id
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		t.ExecuteTemplate(w, "signup.tmpl", LoginContext{Action: "/signup"})
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, cookie_name)

	if r.Method == http.MethodPost {

		details := LoginDetails{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		email := normalizeEmail(details.Email)

		q, err := db.Prepare("SELECT id, password FROM users WHERE email = ?")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rows, err := q.Query(email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var id int
		var password_hash []byte
		for rows.Next() {
			err := rows.Scan(&id, &password_hash)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			matches := bcrypt.CompareHashAndPassword(password_hash, []byte(details.Password))

			if matches != nil {
				http.Error(w, "Incorrect password", http.StatusForbidden)
				return
			}
		}

		session.Values["user_id"] = id
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		t.ExecuteTemplate(w, "login.tmpl", LoginContext{Action: "/login"})
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookie_name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	delete(session.Values, "user_id")
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type User struct {
	Email string
}

func getUser(session *sessions.Session) *User {
	id, exists := session.Values["user_id"]
	if !exists {
		return &User{}
	}
	stmt, err := db.Prepare("SELECT email FROM users WHERE id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	var email string
	err = stmt.QueryRow(id).Scan(&email)
	switch {
	case err == sql.ErrNoRows:
		// no user with this id??
		delete(session.Values, "user_id")
		// deletion may not get saved, but that shouldn't matter
		return &User{}
	case err != nil:
		log.Fatal(err)
	}
	return &User{Email: email}
}

func home(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookie_name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user := getUser(session)
	t.ExecuteTemplate(w, "home.tmpl", user)
}

func main() {
	t = template.Must(template.ParseGlob("templates/*.tmpl"))

	db_, err := sql.Open("sqlite3", "./accounts.db")
	if err != nil {
		panic(err)
	}
	db = db_

	r := mux.NewRouter()
	r.HandleFunc("/", home)
	r.HandleFunc("/signup", signup)
	r.HandleFunc("/login", login)
	r.HandleFunc("/logout", logout)

	http.ListenAndServe(":8080", r)
}
