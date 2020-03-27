package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"strings"
)

var cookie_name = "beep-beep"

var (
	key   [32]byte // key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	t     *template.Template
	db    *sql.DB
	store *sessions.CookieStore
)

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

type User struct {
	Email string
}

func signup(w http.ResponseWriter, r *http.Request) {
	session, _ := (*store).Get(r, cookie_name)

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
	session, _ := (*store).Get(r, cookie_name)

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
	session, err := (*store).Get(r, cookie_name)
	if e, ie := err.(securecookie.Error); ie && e.IsDecode() {
		// decode error: we can just redirect home; the invalid cookie will be cleared automatically
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	} else if err != nil {
		http.Error(w, err.Error()+" (in logout)", http.StatusInternalServerError)
		return
	}
	delete(session.Values, "user_id")
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func home(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user")
	t.ExecuteTemplate(w, "home.tmpl", user)
}

func GetSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := (*store).Get(r, cookie_name)
		var user *User
		if err != nil {
			if e, ie := err.(securecookie.Error); ie && e.IsDecode() {
				// pass --
				// (*store).Options.MaxAge = -1
				// delete(*store, cookie_name)
			} else {
				http.Error(w, err.Error()+" (cookie error)", http.StatusInternalServerError)
				return
			}
		} else {
			id, exists := session.Values["user_id"]
			if !exists {
				goto anywayyy
			}
			stmt, err := db.Prepare("SELECT email FROM users WHERE id = ?")
			if err != nil {
				http.Error(w, err.Error()+" (sql statement error)", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			var email string
			err = stmt.QueryRow(id).Scan(&email)
			if err == sql.ErrNoRows {
				// no user with this id??
				delete(session.Values, "user_id")
				goto anywayyy
			} else if err != nil {
				http.Error(w, err.Error()+" (sql query error???)", http.StatusInternalServerError)
				return
			}
			user = &User{Email: email}
		}
	anywayyy:
		r = r.WithContext(context.WithValue(r.Context(), "user", user))
		next.ServeHTTP(w, r)
	})
}

func main() {
	_, err := rand.Read(key[:])
	if err != nil {
		panic(err)
	}

	store = sessions.NewCookieStore(key[:])

	t = template.Must(template.ParseGlob("templates/*.tmpl"))

	db_, err := sql.Open("sqlite3", "./accounts.db")
	if err != nil {
		panic(err)
	}
	db = db_

	r := mux.NewRouter()
	r.Use(GetSession)

	r.HandleFunc("/", home)
	r.HandleFunc("/signup", signup)
	r.HandleFunc("/login", login)
	r.HandleFunc("/logout", logout)

	http.ListenAndServe(":8080", r)
}
