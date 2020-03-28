package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
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

func normalizeHost(e string) string {
	return strings.ToLower(e)
}

type User struct {
	Id    int64
	Email string
}

func signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		t.ExecuteTemplate(w, "signup.tmpl", nil)
		return
	}
	session, err := (*store).Get(r, cookie_name)
	if e, ie := err.(securecookie.Error); ie && e.IsDecode() {
		// invalid cookie nbd; we'll overwrite
	} else if err != nil {
		http.Error(w, err.Error()+" (in logout)", http.StatusInternalServerError)
		return
	}
	email := normalizeEmail(r.FormValue("email"))
	pw_plain := r.FormValue("password")
	pw_hash, err := bcrypt.GenerateFromPassword([]byte(pw_plain), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error()+" (while trying to encrypt password)", http.StatusInternalServerError)
		return
	}

	stmt, err := db.Prepare("INSERT INTO users(email, password) values(?,?)")
	if err != nil {
		http.Error(w, err.Error()+" (while setting up db query)", http.StatusInternalServerError)
		return
	}

	res, err := stmt.Exec(email, pw_hash)
	if err != nil {
		if err.Error() == "UNIQUE constraint failed: users.email" {
			http.Error(w, "Email already exists", http.StatusForbidden)
		} else {
			http.Error(w, "Error while trying to create account— "+err.Error(), http.StatusForbidden)
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
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		t.ExecuteTemplate(w, "login.tmpl", nil)
		return
	}
	session, err := (*store).Get(r, cookie_name)
	if e, ie := err.(securecookie.Error); ie && e.IsDecode() {
		// invalid cookie nbd; we'll overwrite
	} else if err != nil {
		http.Error(w, err.Error()+" (in logout)", http.StatusInternalServerError)
		return
	}
	email := normalizeEmail(r.FormValue("email"))
	pw_plain := r.FormValue("password")

	stmt, err := db.Prepare("SELECT id, password FROM users WHERE email = ?")
	if err != nil {
		http.Error(w, err.Error()+" (while preparing sql)", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()
	var id int64
	var pw_hash []byte
	err = stmt.QueryRow(email).Scan(&id, &pw_hash)
	if err == sql.ErrNoRows { // no user with this id??
		http.Error(w, err.Error()+" (could not find account)", http.StatusInternalServerError)
		return
	} else if err != nil {
		http.Error(w, err.Error()+" (while finding account)", http.StatusInternalServerError)
		return
	}

	matches := bcrypt.CompareHashAndPassword(pw_hash, []byte(pw_plain))
	if matches != nil {
		http.Error(w, "Incorrect password", http.StatusForbidden)
		return
	}

	session.Values["user_id"] = id
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

type Domain struct {
	Host string
}

type NewDomainPageContext struct {
	User *User
}

func new_domain(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value("user").(*User)
	if user == nil {
		http.Error(w, "(not logged in)", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		t.ExecuteTemplate(w, "new-domain.tmpl", NewDomainPageContext{User: user})
		return
	}
	host := normalizeHost(r.FormValue("host"))

	stmt, err := db.Prepare("INSERT INTO domains(host, user_id) values(?,?)")
	if err != nil {
		http.Error(w, err.Error()+" (while setting up db query)", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(host, user.Id)
	if err != nil {
		http.Error(w, "Error while trying to add domain— "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = res.LastInsertId()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type HomePageContext struct {
	User    *User
	Domains []Domain
}

func home(w http.ResponseWriter, r *http.Request) {
	var domains []Domain
	user, _ := r.Context().Value("user").(*User)
	if user != nil {
		stmt, err := db.Prepare("SELECT host, key FROM domains WHERE user_id = ?")
		if err != nil {
			http.Error(w, err.Error()+" (while setting up db query)", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		rows, err := stmt.Query(user.Id)
		if err != nil {
			http.Error(w, "Error while looking up domains domain— "+err.Error(), http.StatusInternalServerError)
			return
		}
		domains = make([]Domain, 0)
		for rows.Next() {
			var host string
			var key string
			err = rows.Scan(&host, &key)
			if err != nil {
				http.Error(w, err.Error()+" (while getting domains)", http.StatusInternalServerError)
				return
			}
			fmt.Println("row", host, key)
			domains = append(domains, Domain{Host: host})
		}

	}

	page_context := HomePageContext{
		User:    user,
		Domains: domains,
	}
	t.ExecuteTemplate(w, "home.tmpl", page_context)
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
			user = &User{
				Email: email,
				Id:    id.(int64),
			}
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
	r.HandleFunc("/new-domain", new_domain)
	http.ListenAndServe(":8080", r)
}
