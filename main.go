package main

import (
	"database/sql"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
	cookie_name = "beep-beep"
)

var t *template.Template

func normalizeEmail(e string) string {
	return strings.ToLower(e)
}

func secret(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, cookie_name)

	// Check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Print secret message
	fmt.Fprintln(w, "The cake is a lie!")
}

type LoginDetails struct {
	Email    string
	Password string
}

type LoginContext struct {
	Action string
}

func signup(w http.ResponseWriter, r *http.Request) {
	// session, _ := store.Get(r, cookie_name)

	if r.Method == http.MethodPost {
		db, err := sql.Open("sqlite3", "./accounts.db")
		checkErr(err)

		details := LoginDetails{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		email := normalizeEmail(details.Email)

		q, err := db.Prepare("SELECT 1 FROM users WHERE email = ?")
		checkErr(err)
		rows, err := q.Query(email)

		if rows.Next() {
			panic("aiee already exists")
		} else {
			fmt.Println("kk cool")
		}

		rows.Close() //good habit to close

		password, err := bcrypt.GenerateFromPassword([]byte("abc123"), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}


		// insert
		stmt, err := db.Prepare("INSERT INTO users(email, password) values(?,?)")
		checkErr(err)

		res, err := stmt.Exec(email, password)
		checkErr(err)

		id, err := res.LastInsertId()
		checkErr(err)

		fmt.Println(id)
		t.ExecuteTemplate(w, "signup.tmpl", LoginContext{Action: "/signup"})
	} else {
		t.ExecuteTemplate(w, "signup.tmpl", LoginContext{Action: "/signup"})
	}

	// // Set user as authenticated
	// session.Values["authenticated"] = true
	// session.Save(r, w)
}

func login(w http.ResponseWriter, r *http.Request) {
	// session, _ := store.Get(r, cookie_name)

	if r.Method == http.MethodPost {

		details := LoginDetails{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		password := details.Password
		hash := "asdfasdf"
		matches := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
		if !matches {
			panic("oh nooooo")
		}
		t.ExecuteTemplate(w, "signup.tmpl", LoginContext{Action: "/login"})
	} else {
		t.ExecuteTemplate(w, "signup.tmpl", LoginContext{Action: "/login"})
	}

	// // Set user as authenticated
	// session.Values["authenticated"] = true
	// session.Save(r, w)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, cookie_name)

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Save(r, w)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func hi_db() {
	db, err := sql.Open("sqlite3", "./accounts.db")
	checkErr(err)

	// insert
	stmt, err := db.Prepare("INSERT INTO users(email, password) values(?,?)")
	checkErr(err)

	res, err := stmt.Exec("uniphil@gmail.com", "研发部门")
	checkErr(err)

	id, err := res.LastInsertId()
	checkErr(err)

	fmt.Println(id)
	// update
	stmt, err = db.Prepare("update users set email=? where id=?")
	checkErr(err)

	res, err = stmt.Exec("blah@example.com", id)
	checkErr(err)

	affect, err := res.RowsAffected()
	checkErr(err)

	fmt.Println(affect)

	// query
	rows, err := db.Query("SELECT * FROM users")
	checkErr(err)
	var id_ int
	var email string
	var password string
	var created time.Time
	var v_code string
	var verified sql.NullTime

	for rows.Next() {
		err = rows.Scan(&id_, &email, &created, &password, &v_code, &verified)
		checkErr(err)
		fmt.Println(id_)
		fmt.Println(email)
		fmt.Println(password)
		fmt.Println(created)
		fmt.Println(v_code)
		if verified.Valid {
			fmt.Println(verified.Time)
		} else {
			fmt.Println("not verified.")
		}
	}

	rows.Close() //good habit to close

	// delete
	stmt, err = db.Prepare("delete from users where id=?")
	checkErr(err)

	res, err = stmt.Exec(id)
	checkErr(err)

	affect, err = res.RowsAffected()
	checkErr(err)

	fmt.Println(affect)

	db.Close()
}

func main() {
	hi_db()
	var err error
	t, err = template.ParseGlob("templates/*.tmpl")
	if err != nil {
		panic(err)
	}
	r := mux.NewRouter()
	r.HandleFunc("/", hello)
	r.HandleFunc("/secret", secret)
	r.HandleFunc("/signup", signup)
	r.HandleFunc("/login", login)
	r.HandleFunc("/logout", logout)
	http.ListenAndServe(":8080", r)
}

func hello(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h, err := bcrypt.GenerateFromPassword([]byte("abc123"), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		t.ExecuteTemplate(w, "signup.tmpl", h)
	} else {
		t.ExecuteTemplate(w, "signup.tmpl", "asdf")
	}
}
