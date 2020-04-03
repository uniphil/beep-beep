package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"github.com/go-redis/redis"
	"github.com/gorilla/csrf"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var cookie_name = "beep-beep"

var (
	csrf_key [32]byte
	key      [32]byte // key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	t        *template.Template
	db       *sql.DB
	rdb      *redis.Client
	store    *sessions.CookieStore
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
		t.ExecuteTemplate(w, "signup.tmpl", map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
		})
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
		if err.Error() == "UNIQUE constraint failed: users.email" { // user exists
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect) // 307 maintains POST
			return
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
		t.ExecuteTemplate(w, "login.tmpl", map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"Next":           r.URL.Query().Get("next"),
		})
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
	if next := r.URL.Query().Get("next"); next != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
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

func new_domain(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value("user").(*User)
	if user == nil {
		http.Error(w, "(not logged in)", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		t.ExecuteTemplate(w, "new-domain.tmpl", map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"User":           user,
		})
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

var account_detail = require_user(func(w http.ResponseWriter, r *http.Request, u User) {
	stmt, err := db.Prepare("SELECT created, email_verified FROM users WHERE id = ?")
	if err != nil {
		http.Error(w, err.Error()+" (sql statement error)", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	var created time.Time
	var email_verified sql.NullTime
	err = stmt.QueryRow(u.Id).Scan(&created, &email_verified)
	if err != nil {
		http.Error(w, err.Error()+" (sql query error)", http.StatusInternalServerError)
		return
	}
	err = t.ExecuteTemplate(w, "account_detail.tmpl", map[string]interface{}{
		"User":     u,
		"Created":  created,
		"Verified": email_verified.Valid,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
})

var domain_detail = require_user(func(w http.ResponseWriter, r *http.Request, u User) {
	host := mux.Vars(r)["host"]

	stmt, err := db.Prepare("SELECT key FROM domains WHERE host=? and user_id=?")
	if err != nil {
		http.Error(w, err.Error()+" (while setting up db query)", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	var key string
	err = stmt.QueryRow(host, u.Id).Scan(&key)
	if err != nil {
		http.Error(w, "Error while looking up domain: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.ExecuteTemplate(w, "domain_detail.tmpl", map[string]interface{}{
		"User": u,
		"Host": host,
		"Key":  key,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
})

func require_user(h func(w http.ResponseWriter, r *http.Request, u User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, _ := r.Context().Value("user").(*User)
		if user == nil {
			http.Redirect(w, r, "/login?next="+r.URL.EscapedPath(), http.StatusFound)
			return
		}
		h(w, r, *user)
	}
}

type Domain struct {
	Host             string
	Key              string
	Visits           int64
	VisitorsEstimate int64
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

			date_range := redis.ZRangeBy{
				Min: "2020",
				Max: "2021",
			}

			var visitors_estimate int64
			hlls, err := rdb.ZRangeByScore("counts:hlls:all:"+host, date_range).Result()
			if err == nil && len(hlls) > 0 {
				hll_total, err := rdb.PFCount(hlls...).Result()
				if err == nil {
					visitors_estimate += hll_total
				}
			}

			var visits int64
			counts, err := rdb.ZRangeByScore("counts:abss:all:"+host, date_range).Result()
			if err == nil && len(counts) > 0 {
				counters := rdb.MGet(counts...).Val()
				if err == nil {
					for _, counter := range counters {
						n, err := strconv.ParseInt(counter.(string), 10, 64)
						if err == nil {
							visits += n
						}
					}
				}
			}

			var dnt_visits int64
			dnts, err := rdb.ZRangeByScore("counts:dnt:"+host, date_range).Result()
			if err == nil && len(dnts) > 0 {
				counts, err := rdb.MGet(dnts...).Result()
				if err == nil {
					for _, count := range counts {
						n, err := strconv.ParseInt(count.(string), 10, 64)
						if err == nil {
							dnt_visits += n
						}
					}
				}
			}

			dnt_rate_estimate := 1.0
			if visits > 0 {
				dnt_rate_estimate = float64(dnt_visits) / float64(dnt_visits+visits)
			}
			dnt_visitors_estimate := float64(visitors_estimate) * dnt_rate_estimate

			domains = append(domains, Domain{
				Host:             host,
				Visits:           dnt_visits + visits,
				VisitorsEstimate: visitors_estimate + int64(math.Round(dnt_visitors_estimate)),
				Key:              key,
			})
		}

	}
	t.ExecuteTemplate(w, "home.tmpl", map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
		"User":           user,
		"Domains":        domains,
	})
}

func static_template(w http.ResponseWriter, r *http.Request) {
	template_name := strings.TrimPrefix(r.URL.EscapedPath(), "/") + ".tmpl"
	user, _ := r.Context().Value("user").(*User)
	err := t.ExecuteTemplate(w, template_name, map[string]interface{}{
		"User": user,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
	}
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

func Cache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=31536000") // 365 days
		h.ServeHTTP(w, r)
	})
}

func SecurityHeaders(strict bool) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "same-origin")
			if strict {
				w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src https://beep-beep.net; style-src https://beep-beep.net; img-src https://beep-beep.net https://visit.beep-beep.net; connect-src https://beep-beep.net; prefetch-src https://beep-beep.net https://visit.beep-beep.net; block-all-mixed-content; disown-opener")
				w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
				w.Header().Set("Feature-Policy",
					// never annoy
					"autoplay 'none';"+
						"speaker 'none';"+
						"midi 'none';"+
						// trust
						"camera 'none';"+
						"microphone 'none';"+
						"usb 'none';"+
						"geolocation 'none';"+
						"gyroscope 'none';"+
						"ambient-light-sensor 'none';"+
						"vr 'none';"+
						// security-ish
						"document-write 'none';"+
						"fullscreen 'none';"+
						"document-domain 'none';"+
						"display-capture 'none';"+
						// bee good"
						"unsized-media 'none';"+
						"unoptimized-images 'none';"+
						"oversized-images 'none';"+
						"sync-script 'none';"+
						"sync-xhr 'none';"+
						"encrypted-media 'none';"+
						"vertical-scroll 'none'")
			}
			h.ServeHTTP(w, r)
		})
	}
}

func main() {
	DEVMODE := os.Getenv("DEV") != ""
	_, err := rand.Read(key[:])
	if err != nil {
		panic(err)
	}
	_, err = rand.Read(csrf_key[:])
	if err != nil {
		panic(err)
	}
	store = sessions.NewCookieStore(key[:])
	store.Options.HttpOnly = true
	if !DEVMODE {
		store.Options.Secure = true
	}
	t = template.Must(template.ParseGlob("templates/*.tmpl"))
	db, err = sql.Open("sqlite3", "./accounts.db")
	if err != nil {
		panic(err)
	}
	rdb = redis.NewClient(&redis.Options{})

	r := mux.NewRouter()
	r.Use(handlers.RecoveryHandler())
	r.Use(SecurityHeaders(!DEVMODE))
	r.Use(csrf.Protect(csrf_key[:], csrf.Secure(!DEVMODE)))
	r.Use(GetSession)

	r.HandleFunc("/", home)
	r.HandleFunc("/about", static_template)
	r.HandleFunc("/account", account_detail)
	r.HandleFunc("/contact", static_template)
	r.HandleFunc("/domains/{host}", domain_detail)
	r.HandleFunc("/login", login)
	r.HandleFunc("/logout", logout)
	r.HandleFunc("/new-domain", new_domain)
	r.HandleFunc("/pricing", static_template)
	r.HandleFunc("/privacy", static_template)
	r.HandleFunc("/signup", signup)

	r.PathPrefix("/static/").Handler(
		Cache(http.StripPrefix("/static/", http.FileServer(http.Dir("static/")))))
	r.PathPrefix("/").Handler(
		Cache(http.FileServer(http.Dir("static/_root/"))))

	host := "0.0.0.0"
	if DEVMODE {
		host = "localhost"
	}
	fmt.Println(host+".", "Dev:", DEVMODE)
	http.ListenAndServe(host+":8080", r)
}
