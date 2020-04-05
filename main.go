package main

import (
	"context"
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
	"sort"
	"strconv"
	"strings"
	"time"
)

var cookie_name = "beep-beep"
var DATE_FORMAT = "20060102"

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
	// TODO: require_user
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

var delete_domain = require_user(func(w http.ResponseWriter, r *http.Request, u User) {
	host := normalizeHost(r.URL.Query().Get("domain"))
	if host == "" {
		// TODO: flash message
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	stmt, err := db.Prepare("SELECT 1 FROM domains WHERE host = ? AND user_id = ?")
	if err != nil {
		http.Error(w, err.Error()+" (while setting up db query)", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	var _n int64
	err = stmt.QueryRow(host, u.Id).Scan(&_n)
	if err == sql.ErrNoRows {
		// TODO: flash message
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	} else if err != nil {
		http.Error(w, "Error while trying to delete domain— "+err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method != http.MethodPost {
		t.ExecuteTemplate(w, "delete-domain.tmpl", map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(r),
			"User":           u,
			"Host":           host,
		})
		return
	}

	confirm_host := normalizeHost(r.FormValue("host-confirm"))
	if confirm_host != host {
		http.Error(w, fmt.Sprintf("Domain confirmation \"%s\" didn't match domain: %s",
			confirm_host, host), http.StatusBadRequest)
		return
	}

	stmt, err = db.Prepare("DELETE FROM domains WHERE host = ? AND user_id = ?")
	if err != nil {
		http.Error(w, err.Error()+" (while setting up db query)", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(host, u.Id)
	if err != nil {
		http.Error(w, "Error while trying to delete domain— "+err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO flash
	http.Redirect(w, r, "/", http.StatusSeeOther)
})

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

	now := time.Now()
	start := now.AddDate(0, 0, -30)
	traffic, daily_traffic, _ := host_traffic_summary(host, start, now)
	paths_traffic, _ := paths_summary(host, start, now)

	err = t.ExecuteTemplate(w, "domain_detail.tmpl", map[string]interface{}{
		"User":         u,
		"Host":         host,
		"Key":          key,
		"Traffic":      traffic,
		"DailyTraffic": daily_traffic,
		"PathsTraffic": paths_traffic,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
})

var path_detail = require_user(func(w http.ResponseWriter, r *http.Request, u User) {
	host := mux.Vars(r)["host"]
	path := "/" + mux.Vars(r)["path"]
	err := t.ExecuteTemplate(w, "path_detail.tmpl", map[string]interface{}{
		"User": u,
		"Host": host,
		"Path": path,
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

func estimate_visitors(pageviews int64, dnt_pageviews int64, visitors int64) int64 {
	var dnt_visitors int64
	if dnt_pageviews > 0 {
		if pageviews > 0 {
			dnt_rate := float64(dnt_pageviews) / float64(dnt_pageviews+pageviews)
			dnt_visitors = int64(math.Round(float64(visitors) * dnt_rate))
		} else {
			dnt_visitors = 1
		}
	}
	return visitors + dnt_visitors
}

type Traffic struct {
	Visitors  int64
	Pageviews int64
}

type GraphData struct {
	H, W int64
	Data Data
}

type Domain struct {
	Host         string
	Key          string
	Traffic      Traffic
	DailyTraffic []Traffic
	GraphData    GraphData
}

type PathTraffic struct {
	Path    string
	Traffic Traffic
}

func paths_summary(host string, start time.Time, end time.Time) ([]PathTraffic, error) {
	start = start.AddDate(0, 0, 1)
	end = end.AddDate(0, 0, 1)
	summary := make(map[string]Traffic)
	path_hll_keys := make(map[string][]string)
	path_abs_keys := make(map[string][]string)
	for t := start; t.Before(end); t = t.AddDate(0, 0, 1) {
		date_key := t.Format(DATE_FORMAT)

		hll_keys, _ := rdb.Keys(fmt.Sprintf("counts:hll:%s:%s:*", host, date_key)).Result()
		for _, key := range hll_keys {
			path := strings.SplitN(key, ":", 5)[4]
			path_hll_keys[path] = append(path_hll_keys[path], key)
		}

		abs_keys, _ := rdb.Keys(fmt.Sprintf("counts:abs:%s:%s:*", host, date_key)).Result()
		for _, key := range abs_keys {
			path := strings.SplitN(key, ":", 5)[4]
			path_abs_keys[path] = append(path_abs_keys[path], key)
		}
	}

	for path, keys := range path_hll_keys {
		count, _ := rdb.PFCount(keys...).Result()
		summary[path] = Traffic{
			Visitors: count,
		}
	}

	for path, keys := range path_abs_keys {
		counts, _ := rdb.MGet(keys...).Result()
		var pageviews int64
		for _, count := range counts {
			n, _ := strconv.ParseInt(count.(string), 10, 64)
			pageviews += n
		}
		summary[path] = Traffic{
			Visitors:  summary[path].Visitors,
			Pageviews: pageviews,
		}
	}

	var sorted []PathTraffic
	for k, v := range summary {
		sorted = append(sorted, PathTraffic{Path: k, Traffic: v})
	}
	sort.Slice(sorted, func(a, b int) bool {
		at, bt := sorted[a].Traffic, sorted[b].Traffic
		if at.Visitors == bt.Visitors {
			return bt.Pageviews < at.Pageviews
		}
		return bt.Visitors < at.Visitors
	})

	return sorted, nil
}

func host_traffic_summary(host string, start time.Time, end time.Time) (Traffic, []Traffic, error) {
	start = start.AddDate(0, 0, 1)
	end = end.AddDate(0, 0, 1)
	var (
		daily_traffic         []Traffic
		monthly_pageviews     int64
		monthly_dnt_pageviews int64
		monthly_hll_keys      []string
	)
	for t := start; t.Before(end); t = t.AddDate(0, 0, 1) {
		date_key := t.Format(DATE_FORMAT)

		var visitors int64
		hll_keys, err := rdb.Keys(fmt.Sprintf("counts:hll:%s:%s:*", host, date_key)).Result()
		if err == nil && len(hll_keys) > 0 {
			visitors += rdb.PFCount(hll_keys...).Val()
		}

		var pageviews int64
		abs_keys, err := rdb.Keys(fmt.Sprintf("counts:abs:%s:%s:*", host, date_key)).Result()
		if err == nil && len(abs_keys) > 0 {
			counters := rdb.MGet(abs_keys...).Val()
			if err == nil {
				for _, counter := range counters {
					n, err := strconv.ParseInt(counter.(string), 10, 64)
					if err == nil {
						pageviews += n
					}
				}
			}
		}

		var dnt_pageviews int64
		v, err := rdb.Get(fmt.Sprintf("counts:abs:%s:%s", host, date_key)).Result()
		if err == nil {
			n, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				dnt_pageviews += n
			}
		}

		monthly_hll_keys = append(monthly_hll_keys, hll_keys...)
		monthly_pageviews += pageviews
		monthly_dnt_pageviews += dnt_pageviews
		daily_traffic = append(daily_traffic, Traffic{
			Pageviews: pageviews + dnt_pageviews,
			Visitors:  estimate_visitors(pageviews, dnt_pageviews, visitors),
		})
	}

	monthly_visitors, _ := rdb.PFCount(monthly_hll_keys...).Result()

	traffic := Traffic{
		Visitors:  estimate_visitors(monthly_pageviews, monthly_dnt_pageviews, monthly_visitors),
		Pageviews: monthly_pageviews + monthly_dnt_pageviews,
	}
	return traffic, daily_traffic, nil
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
		for rows.Next() {
			var host string
			var key string
			err = rows.Scan(&host, &key)
			if err != nil {
				http.Error(w, err.Error()+" (while getting domains)", http.StatusInternalServerError)
				return
			}
			now := time.Now()
			start := now.AddDate(0, 0, -30)
			traffic, daily_traffic, _ := host_traffic_summary(host, start, now)

			var data Data
			for i, t := range daily_traffic {
				x := float64(i)
				y := float64(t.Pageviews)
				data = append(data, struct{ X, Y float64 }{
					X: x,
					Y: y,
				})
			}

			domains = append(domains, Domain{
				Host:         host,
				Key:          key,
				Traffic:      traffic,
				DailyTraffic: daily_traffic,
				GraphData: GraphData{
					H:    32,
					W:    128,
					Data: data,
				},
			})
		}
	}
	err := t.ExecuteTemplate(w, "home.tmpl", map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
		"User":           user,
		"Domains":        domains,
	})
	if err != nil {
		fmt.Println("err", err.Error())
		http.Error(w, err.Error(), http.StatusNotFound)
	}
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

type Data []struct {
	X, Y float64
}

func (data Data) Scale(w, h int64, yzero bool) Data {
	PADDING := int64(2)
	xmin := math.Inf(1)
	xmax := math.Inf(-1)
	ymin := math.Inf(1)
	ymax := math.Inf(-1)
	for _, d := range data {
		if d.X < xmin {
			xmin = d.X
		}
		if d.X > xmax {
			xmax = d.X
		}
		if d.Y < ymin {
			ymin = d.Y
		}
		if d.Y > ymax {
			ymax = d.Y
		}
	}
	var out Data
	for _, d := range data {
		var y float64
		if yzero {
			y = d.Y * float64(h-PADDING*2) / ymax
		} else {
			y = (d.Y - ymin) * float64(h-PADDING*2) / (ymax - ymin)
		}
		out = append(out, struct{ X, Y float64 }{
			X: (d.X-xmin)*float64(w-PADDING*2)/(xmax-xmin) + float64(PADDING),
			Y: y + float64(PADDING),
		})
	}
	return out
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
	var err error
	DEVMODE := os.Getenv("DEV") != ""

	if DEVMODE {
		for i, c := range []byte("super secret") {
			key[i] = c
			csrf_key[i] = c
		}
	} else {
		ENV_KEY := os.Getenv("KEY")
		ENV_CSRF_KEY := os.Getenv("CSRF_KEY")
		for i := 0; i < len(key); i++ {
			key[i] = ENV_KEY[i]
			csrf_key[i] = ENV_CSRF_KEY[i]
		}
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
	r.HandleFunc("/domains/delete", delete_domain)
	r.HandleFunc("/domains/{host}", domain_detail)
	r.HandleFunc("/domains/{host}/{path:.*}", path_detail)
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
