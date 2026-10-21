// Intentionally vulnerable Go fixture for the taint-engine tests (net/http).
package main

import (
	"database/sql"
	"net/http"
	"os/exec"
	"strconv"
)

var db *sql.DB

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	db.Query("SELECT * FROM users WHERE name = '" + q + "'") // VULN sqli
}

func run(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	exec.Command("sh", "-c", "ping -c 1 "+host) // VULN command_injection
}

func countSafe(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n")) // SAFE: coerced to int
	db.Query("SELECT * FROM t LIMIT " + strconv.Itoa(n))
}

func main() {
	http.HandleFunc("/search", search)
	http.HandleFunc("/run", run)
	http.HandleFunc("/count", countSafe)
	http.ListenAndServe(":8080", nil)
}
