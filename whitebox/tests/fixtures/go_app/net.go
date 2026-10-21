package main

import "net/http"

func fetch(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	http.Get(url) // VULN ssrf
}

func goNext(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), 302) // VULN open_redirect
}

func netRoutes() {
	http.HandleFunc("/fetch", fetch)
	http.HandleFunc("/next", goNext)
}
