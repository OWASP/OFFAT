package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func read(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	os.ReadFile("/data/" + name) // VULN path_traversal
}

func readSafe(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("f")) // SAFE: filepath.Base
	os.ReadFile("/data/" + name)
}

func fileRoutes() {
	http.HandleFunc("/read", read)
	http.HandleFunc("/read-safe", readSafe)
}
