package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/robinsoj/chirpy/internal/database"
)

var naughtyWords = []string{"KERFUFFLE", "SHARBERT", "FORNAX"}

func main() {
	godotenv.Load("./.env")
	dbUrl := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		fmt.Println("Error encountered: ", err)
		os.Exit(1)
	}
	dbQueries := database.New(db)
	platform := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")
	fmt.Println("Hello World!")
	const filepathRoot = "."
	const port = "8080"
	mux := http.NewServeMux()

	cfg := &apiConfig{}
	cfg.db = dbQueries
	cfg.platform = platform
	cfg.jwtSecret = jwtSecret
	cfg.polkaKey = polkaKey
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))
	mux.Handle("/app/", cfg.middlewareMetricsInc(fileServer))
	mux.HandleFunc("GET /api/healthz", handleReadiness)
	mux.HandleFunc("GET /admin/metrics", cfg.handleMetrics)
	mux.HandleFunc("POST /admin/reset", cfg.handleReset)
	mux.HandleFunc("POST /api/chirps", cfg.handleChirp)
	mux.HandleFunc("POST /api/users", cfg.handleUserCreate)
	mux.HandleFunc("PUT /api/users", cfg.handleUserUpdate)
	mux.HandleFunc("GET /api/chirps", cfg.handleGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.handleSingleChirps)
	mux.HandleFunc("POST /api/login", cfg.handleLogin)
	mux.HandleFunc("POST /api/refresh", cfg.handleRefresh)
	mux.HandleFunc("POST /api/revoke", cfg.handleRevoke)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.handleDeleteChirp)
	mux.HandleFunc("POST /api/polka/webhooks", cfg.handlePolkaWebHook)

	server := http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	server.ListenAndServe()
	os.Exit(0)
}
