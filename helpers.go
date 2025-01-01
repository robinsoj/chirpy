package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robinsoj/chirpy/internal/database"
)

func respondWithError(respWrite http.ResponseWriter, code int, msg string) {
	respWrite.WriteHeader(code)
	errResp, _ := json.Marshal(ErrorResponse{Error: msg})
	respWrite.Write([]byte(errResp))
}

func respondWithJSON(respWrite http.ResponseWriter, code int, payload interface{}) {
	respWrite.WriteHeader(code)
	successResp, _ := json.Marshal(payload)
	respWrite.Write(successResp)
}

func cleanChirp(msg string) string {
	chirpWords := strings.Split(msg, " ")
	for i, word := range chirpWords {
		for _, naughtyWord := range naughtyWords {
			if strings.ToUpper(word) == naughtyWord {
				chirpWords[i] = "****"
				break
			}
		}
	}
	return strings.Join(chirpWords, " ")
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) createRefreshToken(ctx context.Context, token string, user_id uuid.UUID) error {
	crtParams := database.StoreRefreshTokenParams{
		Token:  token,
		UserID: user_id,
		ExpiresAt: sql.NullTime{
			Time:  time.Now().UTC().Add(60 * 24 * time.Hour),
			Valid: true,
		},
	}
	err := cfg.db.StoreRefreshToken(ctx, crtParams)
	if err != nil {
		return err
	}
	return nil
}
