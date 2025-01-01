package main

import (
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/robinsoj/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

type ChirpMessage struct {
	Body string `json:"body"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type ValidResponse struct {
	Valid bool `json:"valid"`
}

type CleanedBody struct {
	CleanedBody string `json:"cleaned_body"`
}

type NewUser struct {
	Password string `json:"password"`
	Email    string `json:"email"`
	//ExpiresIN int    `json:"expires_in_seconds"`
}

type NewUserResponse struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"hashed_password"`
	Token          string    `json:"token"`
	RefreshToken   string    `json:"refresh_token"`
	IsChirpyRed    bool      `json:"is_chirpy_red"`
}

type ChirpPost struct {
	Body   string    `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

type NewChirpResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type RefreshTokenResponse struct {
	Token string `json:"token"`
}

type UserChange struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type PolkaWebHookRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID uuid.UUID `json:"user_id"`
	} `json:"data"`
}
