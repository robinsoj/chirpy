package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/robinsoj/chirpy/internal/auth"
	"github.com/robinsoj/chirpy/internal/database"
)

func handleReadiness(respWrite http.ResponseWriter, req *http.Request) {
	respWrite.Header().Set("Content-Type", "text/plain; charset=utf-8")
	respWrite.WriteHeader(http.StatusOK)
	respWrite.Write([]byte(http.StatusText(http.StatusOK)))
}

func (cfg *apiConfig) handleMetrics(respWrite http.ResponseWriter, _ *http.Request) {
	respWrite.Header().Set("Content-Type", "text/html; charset=utf-8")
	respWrite.WriteHeader(http.StatusOK)
	hits := cfg.fileserverHits.Load()
	return_msg := fmt.Sprintf("<html>\n\t<body>\n\t\t<h1>Welcome, Chirpy Admin</h1>\n\t\t<p>Chirpy has been visited %d times!</p>\n\t</body>\n</html>", hits)
	respWrite.Write([]byte(return_msg))
}

func (cfg *apiConfig) handleReset(respWrite http.ResponseWriter, req *http.Request) {
	cfg.fileserverHits.Store(0)
	if cfg.platform == "dev" {
		cfg.db.DeleteUsers(req.Context())
	} else {
		respondWithError(respWrite, http.StatusForbidden, "This action is forbidden in this environment")
		return
	}
	respWrite.Header().Set("Content-Type", "text/plain; charset=utf-8")
	respWrite.WriteHeader(http.StatusOK)
	respWrite.Write([]byte("Metrics reset"))
}

func (cfg *apiConfig) handleChirp(respWrite http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "couldn't validate JWT")
		return
	}

	respWrite.Header().Set("Content-Type", "application/json; charset=utf-8")
	var chirp ChirpPost
	if err := json.NewDecoder(req.Body).Decode(&chirp); err != nil {
		respondWithError(respWrite, http.StatusInternalServerError, "Something went wrong with the chirp decoding")
		return
	}
	if len(chirp.Body) > 140 {
		respondWithError(respWrite, http.StatusBadRequest, "Chirp is too long")
		return
	}

	var chirpParams database.CreateChirpParams
	chirpParams.Body = cleanChirp(chirp.Body)
	chirpParams.UserID = userID
	chirpStruct, err := cfg.db.CreateChirp(req.Context(), chirpParams)
	if err != nil {
		respondWithError(respWrite, http.StatusInternalServerError, "Something went wrong creating the chirp")
		return
	}

	outChirp := NewChirpResponse{
		ID:        chirpStruct.ID,
		CreatedAt: chirpStruct.CreatedAt,
		UpdatedAt: chirpStruct.UpdatedAt,
		Body:      chirp.Body,
		UserID:    userID,
	}
	respondWithJSON(respWrite, http.StatusCreated, outChirp)
}

func (cfg *apiConfig) handleUserCreate(respWrite http.ResponseWriter, req *http.Request) {
	var newUser NewUser
	if err := json.NewDecoder(req.Body).Decode(&newUser); err != nil {
		respondWithError(respWrite, http.StatusBadRequest, "Unable to parse user json")
		return
	}
	var userParams database.CreateUserParams
	userParams.Email = newUser.Email
	hashPass, err := auth.HashPassword(newUser.Password)
	if err != nil {
		respondWithError(respWrite, http.StatusBadRequest, "could not hash the given password")
	}
	userParams.HashedPassword = hashPass
	user, err := cfg.db.CreateUser(req.Context(), userParams)
	if err != nil {
		respondWithError(respWrite, http.StatusBadRequest, "unable to create a new database user")
		return
	}
	outUser := NewUserResponse{
		ID:             user.ID,
		CreatedAt:      user.CreatedAt,
		UpdatedAt:      user.UpdatedAt,
		Email:          user.Email,
		HashedPassword: user.HashedPassword,
		IsChirpyRed:    user.IsChirpyRed,
	}
	respondWithJSON(respWrite, http.StatusCreated, outUser)
}

func (cfg *apiConfig) handleGetChirps(respWrite http.ResponseWriter, req *http.Request) {
	authorID := req.URL.Query().Get("author_id")
	sortDir := req.URL.Query().Get("sort")

	var chirps []database.Chirp
	var err error

	if sortDir == "" || (sortDir != "asc" && sortDir != "desc") {
		sortDir = "asc"
	}

	if authorID == "" {
		if sortDir == "asc" {
			chirps, err = cfg.db.GetChirpsAsc(req.Context())
		} else {
			chirps, err = cfg.db.GetChirpsDesc(req.Context())
		}
		if err != nil {
			fmt.Println(err)
			respondWithError(respWrite, http.StatusInternalServerError, "error retrieving chirps from the database")
			return
		}
	} else {
		authorUUID, err := uuid.Parse(authorID)
		if err != nil {
			respondWithError(respWrite, http.StatusInternalServerError, "Invalid UUID passed")
		}
		if sortDir == "asc" {
			chirps, err = cfg.db.GetChirpsByAuthorAsc(req.Context(), authorUUID)
		} else {
			chirps, err = cfg.db.GetChirpsByAuthorDesc(req.Context(), authorUUID)
		}
		if err != nil {
			respondWithError(respWrite, http.StatusInternalServerError, "error retrieving chirps from the database")
			return
		}
	}
	var outChirp []NewChirpResponse
	for _, chirp := range chirps {
		holdChirp := NewChirpResponse{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
		outChirp = append(outChirp, holdChirp)
	}
	respondWithJSON(respWrite, http.StatusOK, outChirp)
}

func (cfg *apiConfig) handleSingleChirps(respWrite http.ResponseWriter, req *http.Request) {
	uuidStr := req.PathValue("chirpID")
	chirpID, err := uuid.Parse(uuidStr)
	if err != nil {
		respondWithError(respWrite, http.StatusNotFound, "chirp not found")
		return
	}
	chirp, err := cfg.db.GetSingleChirp(req.Context(), chirpID)
	if err != nil {
		respondWithError(respWrite, http.StatusNotFound, "error retrieving chirps from the database")
		return
	}
	outChirp := NewChirpResponse{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}
	respondWithJSON(respWrite, http.StatusOK, outChirp)
}

func (cfg *apiConfig) handleLogin(respWrite http.ResponseWriter, req *http.Request) {
	var newUser NewUser
	if err := json.NewDecoder(req.Body).Decode(&newUser); err != nil {
		respondWithError(respWrite, http.StatusBadRequest, "unable to parse user json")
		return
	}
	user, err := cfg.db.GetUserPassword(req.Context(), newUser.Email)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "incorrect email or password")
		return
	}
	err = auth.CheckPasswordHash(newUser.Password, user.HashedPassword)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "incorrect email or password")
		return
	}
	/*expirationTime := time.Hour
	if newUser.ExpiresIN > 0 && newUser.ExpiresIN < 3600 {
		expirationTime = time.Duration(newUser.ExpiresIN) * time.Second
	}*/

	accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret)
	if err != nil {
		respondWithError(respWrite, http.StatusInternalServerError, "Couldn't create access JWT")
		return
	}
	rt, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(respWrite, http.StatusInternalServerError, "failed to make refresh_token")
		return
	}
	err = cfg.createRefreshToken(req.Context(), rt, user.ID)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't store the refresh_token")
		return
	}

	outUser := NewUserResponse{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        accessToken,
		RefreshToken: rt,
		IsChirpyRed:  user.IsChirpyRed,
	}
	respondWithJSON(respWrite, http.StatusOK, outUser)
}

func (cfg *apiConfig) handleRefresh(respWrite http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}
	rt, err := cfg.db.LookUpRefresh(req.Context(), token)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't find refresh_token")
		return
	}
	mrt, err := auth.MakeJWT(rt.UserID, cfg.jwtSecret)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't validate token")
		return
	}
	err = cfg.createRefreshToken(req.Context(), mrt, rt.UserID)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't store the refresh_token")
		return
	}
	outToken := RefreshTokenResponse{
		Token: mrt,
	}
	respondWithJSON(respWrite, http.StatusOK, outToken)
}

func (cfg *apiConfig) handleRevoke(respWrite http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}
	err = cfg.db.RevokeToken(req.Context(), token)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Could not review the refresh_token")
		return
	}
	respondWithJSON(respWrite, http.StatusNoContent, nil)
}

func (cfg *apiConfig) handleUserUpdate(respWrite http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't validate JWT")
		return
	}
	var userChng UserChange
	if err := json.NewDecoder(req.Body).Decode(&userChng); err != nil {
		respondWithError(respWrite, http.StatusInternalServerError, "malformed json encountered")
		return
	}
	hashed_password, err := auth.HashPassword(userChng.Password)
	if err != nil {
		respondWithError(respWrite, http.StatusInternalServerError, "failed to hash the new password")
		return
	}
	passwUpdateParams := database.UpdateUserPasswordParams{
		HashedPassword: hashed_password,
		Email:          userChng.Email,
		ID:             userID,
	}
	user, err := cfg.db.UpdateUserPassword(req.Context(), passwUpdateParams)
	if err != nil {
		respondWithError(respWrite, http.StatusInternalServerError, "failed to update user password")
		return
	}
	outUser := NewUserResponse{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}
	respondWithJSON(respWrite, http.StatusOK, outUser)
}

func (cfg *apiConfig) handleDeleteChirp(respWrite http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't find JWT")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(respWrite, http.StatusForbidden, "User does not own the chirp")
		return
	}
	uuidStr := req.PathValue("chirpID")
	chirpID, err := uuid.Parse(uuidStr)
	if err != nil {
		respondWithError(respWrite, http.StatusNotFound, "chirp not found")
		return
	}
	deleteChirpParam := database.DeleteSingleChirpParams{
		UserID: userID,
		ID:     chirpID,
	}
	deleted_row, err := cfg.db.DeleteSingleChirp(req.Context(), deleteChirpParam)
	if err != nil {
		respondWithError(respWrite, http.StatusForbidden, "Could not delete chirp")
		return
	}
	if deleted_row.ID == uuid.Nil {
		respondWithError(respWrite, http.StatusForbidden, "User does not own the chirp")
		return
	}
	respondWithJSON(respWrite, http.StatusNoContent, "")
}

func (cfg *apiConfig) handlePolkaWebHook(respWrite http.ResponseWriter, req *http.Request) {
	apiKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		respondWithError(respWrite, http.StatusUnauthorized, "Couldn't find API Key")
		return
	}
	if apiKey != cfg.polkaKey {
		respondWithError(respWrite, http.StatusUnauthorized, "Request not authorized")
		return
	}
	var newWebHook PolkaWebHookRequest
	if err := json.NewDecoder(req.Body).Decode(&newWebHook); err != nil {
		respondWithError(respWrite, http.StatusBadRequest, "Unable to parse Polka webhook json")
		return
	}
	if newWebHook.Event != "user.upgraded" {
		respondWithJSON(respWrite, http.StatusNoContent, "")
		return
	}
	user, err := cfg.db.UpgradeToRed(req.Context(), newWebHook.Data.UserID)
	if err != nil {
		respondWithError(respWrite, http.StatusNotFound, "Unable to update red status")
		return
	}
	if user.ID == uuid.Nil {
		respondWithError(respWrite, http.StatusNotFound, "Unable to find this user")
		return
	}
	respondWithError(respWrite, http.StatusNoContent, "")
}
