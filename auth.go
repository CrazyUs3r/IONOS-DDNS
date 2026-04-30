// Package main
package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// CONSTANTS & TYPES
// ============================================================================

const (
	SessionCookieName    = "dyndns_session"
	DefaultSessionMaxAge = 7 * 24 * time.Hour
	sessionCleanupEvery  = 1 * time.Hour
	pbkdf2Iter           = 600_000
	pbkdf2SaltLen        = 16
	pbkdf2KeyLen         = 32
	setupTokenLength     = 32
)

type UserRole string

const (
	RoleAdmin  UserRole = "admin"
	RoleEditor UserRole = "editor"
	RoleViewer UserRole = "viewer"
)

type DashboardUser struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         UserRole  `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

type Session struct {
	Token     string
	UserID    string
	Username  string
	Role      UserRole
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ============================================================================
// GLOBALS
// ============================================================================

var (
	sessionStore   = &SessionStore{sessions: make(map[string]*Session)}
	setupToken     string
	setupTokenOnce sync.Once
	usersFilePath  string
	authEnabled    = true
)

func initAuth(logsDir string) {
	usersFilePath = filepath.Join(filepath.Dir(logsDir), "users.json")

	if v := strings.ToLower(strings.TrimSpace(os.Getenv("DASHBOARD_AUTH"))); v == "false" {
		authEnabled = false
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: T.AuthDisabled,
		})
		return
	}

	users := loadUsers()
	if len(users) == 0 {
		setupTokenOnce.Do(func() {
			b := make([]byte, setupTokenLength)
			_, _ = rand.Read(b)
			setupToken = hex.EncodeToString(b)

			titleLine := T.SetupRequired
			tokenLine := fmt.Sprintf("%s: %s", T.SetupTokenLabel, setupToken)
			urlLine := fmt.Sprintf("%s: http://%s:%s/setup", T.SetupOpenURL, "host", cfg.HealthPort)

			width := maxLen(titleLine, tokenLine, urlLine)

			logBoxBorder := func(left, mid, right string) {
				log(LogContext{
					Level:      LogInfo,
					Action:     ActionStart,
					SkipNotify: true,
					Message:    left + strings.Repeat(mid, width+4) + right,
				})
			}

			logBoxLine := func(text string) {
				log(LogContext{
					Level:      LogInfo,
					Action:     ActionStart,
					SkipNotify: true,
					Message:    fmt.Sprintf("║  %-*s  ║", width, text),
				})
			}

			logBoxBorder("╔", "═", "╗")
			logBoxLine(titleLine)
			logBoxLine(tokenLine)
			logBoxLine(urlLine)
			logBoxBorder("╚", "═", "╝")
		})
	}

	go sessionStore.cleanupLoop()
}

func maxLen(values ...string) int {
	max := 0
	for _, v := range values {
		if len(v) > max {
			max = len(v)
		}
	}
	return max
}

// ============================================================================
// SESSION STORE
// ============================================================================

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

const (
	pathAPI     = "/api/"
	pathWS      = "/ws"
	pathMetrics = "/metrics"
)

var exactPaths = map[string]struct{}{
	pathWS:      {},
	pathMetrics: {},
}

func (s *SessionStore) Create(user *DashboardUser, maxAge time.Duration) *Session {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	sess := &Session{
		Token:     token,
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(maxAge),
	}

	s.mu.Lock()
	s.sessions[token] = sess
	s.mu.Unlock()

	return sess
}

func (s *SessionStore) Get(token string) (*Session, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[token]
	s.mu.RUnlock()

	if !ok || time.Now().After(sess.ExpiresAt) {
		if ok {
			s.Delete(token)
		}
		return nil, false
	}
	return sess, true
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(sessionCleanupEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			for token, sess := range s.sessions {
				if time.Now().After(sess.ExpiresAt) {
					delete(s.sessions, token)
				}
			}
			s.mu.Unlock()
		case <-shutdownCtx.Done():
			return
		}
	}
}

// ============================================================================
// USER PERSISTENCE
// ============================================================================

func loadUsers() []DashboardUser {
	data, err := os.ReadFile(usersFilePath)
	if err != nil {
		return nil
	}
	var users []DashboardUser
	if err := json.Unmarshal(data, &users); err != nil {
		return nil
	}
	return users
}

func saveUsers(users []DashboardUser) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	tmp := usersFilePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, usersFilePath)
}

func findUserByUsername(username string) (*DashboardUser, bool) {
	users := loadUsers()
	for _, u := range users {
		if strings.EqualFold(u.Username, username) {
			return &u, true
		}
	}
	return nil, false
}

func generateUserID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

func sessionFromRequest(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, false
	}
	return sessionStore.Get(cookie.Value)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if path == "/health" || path == "/favicon.svg" ||
			path == "/login" || path == "/logout" || path == "/setup" {
			next.ServeHTTP(w, r)
			return
		}

		users := loadUsers()

		if len(users) == 0 {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}

		sess, ok := sessionFromRequest(r)
		if !ok {
			if isAPIPath(path) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			http.Redirect(w, r, "/login?redirect="+r.URL.Path, http.StatusFound)
			return
		}

		if !hasPermission(sess.Role, r.Method, path) {
			if isAPIPath(path) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func isAPIPath(path string) bool {
	if strings.HasPrefix(path, pathAPI) {
		return true
	}
	_, ok := exactPaths[path]
	return ok
}

func hasPermission(role UserRole, method, path string) bool {
	switch role {
	case RoleAdmin:
		return true

	case RoleEditor:
		blocked := []string{"/api/users", "/api/save-config"}
		for _, b := range blocked {
			if strings.HasPrefix(path, b) {
				return false
			}
		}
		return true

	case RoleViewer:
		if method == http.MethodGet || path == "/ws" || path == "/metrics" {
			return true
		}
		return false

	default:
		return false
	}
}

// ============================================================================
// HANDLER: /login
// ============================================================================

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !authEnabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	users := loadUsers()
	if len(users) == 0 {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}

	if sess, ok := sessionFromRequest(r); ok {
		_ = sess
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	var errMsg string

	if r.Method == http.MethodPost {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		user, found := findUserByUsername(username)
		if found && checkPassword(password, user.PasswordHash) {
			maxAge := DefaultSessionMaxAge
			sess := sessionStore.Create(user, maxAge)

			http.SetCookie(w, &http.Cookie{
				Name:     SessionCookieName,
				Value:    sess.Token,
				Path:     "/",
				MaxAge:   int(maxAge.Seconds()),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})

			allUsers := loadUsers()
			for i, u := range allUsers {
				if u.ID == user.ID {
					allUsers[i].LastLogin = time.Now()
					break
				}
			}
			_ = saveUsers(allUsers)

			log(LogContext{
				Level:   LogInfo,
				Action:  ActionConfig,
				Message: fmt.Sprintf(T.LoginSuccessLog, username, user.Role, getClientIP(r)),
			})

			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}

		errMsg = T.ErrInvalidLogin
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(T.LoginFailedLog, username, getClientIP(r)),
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "%s", buildLoginPage(errMsg, redirect))
}

// ============================================================================
// HANDLER: /logout
// ============================================================================

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookieName)
	if err == nil {
		sessionStore.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ============================================================================
// HANDLER: /setup
// ============================================================================

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if !authEnabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	users := loadUsers()
	if len(users) > 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var errMsg string

	if r.Method == http.MethodPost {
		token := strings.TrimSpace(r.FormValue("setup_token"))
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		switch {
		case token != setupToken:
			errMsg = T.ErrInvalidSetupToken
		case len(username) < 3:
			errMsg = T.ErrUsernameTooShort
		case len(password) < 8:
			errMsg = T.ErrPasswordTooShort
		case password != password2:
			errMsg = T.ErrPasswordsMismatch
		default:
			hash, err := hashPassword(password)
			if err != nil {
				errMsg = T.ErrAccountCreate
				break
			}

			newUser := DashboardUser{
				ID:           generateUserID(),
				Username:     username,
				PasswordHash: hash,
				Role:         RoleAdmin,
				CreatedAt:    time.Now(),
			}

			if err := saveUsers([]DashboardUser{newUser}); err != nil {
				errMsg = T.ErrAccountSave
				break
			}

			setupToken = ""
			log(LogContext{
				Level:   LogInfo,
				Action:  ActionStart,
				Message: fmt.Sprintf(T.FirstAdminCreatedLog, username),
			})

			sess := sessionStore.Create(&newUser, DefaultSessionMaxAge)
			http.SetCookie(w, &http.Cookie{
				Name:     SessionCookieName,
				Value:    sess.Token,
				Path:     "/",
				MaxAge:   int(DefaultSessionMaxAge.Seconds()),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "%s", buildSetupPage(errMsg))
}

// ============================================================================
// HANDLER: /api/users  (nur Admin)
// ============================================================================

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireAdmin(w, r)
	if !ok {
		return
	}

	switch r.Method {

	case http.MethodGet:
		users := loadUsers()
		type safeUser struct {
			ID        string    `json:"id"`
			Username  string    `json:"username"`
			Role      UserRole  `json:"role"`
			CreatedAt time.Time `json:"created_at"`
			LastLogin time.Time `json:"last_login"`
		}
		out := make([]safeUser, len(users))
		for i, u := range users {
			out[i] = safeUser{u.ID, u.Username, u.Role, u.CreatedAt, u.LastLogin}
		}
		writeJSON(w, http.StatusOK, out)

	case http.MethodPost:
		var req struct {
			Username string   `json:"username"`
			Password string   `json:"password"`
			Role     UserRole `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.ErrInvalidJSON})
			return
		}

		req.Username = strings.TrimSpace(req.Username)
		if len(req.Username) < 3 || len(req.Password) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.ErrUsernamePasswordMin})
			return
		}
		if req.Role != RoleAdmin && req.Role != RoleEditor && req.Role != RoleViewer {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.ErrInvalidRole})
			return
		}
		if _, exists := findUserByUsername(req.Username); exists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": T.ErrUsernameTaken})
			return
		}

		hash, err := hashPassword(req.Password)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": T.ErrHash})
			return
		}

		users := loadUsers()
		users = append(users, DashboardUser{
			ID:           generateUserID(),
			Username:     req.Username,
			PasswordHash: hash,
			Role:         req.Role,
			CreatedAt:    time.Now(),
		})

		if err := saveUsers(users); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": T.ErrSave})
			return
		}

		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: fmt.Sprintf(T.UserCreatedLog, req.Username, req.Role, sess.Username),
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": T.StatusCreated})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAPIUsersID(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireAdmin(w, r)
	if !ok {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.ErrMissingID})
		return
	}

	switch r.Method {
	case http.MethodPut:
		handleUpdateUser(w, r, id)
	case http.MethodDelete:
		handleDeleteUser(w, id, sess.UserID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleUpdateUser(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Role     UserRole `json:"role"`
		Password string   `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.ErrInvalidJSON})
		return
	}

	if !updateUserByID(id, req.Role, req.Password) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": T.ErrUserNotFound})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": T.StatusUpdated})
}

func updateUserByID(id string, role UserRole, password string) bool {
	users := loadUsers()

	for i := range users {
		if users[i].ID != id {
			continue
		}

		if isValidRole(role) {
			users[i].Role = role
		}

		if len(password) >= 8 {
			if hash, err := hashPassword(password); err == nil {
				users[i].PasswordHash = hash
			}
		}

		return saveUsers(users) == nil
	}

	return false
}

func isValidRole(role UserRole) bool {
	return role == RoleAdmin || role == RoleEditor || role == RoleViewer
}

func requireAdmin(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	if !authEnabled {
		return nil, true
	}

	sess, ok := sessionFromRequest(r)
	if !ok || sess.Role != RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": T.ErrForbidden})
		return nil, false
	}

	return sess, true
}

func handleDeleteUser(w http.ResponseWriter, id, currentUserID string) {
	if id == currentUserID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": T.ErrOwnAccountDelete})
		return
	}

	found, err := removeUserByID(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": T.ErrSave})
		return
	}

	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": T.ErrUserNotFound})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": T.StatusDeleted})
}

func removeUserByID(id string) (bool, error) {
	users := loadUsers()
	filtered := users[:0]

	for _, u := range users {
		if u.ID == id {
			continue
		}

		filtered = append(filtered, u)
	}

	if len(filtered) == len(users) {
		return false, nil
	}

	return true, saveUsers(filtered)
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iter, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"pbkdf2-sha256$%d$%s$%s",
		pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func checkPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}

	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(got, want) == 1
}

// ============================================================================
// HTML PAGES
// ============================================================================

func authPageShell(title, body string) string {
	return `<!DOCTYPE html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + title + ` · DynDNS</title>
<style>
` + cssData + `

body {
	margin: 0;
	overflow: hidden;
}

.auth-bg {
	position: fixed;
	inset: 0;
	z-index: 0;
	overflow: hidden;
	background:
		radial-gradient(circle at 50% 42%, var(--sun-glow), transparent 26%),
		linear-gradient(180deg, var(--sky-1) 0%, var(--sky-2) 48%, var(--floor) 100%);
}

.auth-sun {
	position: absolute;
	left: var(--sun-x);
	top: var(--sun-y);
	z-index: 0;
	width: 24vmin;
	height: 24vmin;
	transform: translate(-50%, -50%);
	border-radius: 50%;
	box-shadow:
		0 0 28px var(--sun-core),
		0 0 70px var(--sun-glow);
	opacity: 0.95;
}

.auth-sun.is-sun {
	background:
		repeating-linear-gradient(
			to bottom,
			var(--sun-core) 0 10px,
			transparent 10px 18px
		);
}

.auth-sun.is-moon {
	background:
		radial-gradient(circle at 38% 34%, rgba(255,255,255,0.95), rgba(226,232,240,0.88) 58%, rgba(148,163,184,0.75));
}

.auth-sun.is-moon::after {
	content: "";
	position: absolute;
	inset: 0;
	border-radius: 50%;
	background: var(--sky-1);
	transform: translateX(28%);
	box-shadow: -12px 0 24px rgba(0,0,0,0.08);
}

.auth-mountains {
	position: absolute;
	z-index: 1;
	left: -5%;
	right: -5%;
	bottom: 40%;
	height: 26%;
	background: linear-gradient(to top, var(--mountain-dark), var(--mountain));
	clip-path: polygon(
		0% 100%, 0% 72%, 7% 78%, 14% 48%, 22% 70%,
		30% 34%, 39% 76%, 48% 52%, 56% 80%,
		66% 36%, 75% 72%, 84% 44%, 93% 76%,
		100% 58%, 100% 100%
	);
	filter: drop-shadow(0 -1px 0 var(--horizon));
	opacity: 0.95;
}

.auth-mountains::before {
	content: "";
	position: absolute;
	inset: 10% 0 0 0;
	background: var(--mountain);
	clip-path: polygon(
		0% 100%, 0% 64%, 9% 46%, 18% 72%, 29% 42%,
		42% 76%, 53% 50%, 63% 78%, 73% 40%,
		86% 74%, 100% 48%, 100% 100%
	);
	opacity: 0.45;
}

.auth-grid-floor {
	position: absolute;
	z-index: 2;
	left: -50%;
	right: -50%;
	bottom: -38%;
	height: 78%;
	background-image:
		linear-gradient(var(--grid-color) 1px, transparent 1px),
		linear-gradient(90deg, var(--grid-color) 1px, transparent 1px);
	background-size: 70px 70px;
	transform: perspective(520px) rotateX(64deg);
	transform-origin: center top;
	box-shadow: inset 0 18px 45px var(--horizon);
	animation: gridMove 4s linear infinite;
	opacity: 0.7;
}

.auth-bg::after {
	content: "";
	position: absolute;
	inset: 0;
	z-index: 3;
	background:
		linear-gradient(to bottom, rgba(0,0,0,0.04), transparent 35%, rgba(0,0,0,0.58)),
		radial-gradient(circle at center, transparent 35%, rgba(0,0,0,0.36));
	pointer-events: none;
}

@keyframes gridMove {
	to {
		background-position: 0 70px, 0 70px;
	}
}

@media (prefers-reduced-motion: reduce) {
	.auth-grid-floor {
		animation: none;
	}
}

.auth-wrap {
	position: relative;
	z-index: 10;
	min-height: 100vh;
	display: flex;
	align-items: center;
	justify-content: center;
	padding: 20px;
}

.auth-card {
	background: color-mix(in srgb, var(--card) 92%, transparent);
	border: 1px solid var(--border);
	border-radius: 16px;
	padding: 36px 32px;
	width: 100%;
	max-width: 400px;
	box-shadow: 0 18px 45px rgba(0,0,0,0.34);
}

.auth-logo {
	text-align: center;
	font-size: 2.5rem;
	margin-bottom: 8px;
}

.auth-title {
	text-align: center;
	font-size: 1.2rem;
	font-weight: 700;
	margin-bottom: 4px;
}

.auth-sub {
	text-align: center;
	font-size: 0.8rem;
	opacity: 0.5;
	margin-bottom: 28px;
}

.auth-field {
	margin-bottom: 16px;
}

.auth-label {
	display: block;
	font-size: 0.8rem;
	font-weight: 600;
	margin-bottom: 6px;
	opacity: 0.8;
}

.auth-input {
	width: 100%;
	padding: 10px 12px;
	background: rgba(255,255,255,0.05);
	border: 1px solid var(--border);
	border-radius: 8px;
	color: var(--text);
	font-size: 0.95rem;
	box-sizing: border-box;
	transition: border-color 0.15s;
}

.auth-input:focus {
	outline: none;
	border-color: var(--btn-border);
	box-shadow: 0 0 0 2px var(--btn-shadow);
}

.auth-btn {
	width: 100%;
	padding: 11px;
	background: var(--btn-bg);
	color: var(--btn-text);
	border: 1px solid var(--btn-border);
	border-radius: 8px;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	margin-top: 8px;
	transition: background 0.2s;
}

.auth-btn:hover {
	background: var(--btn-hover);
}

.auth-error {
	background: rgba(248,113,113,0.12);
	border: 1px solid rgba(248,113,113,0.4);
	color: #f87171;
	border-radius: 8px;
	padding: 10px 14px;
	font-size: 0.85rem;
	margin-bottom: 18px;
}

.auth-hint {
	font-size: 0.75rem;
	opacity: 0.45;
	text-align: center;
	margin-top: 18px;
}
</style>
</head>
<body>

<div class="auth-bg">
	<div class="auth-sun"></div>
	<div class="auth-mountains"></div>
	<div class="auth-grid-floor"></div>
</div>

<div class="auth-wrap">
	<div class="auth-card">
` + body + `
	</div>
</div>

<script>
(function(){
	const t = localStorage.getItem('theme') ||
		(window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');

	document.documentElement.setAttribute('data-theme', t);

	const now = new Date();
	const h = now.getHours();
	const minutes = h * 60 + now.getMinutes();
	const root = document.documentElement;
	const sun = document.querySelector('.auth-sun');

	let vars;

	if (h >= 5 && h < 11) {
		vars = {
			'--sky-1': '#9be7ff',
			'--sky-2': '#5b7cff',
			'--floor': '#172554',
			'--sun-core': 'rgba(255,230,120,0.95)',
			'--sun-glow': 'rgba(255,184,77,0.55)',
			'--grid-color': 'rgba(34,211,238,0.36)',
			'--horizon': 'rgba(56,189,248,0.75)',
			'--mountain': '#172554',
			'--mountain-dark': '#0f172a'
		};
	} else if (h >= 11 && h < 17) {
		vars = {
			'--sky-1': '#60a5fa',
			'--sky-2': '#3730a3',
			'--floor': '#111827',
			'--sun-core': 'rgba(34,211,238,0.95)',
			'--sun-glow': 'rgba(59,130,246,0.65)',
			'--grid-color': 'rgba(125,211,252,0.36)',
			'--horizon': 'rgba(59,130,246,0.8)',
			'--mountain': '#1e1b4b',
			'--mountain-dark': '#020617'
		};
	} else if (h >= 17 && h < 21) {
		vars = {
			'--sky-1': '#312e81',
			'--sky-2': '#db2777',
			'--floor': '#020617',
			'--sun-core': 'rgba(251,191,36,0.98)',
			'--sun-glow': 'rgba(236,72,153,0.7)',
			'--grid-color': 'rgba(244,114,182,0.42)',
			'--horizon': 'rgba(236,72,153,0.9)',
			'--mountain': '#1e1b4b',
			'--mountain-dark': '#020617'
		};
	} else {
		vars = {
			'--sky-1': '#020617',
			'--sky-2': '#1e1b4b',
			'--floor': '#020617',
			'--sun-core': 'rgba(34,211,238,0.98)',
			'--sun-glow': 'rgba(168,85,247,0.75)',
			'--grid-color': 'rgba(34,211,238,0.46)',
			'--horizon': 'rgba(34,211,238,0.95)',
			'--mountain': '#0f172a',
			'--mountain-dark': '#020617'
		};
	}

	for (const k in vars) {
		root.style.setProperty(k, vars[k]);
	}

	const dayStart = 5 * 60;
	const dayEnd = 21 * 60;
	let progress;

	if (minutes >= dayStart && minutes <= dayEnd) {
		progress = (minutes - dayStart) / (dayEnd - dayStart);
		sun.classList.add('is-sun');
		sun.classList.remove('is-moon');
	} else {
		const nightMinutes = minutes < dayStart
			? minutes + (24 * 60 - dayEnd)
			: minutes - dayEnd;

		progress = nightMinutes / ((24 * 60 - dayEnd) + dayStart);
		sun.classList.add('is-moon');
		sun.classList.remove('is-sun');
	}

	const x = 12 + progress * 76;
	const y = 30 - Math.sin(progress * Math.PI) * 24;

	root.style.setProperty('--sun-x', x + '%');
	root.style.setProperty('--sun-y', y + '%');
})();
</script>

</body></html>`
}

func buildLoginPage(errMsg, redirect string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="auth-error">⚠️ ` + errMsg + `</div>`
	}

	body := `
<div class="auth-logo">🌐</div>
<div class="auth-title">` + T.DashboardTitle + `</div>
<div class="auth-sub">` + T.LoginSubtitle + `</div>
` + errHTML + `
<form method="POST" action="/login?redirect=` + redirect + `">
	<div class="auth-field">
		<label class="auth-label">` + T.Username + `</label>
		<input class="auth-input" type="text" name="username" autofocus autocomplete="username" required>
	</div>
	<div class="auth-field">
		<label class="auth-label">` + T.Password + `</label>
		<input class="auth-input" type="password" name="password" autocomplete="current-password" required>
	</div>
	<button class="auth-btn" type="submit">🔐 ` + T.LoginButton + `</button>
</form>
<div class="auth-hint">` + T.LoginHint + `</div>`

	return authPageShell(T.LoginTitle, body)
}

func buildSetupPage(errMsg string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="auth-error">⚠️ ` + errMsg + `</div>`
	}

	body := `
<div class="auth-logo">🔐</div>
<div class="auth-title">` + T.SetupHeading + `</div>
<div class="auth-sub">` + T.SetupSubtitle + `</div>
` + errHTML + `
<form method="POST" action="/setup">
	<div class="auth-field">
		<label class="auth-label">` + T.SetupToken + `</label>
		<input class="auth-input" type="text" name="setup_token" autofocus autocomplete="off" required
			style="font-family:monospace;font-size:0.8rem;">
	</div>
	<div class="auth-field">
		<label class="auth-label">` + T.Username + `</label>
		<input class="auth-input" type="text" name="username" autocomplete="username" required>
	</div>
	<div class="auth-field">
		<label class="auth-label">` + T.Password + ` <small style="opacity:0.5">(` + T.PasswordMinHint + `)</small></label>
		<input class="auth-input" type="password" name="password" autocomplete="new-password" required>
	</div>
	<div class="auth-field">
		<label class="auth-label">` + T.PasswordConfirm + `</label>
		<input class="auth-input" type="password" name="password2" autocomplete="new-password" required>
	</div>
	<button class="auth-btn" type="submit">✅ ` + T.SetupButton + `</button>
</form>
<div class="auth-hint">` + T.SetupHint + `</div>`

	return authPageShell(T.SetupTitle, body)
}
