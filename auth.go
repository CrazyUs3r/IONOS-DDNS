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
			ip := getLocalIP()

			titleLine := T.SetupRequired
			tokenLine := fmt.Sprintf("%s: %s", T.SetupTokenLabel, setupToken)
			urlLine := fmt.Sprintf("%s: http://%s:%s/setup", T.SetupOpenURL, ip, cfg.HealthPort)

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
<script>` + jsData + `</script>
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
