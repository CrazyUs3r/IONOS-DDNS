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
	"html"
	"io"
	"net/http"
	"net/url"
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
	legacySessionCookieName = "dyndns_session"
	sessionCookieNameHTTP   = "dyndns_session_http"
	sessionCookieNameHTTPS  = "dyndns_session_https"
	DefaultSessionMaxAge    = 7 * 24 * time.Hour
	sessionCleanupEvery     = 1 * time.Hour
	pbkdf2Iter              = 600_000
	pbkdf2SaltLen           = 16
	pbkdf2KeyLen            = 32
	setupTokenLength        = 32
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
	TOTPSecret   string    `json:"totp_secret,omitempty"`
	TOTPEnabled  bool      `json:"totp_enabled,omitempty"`
}

type Session struct {
	Token     string
	CSRFToken string
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
			Message: phrases().AuthDisabled,
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

			titleLine := phrases().SetupRequired
			tokenLine := fmt.Sprintf("%s: %s", phrases().SetupTokenLabel, setupToken)
			urlLine := fmt.Sprintf("%s: http://%s:%s/setup", phrases().SetupOpenURL, ip, cfg.HealthPort)

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
	maxVal := 0
	for _, v := range values {
		maxVal = max(maxVal, len(v))
	}
	return maxVal
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

func randomHexToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *SessionStore) Create(user *DashboardUser, maxAge time.Duration) *Session {
	token, err := randomHexToken(32)
	if err != nil {
		return nil
	}
	csrfToken, err := randomHexToken(32)
	if err != nil {
		return nil
	}

	now := time.Now()
	sess := &Session{
		Token:     token,
		CSRFToken: csrfToken,
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: now,
		ExpiresAt: now.Add(maxAge),
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

func (s *SessionStore) DeleteByUserID(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, token)
		}
	}
}

func (s *SessionStore) DeleteAll() {
	s.mu.Lock()
	clear(s.sessions)
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

var (
	usersCache   []DashboardUser
	usersCacheMu sync.RWMutex
)

func loadUsers() []DashboardUser {
	usersCacheMu.RLock()
	if usersCache != nil {
		out := make([]DashboardUser, len(usersCache))
		copy(out, usersCache)
		usersCacheMu.RUnlock()
		return out
	}
	usersCacheMu.RUnlock()

	usersCacheMu.Lock()
	defer usersCacheMu.Unlock()

	if usersCache != nil {
		out := make([]DashboardUser, len(usersCache))
		copy(out, usersCache)
		return out
	}

	data, err := os.ReadFile(usersFilePath)
	if err != nil {
		return nil
	}
	users, err := unmarshalUsersWithTOTP(data)
	if err != nil {
		return nil
	}
	usersCache = users
	return append([]DashboardUser(nil), users...)
}

func saveUsers(users []DashboardUser) error {
	data, err := marshalUsersWithTOTP(users)
	if err != nil {
		return err
	}
	tmp := usersFilePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, usersFilePath); err != nil {
		return err
	}
	usersCacheMu.Lock()
	usersCache = nil
	usersCacheMu.Unlock()
	return nil
}

func findUserByUsername(username string) (*DashboardUser, bool) {
	users := loadUsers()
	for i := range users {
		if strings.EqualFold(users[i].Username, username) {
			u := users[i]
			return &u, true
		}
	}
	return nil, false
}

func findUserByID(userID string) (*DashboardUser, bool) {
	users := loadUsers()
	for i := range users {
		if users[i].ID == userID {
			u := users[i]
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

func safeLocalRedirect(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return "/"
	}

	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	decodedPath, err := url.PathUnescape(u.EscapedPath())
	if err != nil || strings.HasPrefix(decodedPath, "//") || strings.Contains(decodedPath, "\\") {
		return "/"
	}
	return u.RequestURI()
}

func requestUsesHTTPS(r *http.Request) bool {
	return r != nil && r.TLS != nil
}

func sessionCookieName(r *http.Request) string {
	if requestUsesHTTPS(r) {
		return sessionCookieNameHTTPS
	}
	return sessionCookieNameHTTP
}

func secureCookieEnabled(r *http.Request) bool {
	if !requestUsesHTTPS(r) {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(os.Getenv("DASHBOARD_COOKIE_SECURE"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, sess *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName(r),
		Value:    sess.Token,
		Path:     "/",
		MaxAge:   int(DefaultSessionMaxAge.Seconds()),
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   secureCookieEnabled(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func expireSessionCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	expireSessionCookie(w, sessionCookieName(r), secureCookieEnabled(r))
	expireSessionCookie(w, legacySessionCookieName, secureCookieEnabled(r))
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func validCSRFRequest(r *http.Request, sess *Session) bool {
	if sess == nil || sess.CSRFToken == "" {
		return false
	}

	provided := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if provided == "" {
		contentType := strings.ToLower(r.Header.Get("Content-Type"))
		if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") || r.ContentLength > 64<<10 {
			return false
		}
		if err := r.ParseForm(); err != nil {
			return false
		}
		provided = strings.TrimSpace(r.PostForm.Get("csrf_token"))
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(sess.CSRFToken)) == 1
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

func sessionFromRequest(r *http.Request) (*Session, bool) {
	for _, name := range []string{sessionCookieName(r), legacySessionCookieName} {
		cookie, err := r.Cookie(name)
		if err != nil {
			continue
		}
		if sess, ok := sessionStore.Get(cookie.Value); ok {
			return sess, true
		}
	}
	return nil, false
}

func isPublicAuthPath(path string) bool {
	switch path {
	case "/health",
		"/favicon.svg",
		"/assets/style.css",
		"/assets/dashboard.js",
		"/assets/i18n.js",
		"/login",
		"/setup",
		"/login/totp":
		return true
	default:
		return false
	}
}

func sessionMatchesUser(sess *Session) bool {
	currentUser, exists := findUserByID(sess.UserID)
	return exists &&
		currentUser.Role == sess.Role &&
		currentUser.Username == sess.Username
}

func rejectUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if isAPIPath(r.URL.Path) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "unauthorized",
		})
		return
	}

	target := safeLocalRedirect(r.URL.RequestURI())
	http.Redirect(
		w,
		r,
		"/login?redirect="+url.QueryEscape(target),
		http.StatusSeeOther,
	)
}

func rejectRevokedSession(w http.ResponseWriter, r *http.Request, sess *Session) {
	sessionStore.Delete(sess.Token)
	clearSessionCookie(w, r)

	if isAPIPath(r.URL.Path) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "session revoked",
		})
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func rejectForbidden(
	w http.ResponseWriter,
	r *http.Request,
	apiError string,
	pageError string,
) {
	if isAPIPath(r.URL.Path) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": apiError,
		})
		return
	}

	http.Error(w, pageError, http.StatusForbidden)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if isPublicAuthPath(path) || !authEnabled {
			next.ServeHTTP(w, r)
			return
		}

		if len(loadUsers()) == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}

		sess, ok := sessionFromRequest(r)
		if !ok {
			rejectUnauthenticated(w, r)
			return
		}

		if !sessionMatchesUser(sess) {
			rejectRevokedSession(w, r, sess)
			return
		}

		if isUnsafeMethod(r.Method) && !validCSRFRequest(r, sess) {
			rejectForbidden(
				w,
				r,
				"invalid csrf token",
				"invalid csrf token",
			)
			return
		}

		if !hasPermission(sess.Role, r.Method, path) {
			rejectForbidden(w, r, "forbidden", "Forbidden")
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
		blocked := []string{"/api/users", "/api/save-config", "/api/backup"}
		for _, b := range blocked {
			if strings.HasPrefix(path, b) {
				return false
			}
		}
		return true

	case RoleViewer:
		if method == MethodGET || path == "/ws" || path == "/metrics" {
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
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !authEnabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	users := loadUsers()
	if len(users) == 0 {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	redirect := safeLocalRedirect(r.URL.Query().Get("redirect"))

	if _, ok := sessionFromRequest(r); ok {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	var errMsg string

	if r.Method == MethodPOST {
		clientIP := getClientIP(r)
		limiter := loginLimiter.GetLimiter(clientIP)
		if !limiter.Allow() {
			w.Header().Set("Retry-After", "60")
			errMsg = "Too many login attempts. Please wait."
			log(LogContext{
				Level:   LogWarn,
				Action:  ActionConfig,
				Message: fmt.Sprintf("🚫 Login rate limit exceeded for IP: %s", clientIP),
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, "%s", buildLoginPage(errMsg, redirect))
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		user, found := findUserByUsername(username)
		if found && checkPassword(password, user.PasswordHash) {
			handleLoginPost2FA(w, r, user, redirect)
			return
		}

		errMsg = phrases().ErrInvalidLogin
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf(phrases().LoginFailedLog, username, getClientIP(r)),
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "%s", buildLoginPage(errMsg, redirect))
}

// ============================================================================
// HANDLER: /logout
// ============================================================================

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if sess, ok := sessionFromRequest(r); ok {
		sessionStore.Delete(sess.Token)
	}
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ============================================================================
// HANDLER: /setup
// ============================================================================

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
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

	if r.Method == MethodPOST {
		token := strings.TrimSpace(r.FormValue("setup_token"))
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		switch {
		case token != setupToken:
			errMsg = phrases().ErrInvalidSetupToken
		case len(username) < 3:
			errMsg = phrases().ErrUsernameTooShort
		case len(password) < 8:
			errMsg = phrases().ErrPasswordTooShort
		case password != password2:
			errMsg = phrases().ErrPasswordsMismatch
		default:
			hash, err := hashPassword(password)
			if err != nil {
				errMsg = phrases().ErrAccountCreate
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
				errMsg = phrases().ErrAccountSave
				break
			}

			setupToken = ""
			log(LogContext{
				Level:   LogInfo,
				Action:  ActionStart,
				Message: fmt.Sprintf(phrases().FirstAdminCreatedLog, username),
			})

			sess := sessionStore.Create(&newUser, DefaultSessionMaxAge)
			if sess == nil {
				errMsg = phrases().ErrAccountCreate
				break
			}
			setSessionCookie(w, r, sess)
			http.Redirect(w, r, "/", http.StatusSeeOther)
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

	case MethodGET:
		users := loadUsers()
		type safeUser struct {
			ID          string    `json:"id"`
			Username    string    `json:"username"`
			Role        UserRole  `json:"role"`
			CreatedAt   time.Time `json:"created_at"`
			LastLogin   time.Time `json:"last_login"`
			TOTPEnabled bool      `json:"totp_enabled"`
		}
		out := make([]safeUser, len(users))
		for i, u := range users {
			out[i] = safeUser{u.ID, u.Username, u.Role, u.CreatedAt, u.LastLogin, u.TOTPEnabled}
		}
		writeJSON(w, http.StatusOK, out)

	case MethodPOST:
		var req struct {
			Username string   `json:"username"`
			Password string   `json:"password"`
			Role     UserRole `json:"role"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": phrases().ErrInvalidJSON})
			return
		}

		req.Username = strings.TrimSpace(req.Username)
		if len(req.Username) < 3 || len(req.Password) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": phrases().ErrUsernamePasswordMin})
			return
		}
		if req.Role != RoleAdmin && req.Role != RoleEditor && req.Role != RoleViewer {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": phrases().ErrInvalidRole})
			return
		}
		if _, exists := findUserByUsername(req.Username); exists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": phrases().ErrUsernameTaken})
			return
		}

		hash, err := hashPassword(req.Password)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": phrases().ErrHash})
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
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": phrases().ErrSave})
			return
		}

		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: fmt.Sprintf(phrases().UserCreatedLog, req.Username, req.Role, sess.Username),
		})
		writeJSON(w, http.StatusOK, map[string]string{"status": phrases().StatusCreated})

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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": phrases().ErrMissingID})
		return
	}

	switch r.Method {
	case MethodPUT:
		handleUpdateUser(w, r, id)
	case MethodDELETE:
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

	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": phrases().ErrInvalidJSON})
		return
	}

	if !updateUserByID(id, req.Role, req.Password) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": phrases().ErrUserNotFound})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": phrases().StatusUpdated})
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

		if err := saveUsers(users); err != nil {
			return false
		}
		sessionStore.DeleteByUserID(id)
		return true
	}

	return false
}

func isValidRole(role UserRole) bool {
	return role == RoleAdmin || role == RoleEditor || role == RoleViewer
}

func requireAdmin(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	if !authEnabled {
		return &Session{Username: t(phrases().AuthDisabledActor, "auth-disabled"), Role: RoleAdmin}, true
	}

	sess, ok := sessionFromRequest(r)
	if !ok || sess.Role != RoleAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": phrases().ErrForbidden})
		return nil, false
	}

	return sess, true
}

func handleDeleteUser(w http.ResponseWriter, id, currentUserID string) {
	if id == currentUserID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": phrases().ErrOwnAccountDelete})
		return
	}

	found, err := removeUserByID(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": phrases().ErrSave})
		return
	}

	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": phrases().ErrUserNotFound})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": phrases().StatusDeleted})
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

	if err := saveUsers(filtered); err != nil {
		return false, err
	}
	sessionStore.DeleteByUserID(id)
	return true, nil
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
	return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + ` · DynDNS</title>
<link rel="stylesheet" href="/assets/style.css">
</head>

<body class="auth-page">

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

` + appFooterHTML() + `

<script src="/assets/i18n.js" defer></script>
<script src="/assets/dashboard.js" defer></script>
</body>
</html>`
}

func buildLoginPage(errMsg, redirect string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="auth-error">⚠️ ` + html.EscapeString(errMsg) + `</div>`
	}

	action := "/login?redirect=" + url.QueryEscape(safeLocalRedirect(redirect))
	body := `
<div class="auth-logo">🌐</div>
<div class="auth-title">` + phrases().DashboardTitle + `</div>
<div class="auth-sub">` + phrases().LoginSubtitle + `</div>
` + errHTML + `
<form method="POST" action="` + html.EscapeString(action) + `">
	<div class="auth-field">
		<label class="auth-label">` + phrases().Username + `</label>
		<input class="auth-input" type="text" name="username" autofocus autocomplete="username" required>
	</div>
	<div class="auth-field">
		<label class="auth-label">` + phrases().Password + `</label>
		<input class="auth-input" type="password" name="password" autocomplete="current-password" required>
	</div>
	<button class="auth-btn" type="submit">🔐 ` + phrases().LoginButton + `</button>
</form>
<div class="auth-hint">` + phrases().LoginHint + `</div>`

	return authPageShell(phrases().LoginTitle, body)
}

func buildSetupPage(errMsg string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="auth-error">⚠️ ` + html.EscapeString(errMsg) + `</div>`
	}

	body := `
<div class="auth-logo">🔐</div>
<div class="auth-title">` + phrases().SetupHeading + `</div>
<div class="auth-sub">` + phrases().SetupSubtitle + `</div>
` + errHTML + `
<form method="POST" action="/setup">
	<div class="auth-field">
		<label class="auth-label">` + phrases().SetupToken + `</label>
		<input class="auth-input" type="text" name="setup_token" autofocus autocomplete="off" required
			style="font-family:monospace;font-size:0.8rem;">
	</div>
	<div class="auth-field">
		<label class="auth-label">` + phrases().Username + `</label>
		<input class="auth-input" type="text" name="username" autocomplete="username" required>
	</div>
	<div class="auth-field">
		<label class="auth-label">` + phrases().Password + ` <small style="opacity:0.5">(` + phrases().PasswordMinHint + `)</small></label>
		<input class="auth-input" type="password" name="password" autocomplete="new-password" required>
	</div>
	<div class="auth-field">
		<label class="auth-label">` + phrases().PasswordConfirm + `</label>
		<input class="auth-input" type="password" name="password2" autocomplete="new-password" required>
	</div>
	<button class="auth-btn" type="submit">✅ ` + phrases().SetupButton + `</button>
</form>
<div class="auth-hint">` + phrases().SetupHint + `</div>`

	return authPageShell(phrases().SetupTitle, body)
}
