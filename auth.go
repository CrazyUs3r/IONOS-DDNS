// Package main

package main

import (
	"bufio"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
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
	pbkdf2SaltLen           = 32
	pbkdf2KeyLen            = 32
	dummyPbkd2Hash          = "pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$iJ2gtxNOzRbKDl2b9Rs/8uLh+TzpRSvl/xFJIkTRrA4"
	setupTokenLength        = 32
	maxAuthRequestBody      = 64 << 10
	auditLogMaxBackups      = 5
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
	CreatedAt time.Time
	ExpiresAt time.Time
	Token     string
	CSRFToken string
	UserID    string
	Username  string
	Role      UserRole
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

func initAuth(logsDir string) error {
	usersFilePath = filepath.Join(filepath.Dir(logsDir), "users.json")

	if v := strings.ToLower(strings.TrimSpace(os.Getenv("DASHBOARD_AUTH"))); v == "false" {
		authEnabled = false
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionConfig,
			Message: phrases().AuthDisabled,
		})

		return nil
	}

	users, err := readUsersFile()
	if err != nil {
		return fmt.Errorf("load dashboard users: %w", err)
	}
	usersCacheMu.Lock()
	usersCache = append([]DashboardUser{}, users...)
	usersCacheMu.Unlock()

	if len(users) == 0 {
		var tokenErr error
		setupTokenOnce.Do(func() {
			setupToken, tokenErr = randomHexToken(setupTokenLength)
			if tokenErr != nil {
				return
			}

			ip := getLocalIP()
			titleLine := phrases().SetupRequired
			tokenLine := fmt.Sprintf("%s: %s", phrases().SetupTokenLabel, setupToken)
			urlLine := fmt.Sprintf("%s: http://%s:%s/setup", phrases().SetupOpenURL, ip, cfg.HealthPort)
			width := maxLen(titleLine, tokenLine, urlLine)

			logBoxBorder := func(left, mid, right string) {
				log(LogContext{
					Level:       LogInfo,
					Action:      ActionStart,
					SkipNotify:  true,
					SkipPersist: true,
					Message:     left + strings.Repeat(mid, width+4) + right,
				})
			}
			logBoxLine := func(text string) {
				log(LogContext{
					Level:       LogInfo,
					Action:      ActionStart,
					SkipNotify:  true,
					SkipPersist: true,
					Message:     fmt.Sprintf("║  %-*s  ║", width, text),
				})
			}

			logBoxBorder("╔", "═", "╗")
			logBoxLine(titleLine)
			logBoxLine(tokenLine)
			logBoxLine(urlLine)
			logBoxBorder("╚", "═", "╝")
		})
		if tokenErr != nil {
			return fmt.Errorf("generate dashboard setup token: %w", tokenErr)
		}
	}

	go sessionStore.cleanupLoop()

	return nil
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
	sessions map[string]*Session
	mu       sync.RWMutex
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
			now := time.Now()
			s.mu.Lock()
			for token, sess := range s.sessions {
				if now.After(sess.ExpiresAt) {
					delete(s.sessions, token)
				}
			}
			s.mu.Unlock()
			cleanupTOTPStores(now)
		case <-shutdownCtx.Done():
			return
		}
	}
}

// ============================================================================
// USER PERSISTENCE
// ============================================================================

var (
	usersCache      []DashboardUser
	usersCacheMu    sync.RWMutex
	usersMutationMu sync.Mutex

	errUserNotFound  = errors.New("user not found")
	errUsernameTaken = errors.New("username already exists")
	errLastAdmin     = errors.New("the last administrator cannot be demoted or deleted")
	errInvalidRole   = errors.New("invalid role")
	errPasswordShort = errors.New("password must be at least 8 characters")
	errNoUserChanges = errors.New("no valid user changes supplied")
	errUsersExist    = errors.New("users already configured")
)

func readUsersFile() ([]DashboardUser, error) {
	data, err := os.ReadFile(usersFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []DashboardUser{}, nil
		}

		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errors.New("users.json is empty")
	}
	users, err := unmarshalUsersWithTOTP(data)
	if err != nil {
		return nil, err
	}
	if users == nil {
		return nil, errors.New("users.json must contain a JSON array")
	}

	return users, nil
}

func loadUsers() []DashboardUser {
	usersCacheMu.RLock()
	cached := usersCache
	usersCacheMu.RUnlock()

	if cached != nil {
		out := make([]DashboardUser, len(cached))
		copy(out, cached)

		return out
	}

	usersCacheMu.Lock()
	defer usersCacheMu.Unlock()

	if usersCache != nil {
		out := make([]DashboardUser, len(usersCache))
		copy(out, usersCache)

		return out
	}

	users, err := readUsersFile()
	if err != nil {
		return nil
	}
	usersCache = users

	return append([]DashboardUser(nil), users...)
}

func saveUsers(users []DashboardUser) error {
	usersMutationMu.Lock()
	defer usersMutationMu.Unlock()

	return saveUsersLocked(users)
}

func saveUsersLocked(users []DashboardUser) error {
	data, err := marshalUsersWithTOTP(users)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(usersFilePath, data); err != nil {
		return err
	}

	usersCacheMu.Lock()
	usersCache = append([]DashboardUser(nil), users...)
	usersCacheMu.Unlock()

	return nil
}

func mutateUsers(fn func([]DashboardUser) ([]DashboardUser, error)) error {
	usersMutationMu.Lock()
	defer usersMutationMu.Unlock()

	users := loadUsers()
	updated, err := fn(users)
	if err != nil {
		return err
	}

	return saveUsersLocked(updated)
}

func countAdmins(users []DashboardUser) int {
	count := 0
	for _, user := range users {
		if user.Role == RoleAdmin {
			count++
		}
	}

	return count
}

func updateUserLastLogin(userID string, when time.Time) error {
	return mutateUsers(func(users []DashboardUser) ([]DashboardUser, error) {
		for i := range users {
			if users[i].ID == userID {
				users[i].LastLogin = when

				return users, nil
			}
		}

		return nil, errUserNotFound
	})
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

func generateUserID() (string, error) {
	return randomHexToken(8)
}

func validDashboardUsername(username string) bool {
	username = strings.TrimSpace(username)
	runeCount := utf8.RuneCountInString(username)
	if runeCount < 3 || runeCount > 64 {
		return false
	}

	return strings.IndexFunc(username, unicode.IsControl) == -1
}

func safeAuthLogValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}

		return r
	}, strings.TrimSpace(value))
	if utf8.RuneCountInString(value) <= 128 {
		return value
	}
	runes := []rune(value)

	return string(runes[:128]) + "…"
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

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func remoteRequestIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}

	host := strings.TrimSpace(r.RemoteAddr)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")

	return net.ParseIP(host)
}

func requestFromTrustedProxy(r *http.Request) bool {
	remoteIP := remoteRequestIP(r)
	if remoteIP == nil {
		return false
	}

	for raw := range strings.SplitSeq(os.Getenv("DASHBOARD_TRUSTED_PROXIES"), ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		if ip := net.ParseIP(strings.Trim(entry, "[]")); ip != nil {
			if ip.Equal(remoteIP) {
				return true
			}

			continue
		}

		_, network, err := net.ParseCIDR(entry)
		if err == nil && network.Contains(remoteIP) {
			return true
		}
	}

	return false
}

func forwardedRequestProto(r *http.Request) string {
	if r == nil || !requestFromTrustedProxy(r) {
		return ""
	}

	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		first, _, _ := strings.Cut(forwarded, ",")
		for part := range strings.SplitSeq(first, ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "proto") {
				return strings.ToLower(strings.Trim(strings.TrimSpace(value), `"`))
			}
		}
	}

	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0]))
	}

	return ""
}

func requestUsesHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil || envBool("DASHBOARD_EXTERNAL_HTTPS") {
		return true
	}

	return forwardedRequestProto(r) == "https"
}

func externalRequestHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if requestFromTrustedProxy(r) {
		if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
			first, _, _ := strings.Cut(forwarded, ",")
			for part := range strings.SplitSeq(first, ";") {
				key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
				if ok && strings.EqualFold(strings.TrimSpace(key), "host") {
					host := strings.Trim(strings.TrimSpace(value), `"`)
					if host != "" {
						return host
					}
				}
			}
		}
		if host := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); host != "" {
			return host
		}
	}

	return r.Host
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
	secure := secureCookieEnabled(r)
	expireSessionCookie(w, sessionCookieNameHTTP, false)
	expireSessionCookie(w, legacySessionCookieName, secure)
	if requestUsesHTTPS(r) {
		expireSessionCookie(w, sessionCookieNameHTTPS, secure)
	}
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func validCSRFRequest(w http.ResponseWriter, r *http.Request, sess *Session) bool {
	if sess == nil || sess.CSRFToken == "" {
		return false
	}

	provided := strings.TrimSpace(r.Header.Get("X-Csrf-Token"))
	if provided == "" {
		contentType := strings.ToLower(r.Header.Get("Content-Type"))
		if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") || r.ContentLength > maxAuthRequestBody {
			return false
		}
		if r.PostForm == nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBody)
		}
		if err := r.ParseForm(); err != nil {
			return false
		}
		provided = strings.TrimSpace(r.PostForm.Get("csrf_token"))
	}

	return subtle.ConstantTimeCompare([]byte(provided), []byte(sess.CSRFToken)) == 1
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}

		return err
	}

	return nil
}

func parseLimitedAuthForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBody)
	if err := r.ParseForm(); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid form data", http.StatusBadRequest)
		}

		return false
	}

	return true
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
		"/health/live",
		"/health/ready",
		"/favicon.svg",
		"/assets/style.css",
		"/assets/dashboard.js",
		"/assets/auth.js",
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

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	return w.ResponseWriter.Write(data)
}

func shouldAuditRequest(method, path string) bool {
	if !isUnsafeMethod(method) {
		return false
	}
	switch path {
	case "/logout", "/settings/2fa", "/api/set-language":
		return true
	default:
		return strings.HasPrefix(path, "/api/")
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if isPublicAuthPath(path) {
			next.ServeHTTP(w, r)

			return
		}
		if !authEnabled {
			if shouldAuditRequest(r.Method, path) {
				recorder := &auditResponseWriter{ResponseWriter: w}
				next.ServeHTTP(recorder, r)
				status := recorder.status
				if status == 0 {
					status = http.StatusOK
				}
				auditHTTPRequest(r, nil, status)

				return
			}
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

		if isUnsafeMethod(r.Method) && !validCSRFRequest(w, r, sess) {
			auditHTTPRequest(r, sess, http.StatusForbidden)
			rejectForbidden(
				w,
				r,
				"invalid csrf token",
				"invalid csrf token",
			)

			return
		}

		if !hasPermission(sess.Role, r.Method, path) {
			auditHTTPRequest(r, sess, http.StatusForbidden)
			rejectForbidden(w, r, "forbidden", "Forbidden")

			return
		}

		if shouldAuditRequest(r.Method, path) {
			recorder := &auditResponseWriter{ResponseWriter: w}
			next.ServeHTTP(recorder, r)
			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}
			auditHTTPRequest(r, sess, status)

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

var sharedReadRoutes = map[string]struct{}{
	"/":                   {},
	"/ws":                 {},
	"/metrics":            {},
	"/metrics/prometheus": {},
	"/api/domains":        {},
	"/api/domains/html":   {},
	"/api/page":           {},
	"/api/config":         {},
	"/api/languages":      {},
	"/api/trigger/status": {},
	"/api/export":         {},
	"/api/logs":           {},
	"/api/diagnose":       {},
	"/api/2fa/status":     {},
	"/settings/2fa":       {},
	"/settings/2fa/qr":    {},
}

var editorWriteRoutes = map[string]struct{}{
	"/logout":              {},
	"/settings/2fa":        {},
	"/api/set-language":    {},
	"/api/domain/delete":   {},
	"/api/ipv64/domain":    {},
	"/api/trigger":         {},
	"/api/notify/test":     {},
	"/api/metrics/reset":   {},
	"/api/dns/propagation": {},
}

var viewerWriteRoutes = map[string]struct{}{
	"/logout":       {},
	"/settings/2fa": {},
}

func hasPermission(role UserRole, method, path string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)

	if role == RoleAdmin {
		return true
	}

	if method == http.MethodGet || method == http.MethodHead {
		_, allowed := sharedReadRoutes[path]

		return allowed
	}

	switch role {
	case RoleEditor:
		_, allowed := editorWriteRoutes[path]

		return allowed
	case RoleViewer:
		_, allowed := viewerWriteRoutes[path]

		return allowed
	default:
		return false
	}
}

// ============================================================================
// HANDLER: /login
// ============================================================================

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, phrases().APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)

		return
	}
	if r.Method == http.MethodPost && !parseLimitedAuthForm(w, r) {
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
				Message: "🚫 Login rate limit exceeded for IP: " + clientIP,
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintf(w, "%s", buildLoginPage(errMsg, redirect))

			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		user, found := findUserByUsername(username)
		storedHash := dummyPbkd2Hash
		if found {
			storedHash = user.PasswordHash
		}
		passwordOK := checkPassword(password, storedHash)
		if found && passwordOK {
			handleLoginPost2FA(w, r, user, redirect)

			return
		}

		errMsg = phrases().ErrInvalidLogin
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionLoginFail,
			Message: fmt.Sprintf(phrases().LoginFailedLog, safeAuthLogValue(username), getClientIP(r)),
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
		http.Error(w, phrases().APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)

		return
	}

	if sess, ok := sessionFromRequest(r); ok {
		sessionStore.Delete(sess.Token)
		log(LogContext{
			Level:   LogInfo,
			Action:  ActionLogout,
			Message: fmt.Sprintf(phrases().LogoutLog, sess.Username, sess.Role, getClientIP(r)),
		})
	}
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ============================================================================
// HANDLER: /setup
// ============================================================================

type setupForm struct {
	username string
	password string
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, phrases().APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)

		return
	}
	if r.Method == http.MethodPost && !parseLimitedAuthForm(w, r) {
		return
	}
	if !authEnabled {
		http.Redirect(w, r, "/", http.StatusFound)

		return
	}
	if len(loadUsers()) > 0 {
		http.Redirect(w, r, "/login", http.StatusFound)

		return
	}

	errMsg := ""
	if r.Method == MethodPOST {
		var completed bool
		errMsg, completed = handleSetupPost(w, r)
		if completed {
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "%s", buildSetupPage(errMsg))
}

func handleSetupPost(w http.ResponseWriter, r *http.Request) (string, bool) {
	form, errMsg := validateSetupForm(r)
	if errMsg != "" {
		return errMsg, false
	}

	newUser, errMsg := createInitialAdmin(form)
	if errMsg != "" {
		return errMsg, false
	}

	setupToken = ""
	log(LogContext{
		Level:   LogInfo,
		Action:  ActionStart,
		Message: fmt.Sprintf(phrases().FirstAdminCreatedLog, form.username),
	})

	sess := sessionStore.Create(&newUser, DefaultSessionMaxAge)
	if sess == nil {
		return phrases().ErrAccountCreate, false
	}
	setSessionCookie(w, r, sess)
	http.Redirect(w, r, "/", http.StatusSeeOther)

	return "", true
}

func validateSetupForm(r *http.Request) (setupForm, string) {
	token := strings.TrimSpace(r.FormValue("setup_token"))
	form := setupForm{
		username: strings.TrimSpace(r.FormValue("username")),
		password: r.FormValue("password"),
	}
	passwordConfirmation := r.FormValue("password2")

	switch {
	case subtle.ConstantTimeCompare([]byte(token), []byte(setupToken)) != 1:
		return setupForm{}, phrases().ErrInvalidSetupToken
	case !validDashboardUsername(form.username):
		return setupForm{}, phrases().ErrUsernameTooShort
	case len(form.password) < 8:
		return setupForm{}, phrases().ErrPasswordTooShort
	case form.password != passwordConfirmation:
		return setupForm{}, phrases().ErrPasswordsMismatch
	default:
		return form, ""
	}
}

func createInitialAdmin(form setupForm) (DashboardUser, string) {
	hash, err := hashPassword(form.password)
	if err != nil {
		return DashboardUser{}, phrases().ErrAccountCreate
	}

	userID, err := generateUserID()
	if err != nil {
		return DashboardUser{}, phrases().ErrAccountCreate
	}

	newUser := DashboardUser{
		ID:           userID,
		Username:     form.username,
		PasswordHash: hash,
		Role:         RoleAdmin,
		CreatedAt:    time.Now(),
	}
	if err := saveInitialAdmin(newUser); err != nil {
		return DashboardUser{}, phrases().ErrAccountSave
	}

	return newUser, ""
}

func saveInitialAdmin(newUser DashboardUser) error {
	return mutateUsers(func(users []DashboardUser) ([]DashboardUser, error) {
		if len(users) > 0 {
			return nil, errUsersExist
		}

		return []DashboardUser{newUser}, nil
	})
}

// ============================================================================
// HANDLER: /api/users  (only Admin)
// ============================================================================

type safeUser struct {
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Role        UserRole  `json:"role"`
	TOTPEnabled bool      `json:"totp_enabled"`
}

type createUserRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Role     UserRole `json:"role"`
}

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireAdmin(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case MethodGET:
		handleListUsers(w)
	case MethodPOST:
		handleCreateUser(w, r, sess)
	default:
		http.Error(w, phrases().APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
	}
}

func handleListUsers(w http.ResponseWriter) {
	users := loadUsers()
	out := make([]safeUser, len(users))

	for i, user := range users {
		out[i] = safeUser{
			ID:          user.ID,
			Username:    user.Username,
			Role:        user.Role,
			CreatedAt:   user.CreatedAt,
			LastLogin:   user.LastLogin,
			TOTPEnabled: user.TOTPEnabled,
		}
	}

	writeJSON(w, http.StatusOK, out)
}

func handleCreateUser(w http.ResponseWriter, r *http.Request, sess *Session) {
	req, ok := decodeCreateUserRequest(w, r)
	if !ok {
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": phrases().ErrHash,
		})

		return
	}

	if err := createDashboardUser(req, hash); err != nil {
		writeCreateUserError(w, err)

		return
	}

	log(LogContext{
		Level:  LogInfo,
		Action: ActionConfig,
		Message: fmt.Sprintf(
			phrases().UserCreatedLog,
			req.Username,
			req.Role,
			sess.Username,
		),
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status": phrases().StatusCreated,
	})
}

func decodeCreateUserRequest(
	w http.ResponseWriter,
	r *http.Request,
) (createUserRequest, bool) {
	var req createUserRequest

	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": phrases().ErrInvalidJSON,
		})

		return createUserRequest{}, false
	}

	req.Username = strings.TrimSpace(req.Username)

	if !validDashboardUsername(req.Username) || len(req.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": phrases().ErrUsernamePasswordMin,
		})

		return createUserRequest{}, false
	}

	if !isValidRole(req.Role) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": phrases().ErrInvalidRole,
		})

		return createUserRequest{}, false
	}

	return req, true
}

func createDashboardUser(
	req createUserRequest,
	passwordHash string,
) error {
	userID, err := generateUserID()
	if err != nil {
		return err
	}

	return mutateUsers(func(users []DashboardUser) ([]DashboardUser, error) {
		if usernameExists(users, req.Username) {
			return nil, errUsernameTaken
		}

		return append(users, DashboardUser{
			ID:           userID,
			Username:     req.Username,
			PasswordHash: passwordHash,
			Role:         req.Role,
			CreatedAt:    time.Now(),
		}), nil
	})
}

func usernameExists(users []DashboardUser, username string) bool {
	for _, user := range users {
		if strings.EqualFold(user.Username, username) {
			return true
		}
	}

	return false
}

func writeCreateUserError(w http.ResponseWriter, err error) {
	if errors.Is(err, errUsernameTaken) {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": phrases().ErrUsernameTaken,
		})

		return
	}

	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"error": phrases().ErrSave,
	})
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
		http.Error(w, phrases().APIErrorMethodNotAllowed, http.StatusMethodNotAllowed)
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

	err := updateUserByID(id, req.Role, req.Password)
	switch {
	case errors.Is(err, errUserNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": phrases().ErrUserNotFound})

		return
	case errors.Is(err, errLastAdmin), errors.Is(err, errInvalidRole),
		errors.Is(err, errPasswordShort), errors.Is(err, errNoUserChanges):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})

		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": phrases().ErrSave})

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": phrases().StatusUpdated})
}

type userUpdate struct {
	role         UserRole
	passwordHash string
}

func updateUserByID(id string, role UserRole, password string) error {
	update, err := buildUserUpdate(role, password)
	if err != nil {
		return err
	}

	err = mutateUsers(func(users []DashboardUser) ([]DashboardUser, error) {
		return applyUserUpdate(users, id, update)
	})
	if err != nil {
		return err
	}

	sessionStore.DeleteByUserID(id)

	return nil
}

func buildUserUpdate(
	role UserRole,
	password string,
) (userUpdate, error) {
	if role == "" && password == "" {
		return userUpdate{}, errNoUserChanges
	}

	if role != "" && !isValidRole(role) {
		return userUpdate{}, errInvalidRole
	}

	if password != "" && len(password) < 8 {
		return userUpdate{}, errPasswordShort
	}

	passwordHash, err := hashOptionalPassword(password)
	if err != nil {
		return userUpdate{}, err
	}

	return userUpdate{
		role:         role,
		passwordHash: passwordHash,
	}, nil
}

func hashOptionalPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}

	return hashPassword(password)
}

func applyUserUpdate(
	users []DashboardUser,
	id string,
	update userUpdate,
) ([]DashboardUser, error) {
	index := findUserIndexByID(users, id)
	if index < 0 {
		return nil, errUserNotFound
	}

	if err := validateAdminRoleChange(
		users,
		users[index],
		update.role,
	); err != nil {
		return nil, err
	}

	if update.role != "" {
		users[index].Role = update.role
	}

	if update.passwordHash != "" {
		users[index].PasswordHash = update.passwordHash
	}

	return users, nil
}

func findUserIndexByID(users []DashboardUser, id string) int {
	for i := range users {
		if users[i].ID == id {
			return i
		}
	}

	return -1
}

func validateAdminRoleChange(
	users []DashboardUser,
	user DashboardUser,
	newRole UserRole,
) error {
	if newRole == "" ||
		newRole == RoleAdmin ||
		user.Role != RoleAdmin {
		return nil
	}

	if countAdmins(users) <= 1 {
		return errLastAdmin
	}

	return nil
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
	if errors.Is(err, errLastAdmin) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})

		return
	}
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
	found := false
	err := mutateUsers(func(users []DashboardUser) ([]DashboardUser, error) {
		filtered := make([]DashboardUser, 0, len(users))
		for _, user := range users {
			if user.ID != id {
				filtered = append(filtered, user)

				continue
			}

			found = true
			if user.Role == RoleAdmin && countAdmins(users) <= 1 {
				return nil, errLastAdmin
			}
		}

		if !found {
			return users, nil
		}

		return filtered, nil
	})
	if err != nil {
		return false, err
	}
	if found {
		sessionStore.DeleteByUserID(id)
	}

	return found, nil
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
	if err != nil || iter < 10_000 || iter > 10_000_000 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) < 16 || len(salt) > 128 || len(want) < 16 || len(want) > 128 {
		return false
	}

	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(got, want) == 1
}

// ============================================================================
// AUDIT LOG
// ============================================================================

const (
	auditLogMaxBytes = 5 << 20
	auditReadLimit   = 200
)

var (
	auditLogMu      sync.Mutex
	backupRestoreMu sync.Mutex
	auditFilePath   string
)

type auditEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	Role      string `json:"role"`
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Result    string `json:"result"`
	Status    int    `json:"status"`
}

func auditLogFilePath() string {
	basePath := strings.TrimSpace(logPath)
	if basePath == "" {
		basePath = strings.TrimSpace(usersFilePath)
	}
	if basePath == "" {
		return ""
	}

	auditFilePath = filepath.Join(filepath.Dir(basePath), "audit.json")

	return auditFilePath
}

func safeAuditField(value string, maxRunes int) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}

		return r
	}, strings.TrimSpace(value))
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes]) + "…"
	}

	return value
}

func auditHTTPRequest(r *http.Request, sess *Session, status int) {
	if r == nil {
		return
	}

	actor := "anonymous"
	role := ""
	if sess != nil {
		actor = sess.Username
		role = string(sess.Role)
	} else if !authEnabled {
		actor = "auth-disabled"
		role = string(RoleAdmin)
	}

	result := "success"
	if status >= 400 {
		result = "error"
	}
	id, err := randomHexToken(8)
	if err != nil {
		id = strconv.FormatInt(time.Now().UnixNano(), 36)
	}

	entry := auditEntry{
		ID:        id,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Actor:     safeAuditField(actor, 128),
		Role:      safeAuditField(role, 32),
		IP:        safeAuditField(getClientIP(r), 128),
		Method:    safeAuditField(strings.ToUpper(r.Method), 16),
		Path:      safeAuditField(r.URL.Path, 256),
		Status:    status,
		Result:    result,
	}
	if err := appendAuditEntry(entry); err != nil {
		debugLog("AUDIT", "", fmt.Sprintf("audit write failed: %v", err))
	}
}

func appendAuditEntry(entry auditEntry) error {
	path := auditLogFilePath()
	if path == "" {
		return errors.New("audit path unavailable")
	}

	auditLogMu.Lock()
	defer auditLogMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if st, err := os.Stat(path); err == nil && st.Size() >= auditLogMaxBytes {
		if err := rotateAuditFile(path); err != nil {
			return err
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			debugLog("DASHBOARD", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = file.Write(data)

	return err
}

func rotateAuditFile(path string) error {
	oldest := fmt.Sprintf("%s.%d", path, auditLogMaxBackups)
	_ = os.Remove(oldest)

	for i := auditLogMaxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", path, i)
		dst := fmt.Sprintf("%s.%d", path, i+1)
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, dst); err != nil {
				return err
			}
		}
	}

	return os.Rename(path, path+".1")
}

func readAuditEntries(path string, limit int) ([]auditEntry, int, string, string, error) {
	if limit <= 0 || limit > auditReadLimit {
		limit = auditReadLimit
	}

	auditLogMu.Lock()
	defer auditLogMu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []auditEntry{}, 0, "", "", nil
		}

		return nil, 0, "", "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			debugLog("DASHBOARD", "", fmt.Sprintf(phrases().ErrBodyClose+": %v", err))
		}
	}()

	ring := make([]auditEntry, limit)
	total := 0
	oldestTimestamp := ""
	latestTimestamp := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 128<<10)
	for scanner.Scan() {
		var entry auditEntry
		if json.Unmarshal(scanner.Bytes(), &entry) != nil {
			continue
		}
		if entry.Timestamp != "" {
			if oldestTimestamp == "" {
				oldestTimestamp = entry.Timestamp
			}
			latestTimestamp = entry.Timestamp
		}
		ring[total%limit] = entry
		total++
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, "", "", err
	}

	count := min(total, limit)
	entries := make([]auditEntry, 0, count)
	for i := range count {
		index := (total - 1 - i) % limit
		entries = append(entries, ring[index])
	}

	return entries, total, oldestTimestamp, latestTimestamp, nil
}

func auditGenerationPath(gen int) (string, error) {
	base := auditLogFilePath()
	if base == "" {
		return "", errors.New("audit path unavailable")
	}
	if gen <= 0 {
		return base, nil
	}
	return fmt.Sprintf("%s.%d", base, gen), nil
}

type auditGenerationInfo struct {
	Gen     int       `json:"gen"`
	ModTime time.Time `json:"mod_time"`
	Size    int64     `json:"size"`
}

func listAuditGenerations() []auditGenerationInfo {
	base := auditLogFilePath()
	if base == "" {
		return nil
	}

	var out []auditGenerationInfo
	if st, err := os.Stat(base); err == nil {
		out = append(out, auditGenerationInfo{Gen: 0, ModTime: st.ModTime(), Size: st.Size()})
	}
	for i := 1; i <= auditLogMaxBackups; i++ {
		p := fmt.Sprintf("%s.%d", base, i)
		if st, err := os.Stat(p); err == nil {
			out = append(out, auditGenerationInfo{Gen: i, ModTime: st.ModTime(), Size: st.Size()})
		}
	}

	return out
}

func handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !requireAdminAPI(w, r) {
		return
	}

	gen := 0
	if v := r.URL.Query().Get("gen"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			gen = parsed
		}
	}
	path, err := auditGenerationPath(gen)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})

		return
	}

	entries, total, oldestTimestamp, latestTimestamp, err := readAuditEntries(path, auditReadLimit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})

		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":          entries,
		"total":            total,
		"oldest_timestamp": oldestTimestamp,
		"latest_timestamp": latestTimestamp,
		"generations":      listAuditGenerations(),
		"selected_gen":     gen,
	})
}

func deleteAuditEntry(id string) error {
	path := auditLogFilePath()
	if path == "" {
		return errors.New("audit path unavailable")
	}

	auditLogMu.Lock()
	defer auditLogMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	var kept []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry auditEntry
		if json.Unmarshal([]byte(line), &entry) != nil {
			kept = append(kept, line)

			continue
		}
		if entry.ID != id {
			kept = append(kept, line)
		}
	}

	output := ""
	if len(kept) > 0 {
		output = strings.Join(kept, "\n") + "\n"
	}

	return os.WriteFile(path, []byte(output), 0o600)
}

func handleAPIAuditDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, esc(phrases().APIErrorMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}
	if !requireAdminAPI(w, r) {
		return
	}

	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body); err != nil || body.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})

		return
	}

	if err := deleteAuditEntry(body.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
	<title>` + esc(title) + ` · DynDNS</title>
	<link rel="stylesheet" href="` + assetURL("/assets/style.css", dashboardCSSETag) + `">
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
			<script src="` + assetURL("/assets/auth.js", authJSETag) + `" defer></script>
		</body>
	</html>`
}

func buildLoginPage(errMsg, redirect string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="auth-error">⚠️ ` + esc(errMsg) + `</div>`
	}

	action := "/login?redirect=" + url.QueryEscape(safeLocalRedirect(redirect))
	body := `
	<div class="auth-logo">🌐</div>
	<div class="auth-title">` + phrases().DashboardTitle + `</div>
	<div class="auth-sub">` + phrases().LoginSubtitle + `</div>
	` + errHTML + `
	<form method="POST" action="` + esc(action) + `">
		<div class="auth-field">
			<label class="auth-label">` + phrases().Username + `</label>
			<input class="auth-input" type="text" name="username" autofocus autocomplete="username" required>
		</div>
		<div class="auth-field">
			<label class="auth-label">` + phrases().Password + `</label>
			<div class="input-with-action">
				<input id="login-password" class="auth-input" type="password" name="password" autocomplete="current-password" required>
				<button type="button" class="input-action-btn" data-toggle-password="login-password" aria-label="Passwort anzeigen" aria-pressed="false">👁️</button>
			</div>
		</div>
		<button class="auth-btn" type="submit">🔐 ` + phrases().LoginButton + `</button>
	</form>
	<div class="auth-hint">` + phrases().LoginHint + `</div>`

	return authPageShell(phrases().LoginTitle, body)
}

func buildSetupPage(errMsg string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="auth-error">⚠️ ` + esc(errMsg) + `</div>`
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
			<div class="input-with-action">
				<input id="setup-password" class="auth-input" type="password" name="password" autocomplete="new-password" required>
				<button type="button" class="input-action-btn" data-toggle-password="setup-password" aria-label="Passwort anzeigen" aria-pressed="false">👁️</button>
			</div>
		</div>
		<div class="auth-field">
			<label class="auth-label">` + phrases().PasswordConfirm + `</label>
			<div class="input-with-action">
				<input id="setup-password2" class="auth-input" type="password" name="password2" autocomplete="new-password" required>
				<button type="button" class="input-action-btn" data-toggle-password="setup-password2" aria-label="Passwort anzeigen" aria-pressed="false">👁️</button>
			</div>
		</div>
		<button class="auth-btn" type="submit">✅ ` + phrases().SetupButton + `</button>
	</form>
	<div class="auth-hint">` + phrases().SetupHint + `</div>`

	return authPageShell(phrases().SetupTitle, body)
}
