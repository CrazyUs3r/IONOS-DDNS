package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleViewer = "viewer"

	authCookieName = "dashboard_session"
	sessionTTL     = 7 * 24 * time.Hour
)

type AuthStore struct {
	Users []AuthUser `json:"users"`
}

type AuthUser struct {
	Username     string `json:"username"`
	Role         string `json:"role"`
	PasswordHash string `json:"password_hash"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type CurrentUser struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

var (
	authMu       sync.RWMutex
	authStore    AuthStore
	authFilePath string
	sessionKey   []byte
)

func initAuthStore(configDir string) error {
	authFilePath = filepath.Join(configDir, "auth.json")
	keyFile := filepath.Join(configDir, "session.key")

	key, err := loadOrCreateSessionKey(keyFile)
	if err != nil {
		return err
	}
	sessionKey = key

	if _, err := os.Stat(authFilePath); errors.Is(err, os.ErrNotExist) {
		pw := randomToken(18)
		now := time.Now().UTC().Format(time.RFC3339)

		authStore = AuthStore{
			Users: []AuthUser{
				{
					Username:     "admin",
					Role:         RoleAdmin,
					PasswordHash: hashPassword(pw),
					CreatedAt:    now,
					UpdatedAt:    now,
				},
			},
		}

		if err := saveAuthStoreLocked(); err != nil {
			return err
		}

		fmt.Printf("\n============================================================\n")
		fmt.Printf(" Dashboard initial admin login\n")
		fmt.Printf(" Username: admin\n")
		fmt.Printf(" Password: %s\n", pw)
		fmt.Printf(" Change this password after first login.\n")
		fmt.Printf("============================================================\n\n")

		return nil
	}

	b, err := os.ReadFile(authFilePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, &authStore)
}

func loadOrCreateSessionKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err == nil && len(key) >= 32 {
			return key, nil
		}
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		return nil, err
	}

	return key, nil
}

func saveAuthStoreLocked() error {
	b, err := json.MarshalIndent(authStore, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(authFilePath, b, 0o600)
}

func hashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)

	dk := pbkdf2SHA256([]byte(password), salt, 120000, 32)

	return "pbkdf2_sha256$120000$" +
		base64.RawURLEncoding.EncodeToString(salt) + "$" +
		base64.RawURLEncoding.EncodeToString(dk)
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}

	var iter int
	_, _ = fmt.Sscanf(parts[1], "%d", &iter)

	salt, err1 := base64.RawURLEncoding.DecodeString(parts[2])
	want, err2 := base64.RawURLEncoding.DecodeString(parts[3])

	if err1 != nil || err2 != nil || iter < 10000 {
		return false
	}

	got := pbkdf2SHA256([]byte(password), salt, iter, len(want))

	return hmac.Equal(got, want)
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	var out []byte
	block := 1

	for len(out) < keyLen {
		u := pbkdf2Block(password, salt, iter, block)
		out = append(out, u...)
		block++
	}

	return out[:keyLen]
}

func pbkdf2Block(password, salt []byte, iter, block int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{
		byte(block >> 24),
		byte(block >> 16),
		byte(block >> 8),
		byte(block),
	})

	u := mac.Sum(nil)
	out := append([]byte(nil), u...)

	for i := 1; i < iter; i++ {
		mac = hmac.New(sha256.New, password)
		mac.Write(u)
		u = mac.Sum(nil)

		for j := range out {
			out[j] ^= u[j]
		}
	}

	return out
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}

func issueSession(w http.ResponseWriter, username, role string) {
	exp := time.Now().Add(sessionTTL).Unix()
	payload := fmt.Sprintf("%s|%s|%d", username, role, exp)
	sig := signSession(payload)

	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig)),
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func signSession(payload string) string {
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write([]byte(payload))

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func currentUserFromRequest(r *http.Request) (CurrentUser, bool) {
	c, err := r.Cookie(authCookieName)
	if err != nil || c.Value == "" {
		return CurrentUser{}, false
	}

	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return CurrentUser{}, false
	}

	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 {
		return CurrentUser{}, false
	}

	payload := strings.Join(parts[:3], "|")
	if !hmac.Equal([]byte(signSession(payload)), []byte(parts[3])) {
		return CurrentUser{}, false
	}

	var exp int64
	_, _ = fmt.Sscanf(parts[2], "%d", &exp)

	if time.Now().Unix() > exp {
		return CurrentUser{}, false
	}

	authMu.RLock()
	defer authMu.RUnlock()

	for _, u := range authStore.Users {
		if u.Username == parts[0] && u.Role == parts[1] {
			return CurrentUser{
				Username: u.Username,
				Role:     u.Role,
			}, true
		}
	}

	return CurrentUser{}, false
}

func requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := currentUserFromRequest(r); !ok {
			if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/ws" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next(w, r)
	}
}

func requireRole(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	allowed := map[string]bool{}

	for _, role := range roles {
		allowed[role] = true
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			u, ok := currentUserFromRequest(r)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if !allowed[u.Role] {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next(w, r)
		}
	}
}

func canViewSettings(role string) bool {
	return role == RoleAdmin || role == RoleEditor
}

func canSaveSettings(role string) bool {
	return role == RoleAdmin
}
