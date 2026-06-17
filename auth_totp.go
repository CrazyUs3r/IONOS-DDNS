// Package main
package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	pquernaTotp "github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

// ============================================================================
// TOTP — RFC 6238 (HOTP + time window)
// ============================================================================

const (
	totpDigits    = 6
	totpPeriod    = 30 // seconds
	totpWindow    = 1  // ± 1 period tolerance (covers clock skew)
	totpSecretLen = 20 // bytes → 32-char Base32
	totpIssuer    = "DynDNS"
)

const (
	flashTypeSuccess = "success"
	flashTypeError   = "error"
	flashTypeInfo    = "info"
)

func generateTOTPSecret() (string, error) {
	b := make([]byte, totpSecretLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func validateTOTPCode(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}

	valid, err := pquernaTotp.ValidateCustom(
		code,
		strings.ToUpper(strings.TrimSpace(secret)),
		time.Now(),
		pquernaTotp.ValidateOpts{
			Period:    uint(totpPeriod),
			Skew:      uint(totpWindow),
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	return err == nil && valid
}

func totpProvisioningURI(secret, username, issuer string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		url.QueryEscape(issuer),
		url.QueryEscape(username),
		secret,
		url.QueryEscape(issuer),
		totpDigits,
		totpPeriod,
	)
}

// ============================================================================
// TOTP PENDING STORE  (secret generated but not yet confirmed)
// ============================================================================

type totpPending struct {
	Secret    string
	ExpiresAt time.Time
}

var (
	totpPendingMu    sync.Mutex
	totpPendingStore = map[string]totpPending{}
)

func storeTOTPPending(userID, secret string) {
	totpPendingMu.Lock()
	defer totpPendingMu.Unlock()
	totpPendingStore[userID] = totpPending{
		Secret:    secret,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
}

func loadTOTPPending(userID string) (string, bool) {
	totpPendingMu.Lock()
	defer totpPendingMu.Unlock()
	p, ok := totpPendingStore[userID]
	if !ok || time.Now().After(p.ExpiresAt) {
		delete(totpPendingStore, userID)
		return "", false
	}
	return p.Secret, true
}

func deleteTOTPPending(userID string) {
	totpPendingMu.Lock()
	defer totpPendingMu.Unlock()
	delete(totpPendingStore, userID)
}

// ============================================================================
// USER TOTP FIELDS  (stored in users.json via DashboardUser extension)
// ============================================================================

func totpEnabledForUser(u *DashboardUser) bool {
	return u.TOTPSecret != "" && u.TOTPEnabled
}

// ============================================================================
// PENDING 2FA SESSION STORE  (after password OK, before TOTP OK)
// ============================================================================

type pendingTOTPSession struct {
	UserID    string
	Username  string
	Role      UserRole
	Redirect  string
	Attempts  int
	ExpiresAt time.Time
}

var (
	pendingTOTPMu    sync.Mutex
	pendingTOTPStore = map[string]pendingTOTPSession{}
)

const (
	legacyPendingTOTPCookieName = "dyndns_totp_pending"
	pendingTOTPCookieNameHTTP   = "dyndns_totp_pending_http"
	pendingTOTPCookieNameHTTPS  = "dyndns_totp_pending_https"
	pendingTOTPMaxAge           = 10 * time.Minute
	maxTOTPLoginAttempts        = 5
)

func pendingTOTPCookieName(r *http.Request) string {
	if requestUsesHTTPS(r) {
		return pendingTOTPCookieNameHTTPS
	}
	return pendingTOTPCookieNameHTTP
}

func createPendingTOTPSession(userID, username string, role UserRole, redirect string) string {
	token, err := randomHexToken(16)
	if err != nil {
		return ""
	}

	pendingTOTPMu.Lock()
	pendingTOTPStore[token] = pendingTOTPSession{
		UserID:    userID,
		Username:  username,
		Role:      role,
		Redirect:  redirect,
		ExpiresAt: time.Now().Add(pendingTOTPMaxAge),
	}
	pendingTOTPMu.Unlock()

	return token
}

func loadPendingTOTPSession(token string) (pendingTOTPSession, bool) {
	pendingTOTPMu.Lock()
	defer pendingTOTPMu.Unlock()
	s, ok := pendingTOTPStore[token]
	if !ok || time.Now().After(s.ExpiresAt) {
		delete(pendingTOTPStore, token)
		return pendingTOTPSession{}, false
	}
	return s, true
}

func deletePendingTOTPSession(token string) {
	pendingTOTPMu.Lock()
	defer pendingTOTPMu.Unlock()
	delete(pendingTOTPStore, token)
}

func recordPendingTOTPFailure(token string) (remaining int, ok bool) {
	pendingTOTPMu.Lock()
	defer pendingTOTPMu.Unlock()

	pending, exists := pendingTOTPStore[token]
	if !exists || time.Now().After(pending.ExpiresAt) {
		delete(pendingTOTPStore, token)
		return 0, false
	}

	pending.Attempts++
	if pending.Attempts >= maxTOTPLoginAttempts {
		delete(pendingTOTPStore, token)
		return 0, false
	}
	pendingTOTPStore[token] = pending
	return maxTOTPLoginAttempts - pending.Attempts, true
}

// ============================================================================
// HANDLER: /login/totp  — second-factor verification step
// ============================================================================

func handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !authEnabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	var pendingToken string
	for _, name := range []string{pendingTOTPCookieName(r), legacyPendingTOTPCookieName} {
		cookie, err := r.Cookie(name)
		if err == nil {
			pendingToken = cookie.Value
			break
		}
	}
	if pendingToken == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	pending, ok := loadPendingTOTPSession(pendingToken)
	if !ok {
		clearPendingTOTPCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var errMsg string

	if r.Method == MethodPOST {
		code := strings.TrimSpace(r.FormValue("totp_code"))

		users := loadUsers()
		foundUser, found := findDashboardUser(users, pending.UserID)

		if found &&
			totpEnabledForUser(foundUser) &&
			validateTOTPCode(foundUser.TOTPSecret, code) {
			deletePendingTOTPSession(pendingToken)
			clearPendingTOTPCookie(w, r)

			sess := sessionStore.Create(foundUser, DefaultSessionMaxAge)
			if sess == nil {
				http.Error(w, "could not create session", http.StatusInternalServerError)
				return
			}
			setSessionCookie(w, r, sess)

			foundUser.LastLogin = time.Now()
			_ = saveUsers(users)

			log(LogContext{
				Level:   LogInfo,
				Action:  ActionConfig,
				Message: fmt.Sprintf("🔐 2FA login OK: %s from %s", pending.Username, getClientIP(r)),
			})

			redirect := safeLocalRedirect(pending.Redirect)
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		}

		remaining, retryAllowed := recordPendingTOTPFailure(pendingToken)
		if !retryAllowed {
			clearPendingTOTPCookie(w, r)
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprint(w, buildTOTPLoginPage("Too many invalid codes. Please log in again."))
			return
		}
		time.Sleep(300 * time.Millisecond)
		errMsg = fmt.Sprintf("%s (%d attempts remaining)", t(phrases().TotpLoginInvalidCode, "Invalid code — please try again"), remaining)
		log(LogContext{
			Level:   LogWarn,
			Action:  ActionConfig,
			Message: fmt.Sprintf("🔐 2FA failed: %s from %s", pending.Username, getClientIP(r)),
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, buildTOTPLoginPage(errMsg))
}

func expirePendingTOTPCookie(w http.ResponseWriter, name string, secure bool) {
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

func clearPendingTOTPCookie(w http.ResponseWriter, r *http.Request) {
	expirePendingTOTPCookie(w, pendingTOTPCookieName(r), secureCookieEnabled(r))
	expirePendingTOTPCookie(w, legacyPendingTOTPCookieName, secureCookieEnabled(r))
}

// ============================================================================
// HANDLER: /settings/2fa  — enable / disable / re-generate TOTP
// ============================================================================

func handleSettings2FA(w http.ResponseWriter, r *http.Request) {
	if !authEnabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	sess, ok := sessionFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login?redirect=/settings/2fa", http.StatusFound)
		return
	}

	users := loadUsers()
	currentUser, ok := findDashboardUser(users, sess.UserID)
	if !ok {
		http.Error(w, t(phrases().TotpUserNotFound, "User not found"), http.StatusInternalServerError)
		return
	}

	fragment := is2FAFragmentRequest(r)
	if r.Method == MethodGET && !fragment {
		http.Redirect(w, r, "/#totp", http.StatusFound)
		return
	}

	flash := totpFlash{}
	if r.Method == MethodPOST {
		flash = handleSettings2FAPost(r, currentUser, users)
		users = loadUsers()
		currentUser, ok = findDashboardUser(users, sess.UserID)
		if !ok {
			http.Error(w, t(phrases().TotpUserNotFound, "User not found"), http.StatusInternalServerError)
			return
		}
	}

	pendingSecret, hasPending := loadTOTPPending(currentUser.ID)
	render2FASettings(w, fragment, currentUser, pendingSecret, hasPending, flash)
}

type totpFlash struct {
	Message string
	Type    string
}

func is2FAFragmentRequest(r *http.Request) bool {
	return r.URL.Query().Get("fragment") == "1" || r.Header.Get("X-Requested-With") == "fetch"
}

func findDashboardUser(users []DashboardUser, userID string) (*DashboardUser, bool) {
	for i := range users {
		if users[i].ID == userID {
			return &users[i], true
		}
	}
	return nil, false
}

func handleSettings2FAPost(r *http.Request, currentUser *DashboardUser, users []DashboardUser) totpFlash {
	switch r.FormValue("action") {
	case "generate":
		return handle2FAGenerate(currentUser)
	case "confirm":
		return handle2FAConfirm(r, currentUser, users)
	case "disable":
		return handle2FADisable(r, currentUser, users)
	default:
		return totpFlash{Message: "Unknown 2FA action", Type: flashTypeError}
	}
}

func handle2FAGenerate(currentUser *DashboardUser) totpFlash {
	secret, err := generateTOTPSecret()
	if err != nil {
		return totpFlash{Message: fmt.Sprintf(
			t(phrases().TotpFlashGenerateSecretFailed, "Failed to generate secret: %s"),
			err.Error(),
		), Type: flashTypeError}
	}
	storeTOTPPending(currentUser.ID, secret)
	return totpFlash{Message: t(
		phrases().TotpFlashScanConfirm,
		"Scan the QR code and confirm with your current code",
	), Type: flashTypeInfo}
}

func handle2FAConfirm(r *http.Request, currentUser *DashboardUser, users []DashboardUser) totpFlash {
	pendingSecret, hasPending := loadTOTPPending(currentUser.ID)
	if !hasPending {
		return totpFlash{Message: t(
			phrases().TotpFlashSetupExpired,
			"Setup expired — please start again",
		), Type: flashTypeError}
	}

	code := strings.TrimSpace(r.FormValue("totp_code"))
	if !validateTOTPCode(pendingSecret, code) {
		return totpFlash{Message: t(
			phrases().TotpFlashCodeInvalid,
			"Code invalid — please try again",
		), Type: flashTypeError}
	}

	deleteTOTPPending(currentUser.ID)
	for i := range users {
		if users[i].ID == currentUser.ID {
			users[i].TOTPSecret = pendingSecret
			users[i].TOTPEnabled = true
			break
		}
	}

	if err := saveUsers(users); err != nil {
		return totpFlash{Message: fmt.Sprintf(
			t(phrases().TotpFlashSaveFailed, "Could not save: %s"),
			err.Error(),
		), Type: flashTypeError}
	}
	return totpFlash{Message: t(
		phrases().TotpFlashEnabled,
		"✅ Two-factor authentication is now active",
	), Type: flashTypeSuccess}
}

func handle2FADisable(r *http.Request, currentUser *DashboardUser, users []DashboardUser) totpFlash {
	code := strings.TrimSpace(r.FormValue("totp_code"))
	if !totpEnabledForUser(currentUser) || !validateTOTPCode(currentUser.TOTPSecret, code) {
		return totpFlash{Message: t(
			phrases().TotpFlashDisableInvalid,
			"Invalid code — cannot disable 2FA",
		), Type: flashTypeError}
	}

	for i := range users {
		if users[i].ID == currentUser.ID {
			users[i].TOTPSecret = ""
			users[i].TOTPEnabled = false
			break
		}
	}

	if err := saveUsers(users); err != nil {
		return totpFlash{Message: fmt.Sprintf(
			t(phrases().TotpFlashSaveFailed, "Could not save: %s"),
			err.Error(),
		), Type: flashTypeError}
	}
	deleteTOTPPending(currentUser.ID)
	return totpFlash{Message: t(
		phrases().TotpFlashDisabled,
		"🔓 Two-factor authentication has been disabled",
	), Type: flashTypeSuccess}
}

func render2FASettings(w http.ResponseWriter, fragment bool, currentUser *DashboardUser, pendingSecret string, hasPending bool, flash totpFlash) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if fragment {
		_, _ = fmt.Fprint(w, build2FASettingsFragment(currentUser, pendingSecret, hasPending, flash.Message, flash.Type))
		return
	}
	_, _ = fmt.Fprint(w, build2FAPage(currentUser, pendingSecret, hasPending, flash.Message, flash.Type, false))
}

// ============================================================================
// HANDLER: /api/2fa/status  — for dashboard user list (show badge)
// ============================================================================

func handleAPI2FAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != MethodGET {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, ok := sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	users := loadUsers()
	type entry struct {
		ID          string `json:"id"`
		TOTPEnabled bool   `json:"totp_enabled"`
	}

	var result []entry
	for _, u := range users {
		if sess.Role == RoleAdmin || u.ID == sess.UserID {
			result = append(result, entry{ID: u.ID, TOTPEnabled: u.TOTPEnabled})
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// ============================================================================
// HANDLER: /settings/2fa/qr  — local QR image for pending TOTP setup
// ============================================================================

func handleSettings2FAQRCode(w http.ResponseWriter, r *http.Request) {
	if !authEnabled {
		http.Error(w, "auth disabled", http.StatusNotFound)
		return
	}

	sess, ok := sessionFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	users := loadUsers()
	var currentUser *DashboardUser
	for i := range users {
		if users[i].ID == sess.UserID {
			currentUser = &users[i]
			break
		}
	}
	if currentUser == nil {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}

	pendingSecret, hasPending := loadTOTPPending(currentUser.ID)
	if !hasPending {
		http.Error(w, "no pending 2FA setup", http.StatusNotFound)
		return
	}

	uri := totpProvisioningURI(pendingSecret, currentUser.Username, totpIssuer)
	png, err := qrcode.Encode(uri, qrcode.Medium, 220)
	if err != nil {
		http.Error(w, "could not generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write(png)
}

// ============================================================================
// MODIFY handleLogin TO INTERCEPT WHEN 2FA IS ENABLED
// This replaces the session-creation block inside handleLogin.
// Call this helper instead.
// ============================================================================

func handleLoginPost2FA(w http.ResponseWriter, r *http.Request, user *DashboardUser, redirect string) {
	if totpEnabledForUser(user) {
		token := createPendingTOTPSession(user.ID, user.Username, user.Role, redirect)
		if token == "" {
			http.Error(w, "could not create 2FA session", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     pendingTOTPCookieName(r),
			Value:    token,
			Path:     "/",
			MaxAge:   int(pendingTOTPMaxAge.Seconds()),
			Expires:  time.Now().Add(pendingTOTPMaxAge),
			HttpOnly: true,
			Secure:   secureCookieEnabled(r),
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/login/totp", http.StatusFound)
		return
	}

	sess := sessionStore.Create(user, DefaultSessionMaxAge)
	if sess == nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, r, sess)

	users := loadUsers()
	for i := range users {
		if users[i].ID == user.ID {
			users[i].LastLogin = time.Now()
			break
		}
	}
	_ = saveUsers(users)

	log(LogContext{
		Level:   LogInfo,
		Action:  ActionConfig,
		Message: fmt.Sprintf(phrases().LoginSuccessLog, user.Username, user.Role, getClientIP(r)),
	})

	http.Redirect(w, r, safeLocalRedirect(redirect), http.StatusSeeOther)
}

// ============================================================================
// QR CODE  — generated locally by this app, no external Google/third-party call
// ============================================================================

func qrCodeImgTag(uri string) string {
	_ = uri
	return `<img src="/settings/2fa/qr"
		alt="` + esc(t(phrases().TotpQRAlt, "QR Code")) + `" width="220" height="220"
		class="totp-qr-img">`
}

// ============================================================================
// HTML PAGES
// ============================================================================

func build2FASettingsFragmentForSession(sess *Session, flash, flashType string) string {
	if sess == nil {
		return `<div class="auth-error">⚠️ ` + esc(t(phrases().ErrAuthFailed, "Session expired. Please log in again.")) + `</div>`
	}

	users := loadUsers()
	var currentUser *DashboardUser
	for i := range users {
		if users[i].ID == sess.UserID {
			currentUser = &users[i]
			break
		}
	}
	if currentUser == nil {
		return `<div class="auth-error">⚠️ ` + esc(t(phrases().TotpUserNotFound, "User not found")) + `</div>`
	}

	pendingSecret, hasPending := loadTOTPPending(currentUser.ID)
	return build2FASettingsFragment(currentUser, pendingSecret, hasPending, flash, flashType)
}

func totpFlashClass(flashType string) string {
	switch flashType {
	case flashTypeSuccess:
		return "totp-flash--success"
	case flashTypeError:
		return "totp-flash--error"
	case flashTypeInfo:
		return "totp-flash--info"
	default:
		return "totp-flash--info"
	}
}

func build2FASettingsFragment(user *DashboardUser, pendingSecret string, hasPending bool, flash, flashType string) string {
	flashHTML := ""
	if flash != "" {
		flashHTML = fmt.Sprintf(
			`<div class="totp-flash %s">%s</div>`,
			totpFlashClass(flashType),
			esc(flash),
		)
	}

	issuer := totpIssuer
	formAction := "/settings/2fa?fragment=1"
	var mainContent string

	switch {
	case hasPending:
		uri := totpProvisioningURI(pendingSecret, user.Username, issuer)
		mainContent = `
<p class="totp-help">
	` + esc(t(
			phrases().TotpScanQrInstruction,
			"Scan this QR code with Google Authenticator, Authy, Microsoft Authenticator or any TOTP app, then enter the 6-digit code below to confirm.",
		)) + `
</p>
` + qrCodeImgTag(uri) + `
<details class="totp-uri-details">
	<summary>` + esc(t(phrases().TotpShowURIManually, "Show URI manually")) + `</summary>
	<div class="totp-uri-box">` + esc(uri) + `</div>
</details>
<form method="POST" action="` + formAction + `" data-totp-form>
	<input type="hidden" name="action" value="confirm">
	<div class="auth-field">
		<label class="auth-label">` + esc(t(phrases().TotpCodeFromAppLabel, "6-digit code from your app")) + `</label>
		<input class="auth-input totp-code-input" type="text" name="totp_code" inputmode="numeric"
			pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"
			placeholder="123456" autofocus required>
	</div>
	<button class="auth-btn totp-btn-success" type="submit">
		` + esc(t(phrases().TotpConfirmActivateButton, "✅ Confirm & Activate 2FA")) + `
	</button>
</form>
<form method="POST" action="` + formAction + `" data-totp-form class="totp-secondary-form">
	<input type="hidden" name="action" value="generate">
	<button class="auth-btn totp-btn-muted" type="submit">
		` + esc(t(phrases().TotpGenerateNewSecretButton, "🔄 Generate new secret")) + `
	</button>
</form>`

	case totpEnabledForUser(user):
		activeSubtitle := fmt.Sprintf(
			t(phrases().TotpActiveSubtitle, "Your account is protected with TOTP (%s)"),
			issuer,
		)

		mainContent = `
<div class="totp-status-box">
	<span class="totp-status-icon">🔒</span>
	<div class="totp-status-title totp-status-title--enabled">` + esc(t(phrases().TotpActiveTitle, "Two-factor authentication is active")) + `</div>
	<div class="totp-status-sub">` + esc(activeSubtitle) + `</div>
</div>

<hr class="totp-separator">

<p class="totp-help">
	` + esc(t(phrases().TotpDisableInstruction, "To disable 2FA, enter a valid code from your authenticator app.")) + `
</p>
<form method="POST" action="` + formAction + `" data-totp-form>
	<input type="hidden" name="action" value="disable">
	<div class="auth-field">
		<label class="auth-label">` + esc(t(phrases().TotpCurrentCodeLabel, "Current 6-digit code")) + `</label>
		<input class="auth-input totp-code-input" type="text" name="totp_code" inputmode="numeric"
			pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"
			placeholder="123456" required>
	</div>
	<button class="auth-btn totp-btn-danger" type="submit">
		` + esc(t(phrases().TotpDisableButton, "🔓 Disable 2FA")) + `
	</button>
</form>
<hr class="totp-separator">
<form method="POST" action="` + formAction + `" data-totp-form>
	<input type="hidden" name="action" value="generate">
	<button class="auth-btn totp-btn-muted" type="submit">
		` + esc(t(phrases().TotpReplaceSecretButton, "🔄 Replace with new secret")) + `
	</button>
</form>`

	default:
		mainContent = `
<div class="totp-status-box">
	<span class="totp-status-icon">🔓</span>
	<div class="totp-status-title">` + esc(t(phrases().TotpInactiveTitle, "Two-factor authentication is not active")) + `</div>
	<div class="totp-status-sub">` + esc(t(phrases().TotpInactiveSubtitle, "Add an extra layer of security to your account")) + `</div>
</div>
<form method="POST" action="` + formAction + `" data-totp-form class="totp-primary-form">
	<input type="hidden" name="action" value="generate">
	<button class="auth-btn totp-btn-primary" type="submit">
		` + esc(t(phrases().TotpSetupButton, "🛡️ Set up 2FA")) + `
	</button>
</form>`
	}

	accountMeta := fmt.Sprintf(
		t(phrases().TotpAccountMeta, "Account: %s · Role: %s"),
		user.Username,
		string(user.Role),
	)

	return `
<div class="totp-settings-inline">
<div class="auth-logo">🛡️</div>
<div class="auth-title">` + esc(t(phrases().TotpTitle, "Two-Factor Authentication")) + `</div>
<div class="auth-sub">` + esc(accountMeta) + `</div>
	` + flashHTML + mainContent + `
</div>`
}

func build2FAPage(user *DashboardUser, pendingSecret string, hasPending bool, flash, flashType string, embedded bool) string {
	body := build2FASettingsFragment(user, pendingSecret, hasPending, flash, flashType)
	if embedded {
		return body
	}
	body += `
<div class="totp-page-link-row">
	<a href="/" class="totp-page-link">` + esc(t(phrases().TotpBackToDashboard, "← Back to Dashboard")) + `</a>
</div>`
	return authPageShell(t(phrases().TotpSettingsPageTitle, "2FA Settings"), body)
}

func buildTOTPLoginPage(errMsg string) string {
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="auth-error">⚠️ ` + esc(errMsg) + `</div>`
	}

	body := `
<div class="auth-logo">🔑</div>
<div class="auth-title">` + esc(t(phrases().TotpTitle, "Two-Factor Authentication")) + `</div>
<div class="auth-sub">` + esc(t(phrases().TotpLoginSubtitle, "Enter the 6-digit code from your authenticator app")) + `</div>
` + errHTML + `
<form method="POST" action="/login/totp">
	<div class="auth-field">
		<label class="auth-label">` + esc(t(phrases().TotpLoginCodeLabel, "Authentication Code")) + `</label>
		<input class="auth-input totp-login-code-input" type="text" name="totp_code" inputmode="numeric"
			pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"
			placeholder="000000" autofocus required>
	</div>
	<button class="auth-btn" type="submit">` + esc(t(phrases().TotpVerifyButton, "🔓 Verify")) + `</button>
</form>
<div class="totp-page-link-row totp-page-link-row--compact">
	<a href="/login" class="totp-page-link">
		` + esc(t(phrases().TotpBackToLogin, "← Back to login")) + `
	</a>
</div>`

	return authPageShell(t(phrases().TotpVerificationPageTitle, "2FA Verification"), body)
}

// ============================================================================
// JSON marshaling helpers for the extended DashboardUser  (users.json compat)
// ============================================================================

func marshalUsersWithTOTP(users []DashboardUser) ([]byte, error) {
	return json.MarshalIndent(users, "", "  ")
}

func unmarshalUsersWithTOTP(data []byte) ([]DashboardUser, error) {
	var users []DashboardUser
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return users, nil
}
