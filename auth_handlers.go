package main

import (
	"encoding/json"
	"html"
	"net/http"
	"strings"
	"time"
)

type loginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := currentUserFromRequest(r); ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	_, _ = w.Write([]byte(`<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard Login</title>
<style>` + cssData + `
body {
	min-height: 100vh;
	overflow: hidden;
}

.auth-wrap {
	min-height: 100vh;
	display: flex;
	align-items: center;
	justify-content: center;
	position: relative;
	padding: 18px;
}

.auth-wave-bg {
	position: fixed;
	inset: 0;
	z-index: 0;
	overflow: hidden;
	background: linear-gradient(120deg, #66a6ff33, #89f7fe22);
}

.auth-wave-bg::before,
.auth-wave-bg::after {
	content: "";
	position: absolute;
	width: 180vw;
	height: 180vw;
	left: -40vw;
	top: 42vh;
	border-radius: 42%;
	background: rgba(255,255,255,0.08);
	animation: authWave 18s linear infinite;
}

.auth-wave-bg::after {
	width: 160vw;
	height: 160vw;
	left: -30vw;
	top: 46vh;
	opacity: .55;
	animation-duration: 28s;
	animation-direction: reverse;
}

.auth-card {
	position: relative;
	z-index: 2;
	width: min(420px, 94vw);
	background: rgba(20, 30, 48, .78);
	border: 1px solid rgba(255,255,255,.14);
	border-radius: 18px;
	padding: 28px;
	box-shadow: 0 28px 80px rgba(0,0,0,.42);
	backdrop-filter: blur(18px);
}

.auth-title {
	font-size: 1.4rem;
	font-weight: 800;
	margin: 0 0 6px;
}

.auth-sub {
	opacity: .68;
	margin: 0 0 22px;
}

.auth-row {
	margin-bottom: 14px;
}

.auth-row label {
	display: block;
	font-size: .75rem;
	opacity: .75;
	margin-bottom: 6px;
}

.auth-error {
	display: none;
	color: var(--error);
	font-size: .85rem;
	margin-bottom: 12px;
}

.auth-actions {
	display: flex;
	justify-content: space-between;
	align-items: center;
	gap: 10px;
	margin-top: 18px;
}

.auth-time-badge {
	position: relative;
	z-index: 2;
	position: fixed;
	right: 18px;
	bottom: 14px;
	font-size: .78rem;
	opacity: .55;
}

/* Tageszeiten */
body[data-login-theme="morning"] .auth-wave-bg {
	background: linear-gradient(135deg, #ffecd244, #fcb69f33, #1f293744);
}

body[data-login-theme="day"] .auth-wave-bg {
	background: linear-gradient(135deg, #89f7fe44, #66a6ff33, #1f293744);
}

body[data-login-theme="evening"] .auth-wave-bg {
	background: linear-gradient(135deg, #fbc2eb44, #a6c1ee33, #1f293744);
}

body[data-login-theme="night"] .auth-wave-bg {
	background: linear-gradient(135deg, #0f172a, #1e293b, #020617);
}

body[data-login-theme="night"] .auth-wave-bg::before,
body[data-login-theme="night"] .auth-wave-bg::after {
	background: rgba(59,130,246,.08);
}

@keyframes authWave {
	0% {
		transform: rotate(0deg) translateY(0);
	}
	50% {
		transform: rotate(180deg) translateY(-16px);
	}
	100% {
		transform: rotate(360deg) translateY(0);
	}
}
</style>
</head>
<body>

<div class="auth-wave-bg"></div>

<div class="auth-wrap">
<form class="auth-card" id="loginForm">
<h1 class="auth-title">🔐 Dashboard Login</h1>
<p class="auth-sub">Bitte mit deinem Dashboard-Benutzer anmelden.</p>

<div class="auth-error" id="err">Login fehlgeschlagen</div>

<div class="auth-row">
<label>Benutzer</label>
<input class="s-input" id="username" autocomplete="username" value="admin">
</div>

<div class="auth-row">
<label>Passwort</label>
<input class="s-input" id="password" type="password" autocomplete="current-password" autofocus>
</div>

<div class="auth-actions">
<span style="opacity:.55;font-size:.8rem">Session: 7 Tage</span>
<button class="action-btn" type="submit">Einloggen</button>
</div>
</form>
</div>

<div class="auth-time-badge" id="timeBadge"></div>

<script>
(function() {
	const hour = new Date().getHours();
	let theme = "day";
	let label = "Tag";

	if (hour >= 5 && hour < 11) {
		theme = "morning";
		label = "Morgen";
	} else if (hour >= 11 && hour < 17) {
		theme = "day";
		label = "Tag";
	} else if (hour >= 17 && hour < 21) {
		theme = "evening";
		label = "Abend";
	} else {
		theme = "night";
		label = "Nacht";
	}

	document.body.setAttribute("data-login-theme", theme);
	document.getElementById("timeBadge").textContent = label + " Theme";
})();

document.getElementById('loginForm').addEventListener('submit', async e => {
	e.preventDefault();

	const r = await fetch('/api/login', {
		method: 'POST',
		headers: {'Content-Type': 'application/json'},
		body: JSON.stringify({
			username: username.value,
			password: password.value
		})
	});

	if (r.ok) {
		location.href = '/';
	} else {
		err.style.display = 'block';
	}
});
</script>
</body>
</html>`))
}

func handleAPILogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p loginPayload

	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	p.Username = strings.TrimSpace(p.Username)

	authMu.RLock()
	defer authMu.RUnlock()

	for _, u := range authStore.Users {
		if u.Username == p.Username && verifyPassword(p.Password, u.PasswordHash) {
			issueSession(w, u.Username, u.Role)
			writeJSON(w, http.StatusOK, map[string]string{
				"status": "ok",
			})
			return
		}
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func handleAPILogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clearSession(w)

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func handleAPIMe(w http.ResponseWriter, r *http.Request) {
	u, ok := currentUserFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":              u,
		"can_view_settings": canViewSettings(u.Role),
		"can_save_settings": canSaveSettings(u.Role),
	})
}

func handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		authMu.RLock()
		defer authMu.RUnlock()

		out := make([]map[string]string, 0, len(authStore.Users))

		for _, u := range authStore.Users {
			out = append(out, map[string]string{
				"username":   u.Username,
				"role":       u.Role,
				"created_at": u.CreatedAt,
				"updated_at": u.UpdatedAt,
			})
		}

		writeJSON(w, http.StatusOK, out)

	case http.MethodPost:
		var p struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}

		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		p.Username = strings.TrimSpace(p.Username)
		p.Role = strings.ToLower(strings.TrimSpace(p.Role))

		if p.Username == "" || len(p.Password) < 8 || !validRole(p.Role) {
			http.Error(w, "invalid user", http.StatusBadRequest)
			return
		}

		authMu.Lock()
		defer authMu.Unlock()

		for _, u := range authStore.Users {
			if u.Username == p.Username {
				http.Error(w, "user exists", http.StatusConflict)
				return
			}
		}

		now := time.Now().UTC().Format(time.RFC3339)

		authStore.Users = append(authStore.Users, AuthUser{
			Username:     p.Username,
			Role:         p.Role,
			PasswordHash: hashPassword(p.Password),
			CreatedAt:    now,
			UpdatedAt:    now,
		})

		if err := saveAuthStoreLocked(); err != nil {
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"status": "created",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAPIUserUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	p.Username = strings.TrimSpace(p.Username)
	p.Role = strings.ToLower(strings.TrimSpace(p.Role))

	authMu.Lock()
	defer authMu.Unlock()

	for i := range authStore.Users {
		if authStore.Users[i].Username == p.Username {
			if p.Role != "" {
				if !validRole(p.Role) {
					http.Error(w, "invalid role", http.StatusBadRequest)
					return
				}

				authStore.Users[i].Role = p.Role
			}

			if p.Password != "" {
				if len(p.Password) < 8 {
					http.Error(w, "password min 8 chars", http.StatusBadRequest)
					return
				}

				authStore.Users[i].PasswordHash = hashPassword(p.Password)
			}

			authStore.Users[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)

			if err := saveAuthStoreLocked(); err != nil {
				http.Error(w, "save failed", http.StatusInternalServerError)
				return
			}

			writeJSON(w, http.StatusOK, map[string]string{
				"status": "updated",
			})
			return
		}
	}

	http.Error(w, "not found", http.StatusNotFound)
}

func handleAPIUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p struct {
		Username string `json:"username"`
	}

	_ = json.NewDecoder(r.Body).Decode(&p)
	p.Username = strings.TrimSpace(p.Username)

	authMu.Lock()
	defer authMu.Unlock()

	admins := 0

	for _, u := range authStore.Users {
		if u.Role == RoleAdmin {
			admins++
		}
	}

	for i, u := range authStore.Users {
		if u.Username == p.Username {
			if u.Role == RoleAdmin && admins <= 1 {
				http.Error(w, "last admin cannot be deleted", http.StatusBadRequest)
				return
			}

			authStore.Users = append(authStore.Users[:i], authStore.Users[i+1:]...)

			if err := saveAuthStoreLocked(); err != nil {
				http.Error(w, "save failed", http.StatusInternalServerError)
				return
			}

			writeJSON(w, http.StatusOK, map[string]string{
				"status": "deleted",
			})
			return
		}
	}

	http.Error(w, "not found", http.StatusNotFound)
}

func validRole(role string) bool {
	return role == RoleAdmin || role == RoleEditor || role == RoleViewer
}

func authTopHTML(r *http.Request) string {
	u, ok := currentUserFromRequest(r)
	if !ok {
		return ""
	}

	userButton := ""
	if u.Role == RoleAdmin {
		userButton = `<button class="action-btn" onclick="openUserModal()" id="userMgmtBtn">👥 Benutzer</button>`
	}

	return `
	<div class="auth-header-actions">
		<span class="provider-badge">` + html.EscapeString(u.Username) + ` · ` + html.EscapeString(u.Role) + `</span>` +
		userButton +
		`<button class="action-btn" onclick="logout()">Logout</button>
	</div>
	`
}

func userManagementModalHTML() string {
	return `
	<div class="modal-overlay" id="userOverlay" onclick="if(event.target.id==='userOverlay')closeUserModal()">
	<div class="modal">
		<div class="modal-header">
			<h2>👥 Benutzerverwaltung</h2>
			<button class="modal-close" onclick="closeUserModal()">×</button>
		</div>
		<div class="modal-body">
			<div id="userList" class="s-section"></div>
			<div class="s-section">
				<h3>Benutzer anlegen / ändern</h3>
				<div style="display:grid;gap:12px">
				<label style="display:grid;gap:6px">
				<span class="s-label">Benutzer</span>
				<input class="s-input" id="u-name" autocomplete="off">
				</label>
				<label style="display:grid;gap:6px">
				<span class="s-label">Passwort</span>
				<input class="s-input" id="u-pass" type="password" placeholder="min. 8 Zeichen" autocomplete="new-password">
				</label>
				<label style="display:grid;gap:6px">
					<span class="s-label">Rolle</span>
					<select class="s-input" id="u-role">
						<option value="viewer">viewer</option>
						<option value="editor">editor</option>
						<option value="admin">admin</option>
					</select>
				</label>
				</div>
				<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
				<button class="action-btn" onclick="saveUser(false)">Anlegen</button>
				<button class="action-btn" onclick="saveUser(true)">Ändern</button>
				</div>
			</div>
		</div>
	</div>
	</div>
`
}
