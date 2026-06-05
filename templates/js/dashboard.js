let blinkTimer = null;
let currentLevel = 'ok';
let ws = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
let editIndex = null;
let tempDomainConfigs = [];
const reconnectDelayMax = 10000;

// ============================================================================
// SIDEBAR NAVIGATION
// ============================================================================
const PAGES = ['dashboard', 'domains', 'metrics', 'diagnose', 'logs', 'debug', 'backup', 'settings', 'users'];

let currentPage = 'dashboard';

function navTo(page) {
	if (!PAGES.includes(page)) page = 'dashboard';
	currentPage = page;

	isSettingsOpen = (page === 'settings');

	document.querySelectorAll('.nav-item[data-page]').forEach(el => {
		el.classList.toggle('nav-active', el.dataset.page === page);
	});

	document.querySelectorAll('.page-section').forEach(el => {
		el.style.display = el.dataset.section === page ? '' : 'none';
	});

	const topbarSaveBtn = document.getElementById('topbar-save-config-button');
	if (topbarSaveBtn) {
		topbarSaveBtn.classList.toggle('is-hidden', page !== 'settings');
	}

	const titles = {
		dashboard: tr('nav_dashboard', '🌐 Dashboard'),
		domains: tr('nav_domains', '🌐 Domains'),
		metrics: tr('nav_metrics', '📊 Metrics'),
		diagnose: tr('nav_diagnose', '🩺 Diagnose'),
		logs: tr('nav_logs', '🧾 Logs'),
		debug: tr('nav_debug', '🐞 Debug'),
		backup: tr('nav_backup', '💾 Backup & Restore'),
		settings: tr('nav_settings', '⚙️ Settings'),
		users: tr('nav_users', '👥 User Management'),
	};
	const titleEl = document.getElementById('page-title');
	if (titleEl) titleEl.textContent = titles[page] || 'Dashboard';

	if (page === 'settings') {
		_initSettingsFields();
	}

	if (page === 'users') {
		loadUsers();
	}

	if (page === 'logs') {
		refreshDashboardLogs();
	}

	if (page === 'domains') {
		refreshDashboardDomains();
	}

	if (page === 'diagnose') {
		refreshDiagnosis();
	}

	try { localStorage.setItem('nav-page', page); } catch { }

	const sb = document.getElementById('sidebar');
	if (sb && window.innerWidth < 768) sb.classList.remove('sidebar-open');
}

function toggleSidebar() {
	const sb = document.getElementById('sidebar');
	if (sb) sb.classList.toggle('sidebar-open');
}

document.addEventListener('DOMContentLoaded', async () => {
	await loadInitialConfig();
	renderSettingsDomainList();
	if (!localStorage.getItem('theme')) {
		localStorage.setItem('theme',
			window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
		);
	}
	const savedTheme = localStorage.getItem('theme');
	document.documentElement.setAttribute('data-theme', savedTheme);

	const initialMetrics = {
		avg_latency: (document.getElementById('mLatency')?.textContent || '').trim(),
		success_rate: (document.getElementById('mSuccess')?.textContent || '').trim(),
		total_requests: (document.getElementById('mTotal')?.textContent || '0').trim(),
	};
	currentLevel = calcLevelFromMetrics(initialMetrics);
	applyFavicon(savedTheme, currentLevel, false);
	setBlinking(savedTheme, currentLevel);

	initDomainDetailsState();

	document.addEventListener('visibilitychange', () => {
		if (document.visibilityState === 'visible') {
			if (!ws || ws.readyState === WebSocket.CLOSED) {
				reconnectDelay = 1000;
				connectWS();
			}
		}
	});

	const savedPage = localStorage.getItem('nav-page') || 'dashboard';
	navTo(savedPage);

	document.getElementById('sidebar-overlay')?.addEventListener('click', () => {
		document.getElementById('sidebar')?.classList.remove('sidebar-open');
	});

	document.addEventListener('click', (event) => {
		if (window.innerWidth < 768) {
			const sidebar = document.getElementById('sidebar');
			const hamburger = document.querySelector('.hamburger-btn');

			if (sidebar && sidebar.classList.contains('sidebar-open')) {

				if (!sidebar.contains(event.target) && (!hamburger || !hamburger.contains(event.target))) {
					sidebar.classList.remove('sidebar-open');
				}
			}
		}
	});
	startUptimeClocks();
	initIPTimelines();
	initKeyboardShortcuts();
	initChangedBadges();
	initChartTooltips();
	startClock();
	connectWS();
	document.addEventListener('keydown', e => { if (e.key === 'Escape') closeSettings(); });
});

function faviconHref(theme, level, blink) {
	return '/favicon.svg?theme=' + encodeURIComponent(theme) +
		'&level=' + encodeURIComponent(level) +
		'&blink=' + (blink ? '1' : '0') +
		'&v=' + Date.now();
}

function applyFavicon(theme, level, blink) {
	const fav = document.getElementById('favicon');
	if (!fav) return;
	fav.href = faviconHref(theme, level, blink);
}

function setBlinking(theme, level) {
	if (blinkTimer) { clearInterval(blinkTimer); blinkTimer = null; }
	if (level !== 'err') return;
	let on = false;
	blinkTimer = setInterval(() => {
		on = !on;
		applyFavicon(theme, 'err', on);
	}, 700);
}

function toggleTheme() {
	const html = document.documentElement;
	const current = html.getAttribute('data-theme') || 'dark';
	const next = current === 'dark' ? 'light' : 'dark';
	html.setAttribute('data-theme', next);
	localStorage.setItem('theme', next);
	applyFavicon(next, currentLevel, false);
	setBlinking(next, currentLevel);
	showToast(tr('theme', 'Theme') + ': ' + next);
}

function parseDurationToMs(s) {
	s = (s || '').trim().toLowerCase().replace('µs', 'us');
	const m = s.match(/^([0-9]+(?:\.[0-9]+)?)(ms|s|us)$/);
	if (!m) return NaN;
	const val = parseFloat(m[1]);
	const unit = m[2];
	if (unit === 'ms') return val;
	if (unit === 's') return val * 1000;
	if (unit === 'us') return val / 1000;
	return NaN;
}

function toNum(v, fallback = 0) {
	if (v == null) return fallback;
	if (typeof v === "number") return v;
	const s = String(v).replace(",", ".").replace("%", "").trim();
	const n = Number(s);
	return Number.isFinite(n) ? n : fallback;
}

function initDomainDetailsState() {
	document.querySelectorAll('details.domain-item').forEach(details => {
		if (details.dataset.detailsBound === '1') return;
		const domain = details.dataset.domain;
		if (!domain) return;
		const key = 'domain-open-' + domain;
		if (localStorage.getItem(key) === '1') {
			details.open = true;
		}
		details.addEventListener('toggle', () => {
			localStorage.setItem(key, details.open ? '1' : '0');
		});
		details.dataset.detailsBound = '1';
	});
}

function calcLevelFromMetrics(m) {
	const total = toNum(m.total_requests, 0);
	const successRate = toNum(m.success_rate, 100);
	const successAge = toNum(m.last_success_age_secs, -1);
	const errorAge = toNum(m.last_error_age_secs, -1);
	const recovered = successAge >= 0 && errorAge >= 0 && successAge < errorAge;
	const hasActiveError = errorAge >= 0 && !recovered;

	if (hasActiveError) return errorAge > 600 ? 'warn' : 'err';
	if (total >= 5 && successRate <= 0) return 'err';
	if (total >= 10 && successRate < 50) return 'err';

	const ms = parseDurationToMs(m.avg_latency);
	if (Number.isFinite(ms)) {
		if (ms >= 1000) return 'err';
		if (ms >= 300) return 'warn';
	}
	if (total >= 10 && successRate < 90) return 'warn';
	return 'ok';
}

async function loadInitialConfig() {
	try {
		const r = await fetch('/api/config');
		if (!r.ok) return;
		const data = await r.json();
		tempDomainConfigs = (Array.isArray(data.domain_configs) ? data.domain_configs : [])
			.map(d => ({ ...d }));
		window.initialSystem = data.system ?? {};
	} catch {
		tempDomainConfigs = [];
		window.initialSystem = {};
	}
}

function updateMetrics(m) {
	const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
	setTxt('lastUpdate', new Date().toLocaleTimeString());
	setTxt('mTotal', m.total_requests);
	setTxt('mSuccess', m.success_rate);
	setTxt('mLatency', m.avg_latency);
	setTxt('mErrors', (m.client_errors || 0) + " / " + (m.server_errors || 0));
	setTxt('mP50', m.p50_latency);
	setTxt('mP85', m.p85_latency);
	setTxt('mP99', m.p99_latency);

	const bar = document.getElementById('mUsageBar');
	if (bar) {
		const p = (m.usage_percent != null) ? Number(m.usage_percent) : 0;
		bar.style.width = String(isFinite(p) ? p : 0) + "%";
		if (m.usage_color) bar.style.background = m.usage_color;
	}

	setTxt('mDailyGET', m.daily_get);
	setTxt('mDailyPOST', m.daily_post);
	setTxt('mDailyPUT', m.daily_put);
	setTxt('mDailyDELETE', m.daily_delete);
	setTxt('mDailyNIC', m.daily_nic);
	setTxt('mIPLatency', m.ip_latency_avg);
	setTxt('mIPCount', m.ip_latency_count);
	setTxt('mLastIPCheck', m.last_ip_check);

	const u = m.uptime_secs || 0;
	const days = Math.floor(u / 86400);
	const h = Math.floor((u % 86400) / 3600);
	const min = Math.floor((u % 3600) / 60);
	const s = u % 60;

	let uptime;
	if (days > 0) uptime = days + 'd ' + h + 'h ' + min + 'm';
	else if (h > 0) uptime = h + 'h ' + min + 'm';
	else if (min > 0) uptime = min + 'm ' + s + 's';
	else uptime = s + 's';
	setTxt('uptime', uptime);
}

function initChartTooltips(root = document) {
	root.querySelectorAll('svg.chart-svg').forEach(svg => {
		if (svg.dataset.tooltipReady === '1') return;

		const pointEls = Array.from(svg.querySelectorAll('.chart-point'));
		if (!pointEls.length) return;

		const points = pointEls
			.map(el => ({
				x: Number(el.dataset.x),
				y: Number(el.dataset.y),
				value: el.dataset.value || '0',
				label: el.dataset.label || '',
				unit: el.dataset.unit || '',
			}))
			.filter(p => Number.isFinite(p.x) && Number.isFinite(p.y));

		if (!points.length) return;

		const wrap = svg.closest('.chart-wrap');
		if (!wrap) return;

		svg.dataset.tooltipReady = '1';

		const tooltip = document.createElement('div');
		tooltip.className = 'chart-tooltip';
		tooltip.setAttribute('role', 'status');
		tooltip.setAttribute('aria-live', 'polite');
		document.body.appendChild(tooltip);

		const hoverLine = svg.querySelector('.chart-hover-line');
		const hoverDot = svg.querySelector('.chart-hover-dot');

		const viewBox = svg.viewBox.baseVal;
		const chartWidth = viewBox && viewBox.width ? viewBox.width : 300;
		const chartHeight = viewBox && viewBox.height ? viewBox.height : 60;

		let hideTimer = null;

		const nearestPoint = event => {
			const rect = svg.getBoundingClientRect();
			const pointerX = ((event.clientX - rect.left) / rect.width) * chartWidth;

			return points.reduce((best, point) => {
				return Math.abs(point.x - pointerX) < Math.abs(best.x - pointerX) ? point : best;
			}, points[0]);
		};

		const showPoint = point => {
			if (hideTimer) {
				clearTimeout(hideTimer);
				hideTimer = null;
			}

			if (hoverLine) {
				hoverLine.setAttribute('x1', point.x);
				hoverLine.setAttribute('x2', point.x);
				hoverLine.classList.add('visible');
			}

			if (hoverDot) {
				hoverDot.setAttribute('cx', point.x);
				hoverDot.setAttribute('cy', point.y);
				hoverDot.classList.add('visible');
			}

			const svgRect = svg.getBoundingClientRect();

			let left = svgRect.left + (point.x / chartWidth) * svgRect.width;
			let top = svgRect.top + (point.y / chartHeight) * svgRect.height;

			tooltip.textContent = `${point.label} · ${point.value}${point.unit}`;

			const padding = 10;
			const minLeft = padding + 35;
			const maxLeft = window.innerWidth - padding - 35;

			left = Math.min(Math.max(left, minLeft), maxLeft);

			if (top < 45) {
				top = svgRect.bottom + 32;
				tooltip.style.transform = 'translate(-50%, 0)';
			} else {
				tooltip.style.transform = 'translate(-50%, calc(-100% - 10px))';
			}

			tooltip.style.left = `${left}px`;
			tooltip.style.top = `${top}px`;
			tooltip.classList.add('visible');
		};

		const hide = () => {
			tooltip.classList.remove('visible');
			hoverLine?.classList.remove('visible');
			hoverDot?.classList.remove('visible');
		};

		const showFromEvent = event => {
			showPoint(nearestPoint(event));
		};

		// ---- Mouse / Stylus ----
		svg.addEventListener('pointerenter', event => {
			if (event.pointerType === 'touch') return;
			showFromEvent(event);
		});
		svg.addEventListener('pointermove', event => {
			if (event.pointerType === 'touch') return;
			showFromEvent(event);
		});
		svg.addEventListener('pointerleave', event => {
			if (event.pointerType === 'touch') return;
			hide();
		});

		// ---- Touch ----
		svg.addEventListener('touchstart', event => {
			if (hideTimer) {
				clearTimeout(hideTimer);
				hideTimer = null;
			}
			const t = event.touches[0];
			showPoint(nearestPoint(t));
		}, {
			passive: true
		});

		svg.addEventListener('touchmove', event => {
			if (hideTimer) {
				clearTimeout(hideTimer);
				hideTimer = null;
			}
			const t = event.touches[0];
			showPoint(nearestPoint(t));
		}, {
			passive: true
		});

		svg.addEventListener('touchend', () => {
			hideTimer = setTimeout(hide, 2500);
		}, {
			passive: true
		});

		svg.addEventListener('touchcancel', hide, {
			passive: true
		});
		svg.addEventListener('pointerleave', event => {
			if (event.pointerType !== 'touch' && event.pointerType !== 'pen') {
				hide();
			}
		});
	});
}

let isSettingsOpen = false;

function connectWS() {
	const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
	ws = new WebSocket(proto + location.host + '/ws');
	ws.onmessage = (e) => {
		let msg;
		try { msg = JSON.parse(e.data); } catch { return; }
		if (isSettingsOpen) { return; }
		if (msg.type === 'initial' || msg.type === 'metrics') {
			updateMetrics(msg.data);
			const theme = localStorage.getItem('theme') || 'dark';
			currentLevel = calcLevelFromMetrics(msg.data);
			applyFavicon(theme, currentLevel, false);
			setBlinking(theme, currentLevel);
		} else if (msg.type === 'domain_update') {
			updateDomainDisplay(msg.data).catch(err =>
				console.error('domain_update error:', err)
			);
		} else if (msg.type === 'notification') {
			showToast(msg.data.message, msg.data.level || 'info');
		} else if (msg.type === 'debug_log') {
			appendDebugLog(msg.data);
		} else if (msg.type === 'ip_check_result') {
			updateEndpointStatus(msg.data);
		}
		if (msg.data && msg.data.provider_status) {
			Object.entries(msg.data.provider_status).forEach(([p, ok]) => {
				document.querySelectorAll('.provider-status-dot').forEach(el => {
					el.textContent = ok ? ' ✅' : ' ❌';
				});
			});
		}
	};
	ws.onclose = () => scheduleReconnect();
	ws.onopen = () => { reconnectDelay = 1000; if (reconnectTimer) clearTimeout(reconnectTimer); };
}

function scheduleReconnect() {
	if (reconnectTimer) return;
	reconnectTimer = setTimeout(() => { reconnectTimer = null; connectWS(); }, reconnectDelay);
	reconnectDelay = Math.min(reconnectDelay * 2, reconnectDelayMax);
}

let _toastTimer = null;
function showToast(message, type = 'success') {
	const toast = document.getElementById('toast');
	if (!toast) return;
	if (_toastTimer) clearTimeout(_toastTimer);
	toast.textContent = message;
	let borderColor = 'var(--success)';
	let duration = 4000;
	if (type === 'error') { borderColor = 'var(--error)'; duration = 5000; }
	else if (type === 'warning') { borderColor = '#facc15'; duration = 4000; }
	else if (type === 'info') { borderColor = '#3b82f6'; duration = 2500; }
	toast.style.borderLeft = '4px solid ' + borderColor;
	toast.classList.add('show');
	addToNotifCenter(message, type);
	_toastTimer = setTimeout(() => {
		toast.classList.remove('show');
		_toastTimer = null;
	}, duration);
}

function copyIP(text) {
	if (!text || text === 'N/A' || text === '-') {
		showToast(tr('no_ip_to_copy', '❌ No IP to copy'), 'error');
		return;
	}
	const fallback = (t) => {
		const ta = document.createElement("textarea"); ta.value = t;
		ta.style.position = "fixed"; ta.style.left = "-9999px";
		document.body.appendChild(ta); ta.focus(); ta.select();
		try { document.execCommand('copy'); showToast(tr('copied', '✓ Copied: ') + text); }
		catch (err) { showToast(tr('copy_error', '❌ Fehler'), 'error'); }
		document.body.removeChild(ta);
	};
	if (navigator.clipboard && window.isSecureContext) {
		navigator.clipboard.writeText(text).then(() => showToast(tr('copied', '✓ Copied: ') + text)).catch(() => fallback(text));
	} else fallback(text);
}

function filterLogs(filter) {
	document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.filter === filter));
	const entries = document.querySelectorAll('.log-entry');
	const f = filter.toUpperCase();
	requestAnimationFrame(() => {
		entries.forEach(entry => {
			if (f === 'ALL') { entry.style.display = ''; return; }
			const action = (entry.dataset.action || '').toUpperCase();
			const level = (entry.dataset.level || '').toUpperCase();
			const show = (f === 'ERR' && level === 'ERR') ||
				(f === 'WARN' && level === 'WARN') ||
				(action === f);
			entry.style.display = show ? '' : 'none';
		});
	});
}

function triggerUpdate() {
	const btn = document.getElementById('update-button');
	const token = localStorage.getItem('triggerToken') || '';
	if (btn) btn.disabled = true;
	showToast(tr('update_starting', '⏳ Update wird gestartet...'), 'info');
	fetch('/api/trigger', {
		method: 'POST',
		headers: token ? { 'X-Trigger-Token': token } : {}
	})
		.then(r => r.json().then(j => {
			if (j.error) {
				showToast('⚠️ ' + j.error, 'warning');
			} else {
				showToast(tr('update_started', '✅ Update gestartet'), 'success');
			}
		}))
		.catch(() => {
			showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error');
		})
		.finally(() => {
			if (btn) btn.disabled = false;
		});
}

function sendNotifyTest() {
	const btn = document.getElementById('notify-test-btn');
	const result = document.getElementById('notify-test-result');
	const token = localStorage.getItem('triggerToken') || '';

	if (btn) { btn.disabled = true; btn.textContent = tr('notify_btn_sending', '⏳ Sende...'); }
	if (result) { result.style.display = 'none'; result.innerHTML = ''; }

	fetch('/api/notify/test', {
		method: 'POST',
		headers: token ? { 'X-Trigger-Token': token } : {}
	})
		.then(r => {
			if (r.status === 401) {
				if (btn) { btn.disabled = false; btn.textContent = tr('notify_btn_test', '🧪 Test-Nachricht senden'); }
				if (result) {
					result.style.display = 'block';
					result.innerHTML = `<span class="notify-result--error">${tr('notify_test_unauthorized', '❌ Unauthorized (check token)')}</span>`;
				}
				return null;
			}
			return r.json();
		})
		.then(data => {
			if (!data) return;
			if (btn) { btn.disabled = false; btn.textContent = tr('notify_btn_test', '🧪 Test-Nachricht senden'); }
			if (!result) return;

			result.style.display = 'block';

			if (data.status === 'no_notifiers') {
				result.innerHTML = `<span class="notify-result--warn">${tr('notify_no_notifier', '⚠️ Keine aktiven Notifier konfiguriert.')}</span>`;
				return;
			}

			if (data.status !== 'done') {
				result.innerHTML = `<span class="notify-result--error">${tr('notify_test_error', '❌ Error while sending')}</span>`;
				return;
			}

			const lines = (data.results || []).map(r => {
				const icon = r.ok ? '✅' : '❌';
				const err = r.error ? ` <span class="notify-result--detail">(${escHtml(r.error)})</span>` : '';
				return `${icon} <strong>${escHtml(r.name)}</strong>${err}`;
			});

			const allOk = data.sent === data.total;
			const successText = tr('notify_stat_success', 'erfolgreich');
			const summary = allOk
				? `<div class="notify-result-summary">${tr('notify_test_success', '✅ Test message sent successfully!')}</div>`
				: `<div class="notify-result-summary">${data.sent}/${data.total} ${successText}</div>`;

			result.innerHTML = summary + lines.join('<br>');
			result.className = allOk ? 'notify-test-result notify-result--ok' : 'notify-test-result notify-result--warn';
		})
		.catch(() => {
			if (btn) { btn.disabled = false; btn.textContent = tr('notify_btn_test', '🧪 Test-Nachricht senden'); }
			if (result) {
				result.style.display = 'block';
				result.innerHTML = `<span class="notify-result--error">${tr('notify_test_conn_error', '❌ Connection error to server')}</span>`;
			}
		});
}

function exportData() {
	const token = localStorage.getItem('triggerToken') || '';
	fetch('/api/export', {
		headers: token ? { 'X-Trigger-Token': token } : {}
	})
		.then(async r => {
			if (!r.ok) throw new Error(await r.text());
			return r.blob();
		})
		.then(blob => {
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = 'dyndns-export-' + new Date().toISOString().split('T')[0] + '.json';
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
			showToast(tr('export_started', '✓ Export gestartet'));
		})
		.catch(() => showToast(tr('export_failed', 'Export fehlgeschlagen'), 'error'));
}
function sanitizeBase(s) {
	s = (s || '').trim().toLowerCase();
	let out = '';
	for (const ch of s) {
		const code = ch.charCodeAt(0);
		if ((code >= 97 && code <= 122) || (code >= 48 && code <= 57) || ch === '-' || ch === '_') out += ch;
		else if (ch === '.') out += '-';
	}
	return out || 'x';
}

async function shortHash8(str) {
	if (!(window.crypto && crypto.subtle)) return '00000000';
	const data = new TextEncoder().encode(str || '');
	const buf = await crypto.subtle.digest('SHA-256', data);
	return Array.from(new Uint8Array(buf))
		.map(b => b.toString(16).padStart(2, '0'))
		.join('')
		.slice(0, 8);
}


async function makeSafeID(domain) {
	domain = (domain || '').trim();
	const base = sanitizeBase(domain);
	const sfx = await shortHash8(domain);
	return (base === 'x' ? 'd-' : base + '-') + sfx;
}

async function updateDomainDisplay(data) {
	const safeID = await makeSafeID(data.domain);
	const ip4El = document.getElementById('ip4-' + safeID);
	const ip6El = document.getElementById('ip6-' + safeID);
	if (ip4El && data.ipv4) ip4El.textContent = data.ipv4;
	if (ip6El && data.ipv6) ip6El.textContent = data.ipv6;
	const dotEl = document.getElementById('dot-' + safeID);
	if (dotEl) {
		dotEl.className = 'domain-status-dot dot-ok dot-recent';
		setTimeout(() => { if (dotEl) dotEl.classList.remove('dot-recent'); }, 3600000);
	}
	const uptimeEl = document.getElementById('uptime-' + safeID);
	if (uptimeEl) uptimeEl.textContent = '0m';
	showToast(trf('domain_updated', { domain: data.domain }, '✓ {domain} updated'));
}

function _getVal(id) { const el = document.getElementById(id); return el ? el.value : ''; }
function _isChecked(id) { const el = document.getElementById(id); return el ? el.checked : false; }
function _parseList(raw) { return (raw || '').split(',').map(s => s.trim()).filter(Boolean); }
function _setVal(id, v) { const el = document.getElementById(id); if (!el || el === document.activeElement) return; el.value = v != null ? String(v) : ''; }
function _setChk(id, v) { const el = document.getElementById(id); if (!el || el === document.activeElement) return; el.checked = !!v; updateCheckboxLabel(el); }

function openSettings() {
	navTo('settings');
}

function _initSettingsFields() {
	isSettingsOpen = true;

	const saved = localStorage.getItem('triggerToken') || '';
	const inp = document.getElementById('s-token');
	if (inp) inp.placeholder = saved ? tr('token_saved_masked', '●●●●●● (gespeichert)') : tr('token_enter', 'Token eingeben...');

	const sys = (typeof initialSystem !== 'undefined' && initialSystem) ? initialSystem : {};
	const mqtt = sys.mqtt || {};
	const email = sys.email || {};
	_setVal('cfg-ip-mode', sys.ip_mode || 'BOTH');
	_setVal('cfg-interval', sys.interval || 300);
	_setVal('cfg-health-port', sys.health_port || '8080');
	_setVal('cfg-iface', sys.iface_name || '');
	_setVal('cfg-dns', (sys.dns_servers || []).join(', '));
	_setVal('cfg-max-log', sys.max_log_lines || 500);
	_setVal('cfg-max-retries', sys.max_api_retries || 3);
	_setVal('cfg-max-concurrent', sys.max_concurrent || 5);
	_setVal('cfg-hourly-limit', sys.hourly_rate_limit || 1200);
	_setVal('cfg-lang', sys.lang || 'de');
	_setChk('cfg-dry-run', sys.dry_run || false);
	_setChk('cfg-debug', sys.debug_enabled || false);
	_setChk('cfg-debug-http', sys.debug_http_raw || false);
	_setVal('cfg-ipv4_endpoints', (sys.ipv4_endpoints || []).join(', '));
	_setVal('cfg-ipv6_endpoints', (sys.ipv6_endpoints || []).join(', '));

	_setChk('cfg-notify-enabled', sys.notify_enabled || false);
	const activeEvents = new Set((sys.notify_events || []).map(e => e.toUpperCase()));
	document.querySelectorAll('input[name="notify-event"]').forEach(cb => {
		cb.checked = activeEvents.has(cb.value);
	});
	_setVal('cfg-tg-token', sys.telegram_token || '');
	_setVal('cfg-tg-chat-id', sys.telegram_chat_id || '');
	_setVal('cfg-gotify-url', sys.gotify_url || '');
	_setVal('cfg-gotify-token', sys.gotify_token || '');
	_setVal('cfg-webhook-url', sys.webhook_url || '');
	_setVal('cfg-webhook-secret', sys.webhook_secret || '');
	_setVal('cfg-mqtt-broker', mqtt.broker || '');
	_setVal('cfg-mqtt-clientid', mqtt.client_id || '');
	_setVal('cfg-mqtt-username', mqtt.username || '');
	_setVal('cfg-mqtt-password', mqtt.password || '');
	_setVal('cfg-mqtt-topic', mqtt.topic || '');
	_setVal('cfg-mqtt-qos', mqtt.qos ?? 0);
	_setChk('cfg-mqtt-retain', mqtt.retain || false);
	_setChk('cfg-mqtt-discovery', mqtt.discovery || false);
	_setVal('cfg-mqtt-discovery-prefix', mqtt.discovery_prefix || 'homeassistant');
	_setVal('cfg-email-host', email.host || '');
	_setVal('cfg-email-port', email.port || '');
	_setVal('cfg-email-user', email.username || '');
	_setVal('cfg-email-pass', email.password || '');
	_setVal('cfg-email-from', email.from || '');
	_setVal('cfg-email-to', email.to || '');
	_setVal('cfg-email-subject-prefix', email.subject_prefix || '');
	_setVal('cfg-email-tls-mode', email.tls_mode || 'starttls');

	renderSettingsDomainList();
}

function closeSettings() {
	isSettingsOpen = false;
}

function closeSettingsOutside(e) { /* noop - no modal */ }

function saveToken() {
	const val = (document.getElementById('s-token').value || '').trim();
	if (val) {
		localStorage.setItem('triggerToken', val);
		document.getElementById('s-token').value = '';
		document.getElementById('s-token').placeholder = tr('token_saved_masked', '●●●●●● (gespeichert)');
		showToast(tr('token_saved', '✅ Token gespeichert'), 'success');
	} else {
		localStorage.removeItem('triggerToken');
		document.getElementById('s-token').placeholder = tr('token_enter', 'Token eingeben...');
		showToast(tr('token_deleted', '🗑️ Token gelöscht'), 'info');
	}
}

function renderSettingsDomainList() {
	const container = document.getElementById('settings-domain-list');
	if (!container) return;
	container.innerHTML = '';

	const sorted = [...tempDomainConfigs].sort((a, b) => {
		if (a.provider !== b.provider) return a.provider.localeCompare(b.provider);
		return a.fqdn.localeCompare(b.fqdn);
	});

	sorted.forEach((d) => {
		const origIndex = tempDomainConfigs.indexOf(d);
		const providerColor = { IONOS: '#3b82f6', CLOUDFLARE: '#f97316', IPV64: '#a855f7', HETZNER: '#14b8a6', HETZNERCLOUD: '#06b6d4' }[d.provider] || '#64748b';
		const div = document.createElement('div');
		div.className = 'domain-pill';
		div.innerHTML =
			'<div class="domain-pill-info">' +
			'<span class="domain-pill-fqdn">' + escHtml(d.fqdn) + '</span>' +
			'<span class="provider-badge" style="background:' + providerColor + '20;color:' + providerColor + ';border:1px solid ' + providerColor + '40;margin-left:6px;">' + escHtml(d.provider) + '</span>' +
			(d.ttl ? '<span class="provider-badge" style="margin-left:6px;">TTL ' + escHtml(d.ttl) + '</span>' : '') +
			(d.ip_mode ? '<span class="provider-badge" style="margin-left:6px;">' + escHtml(d.ip_mode) + '</span>' : '') +
			(d.provider === 'CLOUDFLARE' && d.cf_proxied ? '<span class="provider-badge" style="margin-left:6px;">proxied</span>' : '') +
			'</div>' +
			'<div class="domain-pill-actions">' +
			'<button onclick="editDomain(' + origIndex + ')" class="domain-pill-edit-btn">✏️</button>' +
			'<button onclick="removeDomainFromList(' + origIndex + ')" class="domain-pill-remove-btn">✕</button>' +
			'</div>';
		container.appendChild(div);
	});
}

function escHtml(s) {
	return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function openAddDomainSection() {
	const section = document.getElementById('add-domain-section');
	if (!section) return;

	section.open = true;
	section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function resetDomainForm() {
	_setVal('new-domain-fqdn', '');
	_setVal('new-domain-ttl', '');
	_setVal('new-domain-ip-mode', '');
	_setVal('new-ionos-prefix', '');
	_setVal('new-ionos-secret', '');
	_setVal('new-cf-token', '');
	_setVal('new-cf-email', '');
	_setVal('new-cf-secret', '');
	_setVal('new-ipv64-token', '');
	_setVal('new-hetzner-token', '');
	_setVal('new-hcloud-token', '');
	_setChk('new-cf-proxied', false);

	const provSel = document.getElementById('new-domain-provider');
	if (provSel) provSel.value = 'IONOS';

	toggleProviderFields();
}

function editDomain(index) {
	const d = tempDomainConfigs[index];
	if (!d) return;

	editIndex = index;
	resetDomainForm();

	_setVal('new-domain-fqdn', d.fqdn || '');

	const provSel = document.getElementById('new-domain-provider');
	if (provSel) provSel.value = String(d.provider || '').toUpperCase() || 'IONOS';

	toggleProviderFields();

	_setVal('new-domain-ttl', d.ttl || '');

	_setVal('new-domain-ip-mode', d.ip_mode || '');

	if (d.provider === 'IONOS') {
		_setVal('new-ionos-prefix', d.api_prefix || '');
		_setVal('new-ionos-secret', d.api_secret || '');
	} else if (d.provider === 'CLOUDFLARE') {
		_setVal('new-cf-token', d.cf_token || '');
		_setVal('new-cf-email', d.cf_email || '');
		_setVal('new-cf-secret', d.cf_secret || '');
		_setChk('new-cf-proxied', d.cf_proxied || false);
	} else if (d.provider === 'IPV64') {
		_setVal('new-ipv64-token', d.ipv64_token || '');
	} else if (d.provider === 'HETZNER') {
		_setVal('new-hetzner-token', d.api_secret || d.api_prefix || '');
	} else if (d.provider === 'HETZNERCLOUD') {
		_setVal('new-hcloud-token', d.api_secret || d.api_prefix || '');
	}

	renderSettingsDomainList();
	openAddDomainSection();
	const addBtn = document.querySelector('#add-domain-section button[onclick="addDomainToList()"]');
	if (addBtn) addBtn.textContent = tr('edit_domain_saved', 'Änderungen übernehmen');
	document.getElementById('new-domain-fqdn')?.focus();
}

function toggleProviderFields() {
	const p = document.getElementById('new-domain-provider').value;
	document.getElementById('fields-ionos').style.display = p === 'IONOS' ? 'block' : 'none';
	document.getElementById('fields-cloudflare').style.display = p === 'CLOUDFLARE' ? 'block' : 'none';
	document.getElementById('fields-ipv64').style.display = p === 'IPV64' ? 'block' : 'none';
	document.getElementById('fields-hetzner').style.display = p === 'HETZNER' ? 'block' : 'none';
	document.getElementById('fields-hetznercloud').style.display = p === 'HETZNERCLOUD' ? 'block' : 'none';
}

function addDomainToList() {
	const fqdn = document.getElementById('new-domain-fqdn').value.trim().toLowerCase();
	const provider = document.getElementById('new-domain-provider').value;
	const ttlRaw = _getVal('new-domain-ttl').trim();
	const ipMode = _getVal('new-domain-ip-mode').trim();
	const ttl = ttlRaw === '' ? 0 : parseInt(ttlRaw, 10);
	if (!fqdn) return showToast(tr('fqdn_missing', 'FQDN fehlt'), 'error');

	let entry = {
		fqdn: fqdn,
		provider: provider,
		ttl: Number.isFinite(ttl) && ttl > 0 ? ttl : 0,
		ip_mode: ipMode || ''
	};
	if (provider === 'IONOS') {
		entry.api_prefix = _getVal('new-ionos-prefix');
		entry.api_secret = _getVal('new-ionos-secret');
	} else if (provider === 'CLOUDFLARE') {
		entry.cf_token = _getVal('new-cf-token');
		entry.cf_email = _getVal('new-cf-email');
		entry.cf_secret = _getVal('new-cf-secret');
		entry.cf_proxied = document.getElementById('new-cf-proxied')?.checked || false;
	} else if (provider === 'IPV64') {
		entry.ipv64_token = _getVal('new-ipv64-token');
	} else if (provider === 'HETZNER') {
		entry.api_secret = _getVal('new-hetzner-token');
	} else if (provider === 'HETZNERCLOUD') {
		entry.api_secret = _getVal('new-hcloud-token');
	}

	if (editIndex !== null) {
		tempDomainConfigs[editIndex] = entry;
		editIndex = null;
	} else {
		tempDomainConfigs.push(entry);
	}

	renderSettingsDomainList();
	resetDomainForm();

	document.getElementById('new-domain-fqdn').value = '';
	[
		'new-domain-ttl',
		'new-ionos-prefix',
		'new-ionos-secret',
		'new-cf-token',
		'new-cf-email',
		'new-cf-secret',
		'new-ipv64-token',
		'new-hetzner-token',
		'new-hcloud-token',
	].forEach(id => _setVal(id, ''));

	_setChk('new-cf-proxied', false);
	const addBtn = document.querySelector('#add-domain-section button[onclick="addDomainToList()"]');
	if (addBtn) addBtn.textContent = tr('settings_add_btn', 'Hinzufügen');
}

function cancelEdit() {
	editIndex = null;
	resetDomainForm();
	const addBtn = document.querySelector('#add-domain-section button[onclick="addDomainToList()"]');
	if (addBtn) addBtn.textContent = tr('settings_add_btn', 'Hinzufügen');
	const section = document.getElementById('add-domain-section');
	if (section) section.open = false;
	showToast(tr('edit_domain_cancelled', 'Edit cancelled'), 'info');
}

function removeDomainFromList(index) {
	tempDomainConfigs.splice(index, 1);
	renderSettingsDomainList();
}

async function refreshDashboardLogs() {
	const oldSection = document.querySelector('.page-section[data-section="logs"]');
	if (!oldSection) return;

	const activeFilter =
		oldSection.querySelector('.filter-btn.active[data-filter]')?.dataset.filter || 'all';

	try {
		const res = await fetch('/api/logs', {
			method: 'GET',
			cache: 'no-store',
			headers: {
				'Accept': 'application/json'
			}
		});

		if (!res.ok) {
			throw new Error('HTTP ' + res.status);
		}

		const data = await res.json();

		if (!data.html) return;

		oldSection.outerHTML = data.html;

		if (typeof filterLogs === 'function') {
			filterLogs(activeFilter);
		}
	} catch (err) {
		console.error('Logs reload failed:', err);
		if (typeof showToast === 'function') {
			showToast('❌ Logs konnten nicht neu geladen werden');
		}
	}
}

async function refreshDashboardDomains() {
	const oldSection = document.querySelector('.page-section[data-section="domains"]');
	if (!oldSection) return;

	const searchValue = document.getElementById('domainSearch')?.value || '';

	try {
		const res = await fetch('/api/domains/html', {
			method: 'GET',
			cache: 'no-store',
			headers: {
				'Accept': 'application/json'
			}
		});

		if (!res.ok) {
			throw new Error('HTTP ' + res.status);
		}

		const data = await res.json();

		if (!data.html) return;

		oldSection.outerHTML = data.html;

		const searchInput = document.getElementById('domainSearch');
		if (searchInput && searchValue) {
			searchInput.value = searchValue;
			filterDomains(searchValue);
		}

		initDomainDetailsState();
		initIPTimelines();
		initChangedBadges();
		initChartTooltips();
	} catch (err) {
		console.error('Domains reload failed:', err);
		if (typeof showToast === 'function') {
			showToast('❌ Domains konnten nicht neu geladen werden');
		}
	}
}

async function saveFullConfig() {
	if (!confirm(tr('save_config_confirm', 'Alle Einstellungen in config.json speichern?'))) return;

	const token = localStorage.getItem('triggerToken') || '';

	const notifyEvents = [...document.querySelectorAll('input[name="notify-event"]:checked')]
		.map(cb => cb.value);

	const system = {
		ip_mode: _getVal('cfg-ip-mode') || 'BOTH',
		interval: parseInt(_getVal('cfg-interval'), 10) || 300,
		health_port: _getVal('cfg-health-port') || '8080',
		iface_name: _getVal('cfg-iface'),
		dns_servers: _parseList(_getVal('cfg-dns')),
		max_log_lines: parseInt(_getVal('cfg-max-log'), 10) || 500,
		max_api_retries: parseInt(_getVal('cfg-max-retries'), 10) || 4,
		max_concurrent: parseInt(_getVal('cfg-max-concurrent'), 10) || 5,
		hourly_rate_limit: parseInt(_getVal('cfg-hourly-limit'), 10) || 1200,
		lang: _getVal('cfg-lang') || 'de',
		dry_run: _isChecked('cfg-dry-run'),
		debug_enabled: _isChecked('cfg-debug'),
		debug_http_raw: _isChecked('cfg-debug-http'),
		notify_enabled: _isChecked('cfg-notify-enabled'),
		notify_events: notifyEvents,
		telegram_token: _getVal('cfg-tg-token'),
		telegram_chat_id: _getVal('cfg-tg-chat-id'),
		gotify_url: _getVal('cfg-gotify-url'),
		gotify_token: _getVal('cfg-gotify-token'),
		webhook_url: _getVal('cfg-webhook-url'),
		webhook_secret: _getVal('cfg-webhook-secret'),
		mqtt: {
			broker: _getVal('cfg-mqtt-broker'),
			client_id: _getVal('cfg-mqtt-clientid'),
			username: _getVal('cfg-mqtt-username'),
			password: _getVal('cfg-mqtt-password'),
			topic: _getVal('cfg-mqtt-topic'),
			qos: parseInt(_getVal('cfg-mqtt-qos'), 10) || 0,
			retain: _isChecked('cfg-mqtt-retain'),
			discovery: _isChecked('cfg-mqtt-discovery'),
			discovery_prefix: _getVal('cfg-mqtt-discovery-prefix') || 'homeassistant'
		},
		email: {
			host: _getVal('cfg-email-host'),
			port: parseInt(_getVal('cfg-email-port'), 10) || 587,
			username: _getVal('cfg-email-user'),
			password: _getVal('cfg-email-pass'),
			from: _getVal('cfg-email-from'),
			to: _getVal('cfg-email-to'),
			subject_prefix: _getVal('cfg-email-subject-prefix'),
			tls_mode: _getVal('cfg-email-tls-mode') || 'starttls'
		},
		ipv4_endpoints: _parseList(_getVal('cfg-ipv4_endpoints')),
		ipv6_endpoints: _parseList(_getVal('cfg-ipv6_endpoints')),
	};

	showLoadingToast(tr('loading_saving', '⏳ Speichere Konfiguration...'));

	try {
		const r = await fetch('/api/save-config', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				...(token ? { 'X-Trigger-Token': token } : {})
			},
			body: JSON.stringify({ domain_configs: tempDomainConfigs, system })
		});

		if (!r.ok) {
			const txt = await r.text();
			showToast(tr('error_prefix', '❌ Error: ') + txt, 'error');
			return;
		}

		const newLang = _getVal('cfg-lang');
		if (newLang && newLang !== (initialSystem?.lang || 'de')) {
			await fetch('/api/set-language?lang=' + encodeURIComponent(newLang), {
				method: 'POST',
				headers: token ? { 'X-Trigger-Token': token } : {}
			});
		}

		showToast(tr('saved_reload', '✅ Gespeichert! Seite wird neu geladen...'), 'success');
		setTimeout(() => location.reload(), 1500);

	} catch (e) {
		showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error');
	} finally {
		hideLoadingToast();
	}
}

function resetMetrics() {
	if (!confirm(tr('reset_metrics_confirm', 'Möchtest du wirklich alle Metriken (Statistiken) löschen?'))) return;
	const token = localStorage.getItem('triggerToken') || '';
	fetch('/api/metrics/reset', {
		method: 'POST',
		headers: token ? { 'X-Trigger-Token': token } : {}
	})
		.then(r => {
			if (r.ok) { showToast(tr('metrics_reset_ok', '✅ Metriken zurückgesetzt'), 'success'); }
			else { showToast(tr('metrics_reset_failed', '❌ Reset fehlgeschlagen'), 'error'); }
		})
		.catch(() => showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error'));
}

function showNotifierTooltip(el, text) {
	const existing = document.getElementById('notifier-tooltip');
	if (existing && existing._source === el) return;
	if (existing) existing.remove();

	const tip = document.createElement('div');
	tip.id = 'notifier-tooltip';
	tip._source = el;
	tip.textContent = text;

	document.body.appendChild(tip);

	const rect = el.getBoundingClientRect();
	const tipW = tip.offsetWidth;
	let left = rect.left + rect.width / 2 - tipW / 2;
	if (left < 8) left = 8;
	if (left + tipW > window.innerWidth - 8) left = window.innerWidth - tipW - 8;
	tip.style.left = left + 'px';
	tip.style.top = (rect.bottom + 6) + 'px';

	const close = () => {
		tip.remove();
		document.removeEventListener('click', close);
	};

	setTimeout(() => document.addEventListener('click', close), 10);
	setTimeout(() => tip.remove(), 2500);
}

function copyLogEntry(btn) {
	const row = btn.closest('.log-entry-row');
	const text = row ? (row.dataset.copy || '') : '';
	if (!text) return;
	const fallback = (t) => {
		const ta = document.createElement('textarea');
		ta.value = t; ta.style.position = 'fixed'; ta.style.left = '-9999px';
		document.body.appendChild(ta); ta.focus(); ta.select();
		try { document.execCommand('copy'); showToast(tr('copied', '✓ Kopiert: ') + t.slice(0, 60)); }
		catch { showToast(tr('copy_failed', '❌ Copy failed'), 'error'); }
		document.body.removeChild(ta);
	};
	if (navigator.clipboard && window.isSecureContext) {
		navigator.clipboard.writeText(text)
			.then(() => showToast(tr('copied', '✓ Kopiert: ') + text.slice(0, 60)))
			.catch(() => fallback(text));
	} else fallback(text);
}

function exportLogs(format) {
	const rows = [...document.querySelectorAll('#logContainer .log-entry-row')]
		.filter(r => r.style.display !== 'none');

	if (rows.length === 0) {
		showToast(tr('no_log_entries', 'Keine Log-Einträge sichtbar'), 'warning');
		return;
	}

	const filename = 'dyndns-logs-' + new Date().toISOString().split('T')[0];

	if (format === 'txt') {
		const lines = rows.map(r => {
			const time = r.querySelector('.log-entry-time')?.textContent.trim() || '';
			const domain = r.querySelector('.log-entry-domain')?.textContent.trim() || '';
			const msg = r.querySelector('.log-entry-message')?.textContent.trim() || '';
			const action = r.dataset.action || '';
			return [time, action, domain, msg].filter(Boolean).join(' | ');
		});
		const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
		_downloadBlob(blob, filename + '.txt');
	} else {
		const entries = rows.map(r => ({
			time: r.querySelector('.log-entry-time')?.textContent.trim() || '',
			action: r.dataset.action || '',
			level: r.dataset.level || '',
			domain: r.querySelector('.log-entry-domain')?.textContent.trim() || '',
			message: r.querySelector('.log-entry-message')?.textContent.trim() || '',
		}));
		const blob = new Blob([JSON.stringify(entries, null, 2)], { type: 'application/json' });
		_downloadBlob(blob, filename + '.json');
	}
	showToast(tr('export_started', '✓ Export gestartet'), 'success');
}

function _downloadBlob(blob, filename) {
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url; a.download = filename;
	document.body.appendChild(a); a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
}

let _filterDomainsTimer = null;
function filterDomains(query) {
	if (_filterDomainsTimer) cancelAnimationFrame(_filterDomainsTimer);
	_filterDomainsTimer = requestAnimationFrame(() => {
		const container = document.getElementById('domainContainer');
		if (!container) return;
		const search = query.toLowerCase();
		container.querySelectorAll('.domain-item').forEach(d => {
			const name = (d.getAttribute('data-domain') || '').toLowerCase();
			d.classList.toggle('hidden', !name.includes(search));
		});
	});
}

function deleteDomain(domain, btn) {
	if (!confirm(trf('delete_domain_confirm', { domain }, 'Domain "{domain}" wirklich aus dem Status entfernen?'))) return;
	const token = localStorage.getItem('triggerToken') || '';
	btn.disabled = true;
	btn.textContent = '⏳';
	fetch('/api/domain/delete?domain=' + encodeURIComponent(domain), {
		method: 'POST',
		headers: token ? { 'X-Trigger-Token': token } : {}
	})
		.then(r => r.json().then(j => ({ status: r.status, json: j })))
		.then(({ status, json: j }) => {
			if (status === 200) {
				const card = btn.closest('.domain-item');
				if (card) { card.style.transition = 'opacity 0.4s'; card.style.opacity = '0'; setTimeout(() => card.remove(), 400); }
				showToast(trf('domain_removed', { domain }, '🗑️ {domain} entfernt'), 'success');
			} else {
				btn.disabled = false; btn.textContent = tr('remove_btn', '🗑️ Entfernen');
				showToast('❌ ' + (j.error || tr('delete_failed', 'Fehler beim Löschen')), 'error');
			}
		})
		.catch(() => { btn.disabled = false; btn.textContent = tr('remove_btn', '🗑️ Entfernen'); showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error'); });
}

// ============================================================================
// IPv64 DOMAIN MANAGEMENT
// ============================================================================
function _ipv64DomainAction(action) {
	const input = document.getElementById('ipv64-domain-input');
	const result = document.getElementById('ipv64-domain-result');
	const fqdn = (input ? input.value : '').trim().toLowerCase();
	const apiTokenInput = document.getElementById('ipv64-api-token-input');
	const apiToken = (apiTokenInput ? apiTokenInput.value : '').trim();

	if (!fqdn) {
		showToast('❌ FQDN fehlt', 'error');
		return;
	}

	const token = localStorage.getItem('triggerToken') || '';
	if (result) { result.style.display = 'none'; result.innerHTML = ''; }

	const label = action === 'add' ? 'Hinzufügen' : 'Löschen';
	showToast(`⏳ IPv64 Domain wird ${action === 'add' ? 'hinzugefügt' : 'gelöscht'}...`, 'info');

	fetch('/api/ipv64/domain', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			...(token ? { 'X-Trigger-Token': token } : {})
		},
		body: JSON.stringify({ action, fqdn, api_token: apiToken })
	})
		.then(r => r.json().then(j => ({ ok: r.ok, j })))
		.then(({ ok, j }) => {
			if (!ok) {
				const msg = '❌ ' + (j.error || 'Fehler');
				showToast(msg, 'error');
				if (result) {
					result.style.display = 'block';
					result.className = 'ipv64-result notify-result--error';
					result.innerHTML = msg;
				}
				return;
			}
			const icon = action === 'add' ? '✅' : '🗑️';
			const msg = `${icon} Domain <strong>${escHtml(j.fqdn)}</strong> ${j.status}`;
			showToast(`${icon} IPv64 Domain ${j.status}: ${j.fqdn}`, 'success');
			if (result) {
				result.style.display = 'block';
				result.className = 'ipv64-result notify-result--ok';
				result.innerHTML = msg;
			}
			if (input) input.value = '';
			if (apiTokenInput) apiTokenInput.value = '';
		})
		.catch(() => {
			showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error');
		});
}

function ipv64AddDomain() { _ipv64DomainAction('add'); }
function ipv64DeleteDomain() {
	const input = document.getElementById('ipv64-domain-input');
	const fqdn = (input ? input.value : '').trim();
	if (!fqdn) { showToast('❌ FQDN fehlt', 'error'); return; }
	if (!confirm(`IPv64 Domain "${fqdn}" wirklich löschen? Diese Aktion kann nicht rückgängig gemacht werden.`)) return;
	_ipv64DomainAction('delete');
}

function fallbackCopy(text) {
	const ta = document.createElement('textarea');
	ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px';
	document.body.appendChild(ta); ta.focus(); ta.select();
	try { document.execCommand('copy'); showToast('✓ Kopiert: ' + text, 'success'); }
	catch { showToast(tr('copy_failed', '❌ Copy failed'), 'error'); }
	document.body.removeChild(ta);
}

function startClock() {
	const el = document.getElementById('clock');
	if (!el) return;
	const tick = () => {
		const d = new Date();
		el.textContent = [d.getHours(), d.getMinutes(), d.getSeconds()]
			.map(n => String(n).padStart(2, '0')).join(':');
	};
	tick(); setInterval(tick, 1000);
}

function togglePassword(id, btn) {
	const input = document.getElementById(id);
	if (!input) return;

	if (input.type === "password") {
		input.type = "text";
		btn.textContent = "🙈";
	} else {
		input.type = "password";
		btn.textContent = "👁️";
	}
}

function updateCheckboxLabel(cb) {
	const labelSpan = cb.parentElement.querySelector('.s-checkbox-text');
	if (!labelSpan) return;
	const textOn = cb.getAttribute('data-label-on') || 'Aktiv';
	const textOff = cb.getAttribute('data-label-off') || 'Inaktiv';
	labelSpan.textContent = cb.checked ? textOn : textOff;
}

function appendDebugLog(entry) {
	const container = document.getElementById('debug-log-container');
	if (!container) return;

	if (
		container.children.length === 1 &&
		container.firstElementChild &&
		container.firstElementChild.classList.contains('debug-placeholder')
	) {
		container.innerHTML = '';
	}

	const line = document.createElement('div');
	line.style.cssText =
		'padding:2px 0; border-bottom:1px solid rgba(255,255,255,0.04); display:flex; gap:8px; align-items:baseline;';

	const appendSpan = (text, style) => {
		const span = document.createElement('span');
		if (style) span.style.cssText = style;
		span.textContent = text;
		line.appendChild(span);
		return span;
	};

	if (entry.timestamp) {
		appendSpan(entry.timestamp, 'color:#4b5563; white-space:nowrap;');
	}

	if (entry.icon) {
		appendSpan(entry.icon, '');
	}

	if (entry.category) {
		appendSpan(
			`[${entry.category}]`,
			'color:#64b5f6; min-width:80px;'
		);
	}

	if (entry.domain) {
		appendSpan(
			entry.domain,
			'color:#a78bfa;'
		);
	}

	appendSpan(
		entry.message || '',
		'color:#e2e8f0; word-break:break-word;'
	);

	line.dataset.text = `${entry.category || ''} ${entry.domain || ''} ${entry.message || ''}`.toLowerCase();

	container.appendChild(line);

	while (container.children.length > 500) {
		container.removeChild(container.firstChild);
	}

	const autoScroll = document.getElementById('debug-autoscroll');
	if (autoScroll && autoScroll.checked) {
		container.scrollTop = container.scrollHeight;
	}
}

function filterDebugLog(query) {
	const container = document.getElementById('debug-log-container');
	if (!container) return;
	const q = query.toLowerCase();
	for (const line of container.children) {
		line.style.display = (!q || (line.dataset.text || '').includes(q)) ? '' : 'none';
	}
}

function clearDebugLog() {
	const container = document.getElementById('debug-log-container');
	if (!container) return;

	container.innerHTML = '';

	const placeholder = document.createElement('span');
	placeholder.className = 'debug-placeholder';
	placeholder.style.opacity = '0.3';
	placeholder.textContent = tr('cleared', 'Cleared.');
	container.appendChild(placeholder);
}

// ============================================================================
// USER MANAGEMENT
// ============================================================================
function loadUsers() {
	fetch('/api/users')
		.then(r => {
			if (!r.ok) throw new Error('HTTP ' + r.status);
			return r.json();
		})
		.then(users => renderUsersList(users))
		.catch(err => {
			document.getElementById('users-list').innerHTML =
				'<div class="user-load-error">' + tr('user_load_failed', 'Fehler beim Laden') + '</div>';
			console.error(err);
		});
}

function renderUsersList(users) {
	const container = document.getElementById('users-list');
	if (!container) return;
	if (!users || users.length === 0) {
		container.innerHTML = '<div class="users-empty">' + tr('no_users_found', 'Keine Benutzer gefunden.') + '</div>';
		return;
	}

	const roleIcon = { admin: '👑', editor: '✏️', viewer: '👁️' };
	const roleLabel = { admin: tr('role_admin', 'Admin'), editor: tr('role_editor', 'Editor'), viewer: tr('role_viewer', 'Viewer') };

	container.innerHTML = users.map(u => `
		<div class="domain-pill">
			<div class="user-pill-info">
				<span class="user-pill-username">${escHtml(u.username)}</span>
				<span class="provider-badge user-role-badge">
					${roleIcon[u.role] || '?'} ${roleLabel[u.role] || u.role}
				</span>
				${u.last_login ? `<span class="user-last-login">Letzter Login: ${new Date(u.last_login).toLocaleString()}</span>` : ''}
			</div>
			<div class="domain-pill-actions">
				<select onchange="changeUserRole('${u.id}', this.value)" class="user-role-select">
					...
				</select>
				<button onclick="deleteUser('${u.id}', '${escHtml(u.username)}')" class="user-delete-btn">✕</button>
			</div>
		</div>`
	).join('');
}

function addUser() {
	const username = (document.getElementById('new-user-name')?.value || '').trim();
	const password = document.getElementById('new-user-pass')?.value || '';
	const role = document.getElementById('new-user-role')?.value || 'viewer';

	if (username.length < 3) return showToast(tr('auth_user_min', 'Benutzername min. 3 Zeichen'), 'error');
	if (password.length < 8) return showToast(tr('auth_pass_min', 'Passwort min. 8 Zeichen'), 'error');

	const token = localStorage.getItem('triggerToken') || '';
	fetch('/api/users', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Trigger-Token': token } : {}) },
		body: JSON.stringify({ username, password, role })
	})
		.then(r => r.json().then(j => ({ ok: r.ok, j })))
		.then(({ ok, j }) => {
			if (!ok) return showToast('❌ ' + (j.error || 'Fehler'), 'error');
			showToast('✅ ' + tr('user_created', 'Benutzer erstellt'), 'success');
			document.getElementById('new-user-name').value = '';
			document.getElementById('new-user-pass').value = '';
			loadUsers();
		})
		.catch(() => showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error'));
}

function changeUserRole(id, role) {
	const token = localStorage.getItem('triggerToken') || '';
	fetch('/api/users/' + id, {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Trigger-Token': token } : {}) },
		body: JSON.stringify({ role })
	})
		.then(r => r.json().then(j => ({ ok: r.ok, j })))
		.then(({ ok, j }) => {
			if (!ok) return showToast('❌ ' + (j.error || tr('generic_error', 'Fehler')), 'error');
			showToast('✅ ' + tr('role_changed', 'Rolle geändert'), 'success');
			loadUsers();
		})
		.catch(() => showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error'));
}

function deleteUser(id, username) {
	if (!confirm(`Benutzer "${username}" wirklich löschen?`)) return;
	const token = localStorage.getItem('triggerToken') || '';
	fetch('/api/users/' + id, {
		method: 'DELETE',
		headers: token ? { 'X-Trigger-Token': token } : {}
	})
		.then(r => r.json().then(j => ({ ok: r.ok, j })))
		.then(({ ok, j }) => {
			if (!ok) return showToast('❌ ' + (j.error || tr('generic_error', 'Fehler')), 'error');
			showToast('🗑️ ' + tr('user_deleted', 'Benutzer gelöscht'), 'success');
			loadUsers();
		})
		.catch(() => showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error'));
}

function tr(key, fallback = '') {
	const dict = (typeof window !== 'undefined' && window.I18N) ? window.I18N : {};
	const val = dict[key];
	return (typeof val === 'string' && val.trim() !== '') ? val : fallback;
}

function trf(key, vars = {}, fallback = '') {
	let text = tr(key, fallback);
	for (const [k, v] of Object.entries(vars)) {
		text = text.replaceAll('{' + k + '}', String(v));
	}
	return text;
}

const endpointStatus = {};
function updateEndpointStatus(data) {
	endpointStatus[data.url] = { ok: data.ok, ts: Date.now() };
	renderEndpointStatus();
}

function renderEndpointStatus() {
	const el = document.getElementById('endpoint-status');
	if (!el) return;
	const entries = Object.entries(endpointStatus);
	if (entries.length === 0) return;
	el.innerHTML = entries.map(([url, s]) => {
		let host;
		try { host = new URL(url).hostname; } catch { host = url; }
		const icon = s.ok ? '✅' : '❌';
		const diff = Date.now() - s.ts;
		let ageStr;
		if (diff < 1000) {
			ageStr = diff + 'ms';
		} else if (diff < 60000) {
			ageStr = (diff / 1000).toFixed(0) + 's';
		} else {
			ageStr = Math.round(diff / 60000) + 'm';
		}
		return `<span class="endpoint-chip">${icon} ${host} <span class="endpoint-chip-age">${ageStr}</span></span>`;
	}).join('');
}

function showLoadingToast(text = '⏳ Speichere...') {
	let el = document.getElementById('loading-toast');
	if (!el) {
		el = document.createElement('div');
		el.id = 'loading-toast';

		el.innerHTML = `
			<div id="loading-text">${text}</div>
			<div class="loading-toast-track">
        		<div id="loading-bar"></div>
			</div>
		`;

		document.body.appendChild(el);
	} else {
		el.style.display = 'block';
		document.getElementById('loading-text').textContent = text;
	}
	el._timeout = setTimeout(() => {
		const txt = document.getElementById('loading-text');
		if (txt) txt.textContent = tr('loading_slow', '⚠️ Dauert länger als erwartet...');
	}, 5000);
}

function hideLoadingToast() {
	const el = document.getElementById('loading-toast');
	if (!el) return;

	clearTimeout(el._timeout);
	el.style.display = 'none';
}
// ============================================================================
// ANIMATED BACKGROUND — sky/sun/moon init (mirrors auth page)
// ============================================================================
(function () {
	const sun = document.querySelector('.auth-sun');
	if (!sun) return;

	const now = new Date();
	const h = now.getHours();
	const minutes = h * 60 + now.getMinutes();
	const root = document.documentElement;

	let vars;
	if (h >= 5 && h < 11) {
		vars = {
			'--sky-1': '#9be7ff', '--sky-2': '#5b7cff', '--floor': '#172554',
			'--sun-core': 'rgba(255,230,120,0.95)', '--sun-glow': 'rgba(255,184,77,0.55)',
			'--grid-color': 'rgba(34,211,238,0.36)', '--horizon': 'rgba(56,189,248,0.75)',
			'--mountain': '#172554', '--mountain-dark': '#0f172a'
		};
	} else if (h >= 11 && h < 17) {
		vars = {
			'--sky-1': '#60a5fa', '--sky-2': '#3730a3', '--floor': '#111827',
			'--sun-core': 'rgba(34,211,238,0.95)', '--sun-glow': 'rgba(59,130,246,0.65)',
			'--grid-color': 'rgba(125,211,252,0.36)', '--horizon': 'rgba(59,130,246,0.8)',
			'--mountain': '#1e1b4b', '--mountain-dark': '#020617'
		};
	} else if (h >= 17 && h < 21) {
		vars = {
			'--sky-1': '#312e81', '--sky-2': '#db2777', '--floor': '#020617',
			'--sun-core': 'rgba(251,191,36,0.98)', '--sun-glow': 'rgba(236,72,153,0.7)',
			'--grid-color': 'rgba(244,114,182,0.42)', '--horizon': 'rgba(236,72,153,0.9)',
			'--mountain': '#1e1b4b', '--mountain-dark': '#020617'
		};
	} else {
		vars = {
			'--sky-1': '#020617', '--sky-2': '#1e1b4b', '--floor': '#020617',
			'--sun-core': 'rgba(34,211,238,0.98)', '--sun-glow': 'rgba(168,85,247,0.75)',
			'--grid-color': 'rgba(34,211,238,0.46)', '--horizon': 'rgba(34,211,238,0.95)',
			'--mountain': '#0f172a', '--mountain-dark': '#020617'
		};
	}

	for (const k in vars) root.style.setProperty(k, vars[k]);

	const dayStart = 5 * 60, dayEnd = 21 * 60;
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

	root.style.setProperty('--sun-x', (12 + progress * 76) + '%');
	root.style.setProperty('--sun-y', (30 - Math.sin(progress * Math.PI) * 24) + '%');
})();

function formatUptime(lastChangedStr) {
	if (!lastChangedStr || lastChangedStr.trim() === '' || lastChangedStr === '0001-01-01 00:00:00') return '—';
	const parts = lastChangedStr.match(/(\d+)\.(\d+)\.(\d+) (\d+):(\d+):(\d+)/);
	if (!parts) return '—';
	const d = new Date(+parts[3], +parts[2] - 1, +parts[1], +parts[4], +parts[5], +parts[6]);
	if (isNaN(d.getTime()) || d.getFullYear() < 2020) return '—';
	const diff = Math.floor((Date.now() - d) / 1000);
	if (diff < 60) return diff + 's';
	if (diff < 3600) return Math.floor(diff / 60) + 'm';
	if (diff < 86400) return Math.floor(diff / 3600) + 'h ' + Math.floor((diff % 3600) / 60) + 'm';
	return Math.floor(diff / 86400) + 'd ' + Math.floor((diff % 86400) / 3600) + 'h';
}

function startUptimeClocks() {
	document.querySelectorAll('[data-last-changed]').forEach(el => {
		const id = el.dataset.uptimeId;
		const target = document.getElementById('uptime-' + id);
		if (!target) return;
		const update = () => target.textContent = formatUptime(el.dataset.lastChanged);
		update();
		setInterval(update, 30000);
	});
}

let _dotTooltip = null;
let _dotHideTimer = null;

function _getDotTooltip() {
	if (!_dotTooltip) {
		_dotTooltip = document.createElement('div');
		_dotTooltip.className = 'ip-dot-tooltip';
		document.body.appendChild(_dotTooltip);
	}
	return _dotTooltip;
}

function _showDotTooltip(dotEl, text) {
	if (_dotHideTimer) { clearTimeout(_dotHideTimer); _dotHideTimer = null; }
	const tip = _getDotTooltip();
	tip.textContent = text;
	tip.classList.add('visible');
	dotEl.classList.add('dot-active');
	requestAnimationFrame(() => {
		const r = dotEl.getBoundingClientRect();
		const margin = 10;
		const tipW = tip.offsetWidth || 200;
		const tipH = tip.offsetHeight || 52;
		let top = r.top - tipH - margin;
		let left = r.left + r.width / 2 - tipW / 2;
		if (top < margin) top = r.bottom + margin;
		left = Math.max(margin, Math.min(left, window.innerWidth - tipW - margin));
		tip.style.left = left + 'px';
		tip.style.top = top + 'px';
	});
}

function _hideDotTooltip(dotEl, delay) {
	if (delay > 0) {
		_dotHideTimer = setTimeout(() => {
			_getDotTooltip().classList.remove('visible');
			dotEl && dotEl.classList.remove('dot-active');
		}, delay);
	} else {
		_getDotTooltip().classList.remove('visible');
		dotEl && dotEl.classList.remove('dot-active');
	}
}

function _attachDotEvents(dotEl, text) {
	dotEl.addEventListener('mouseenter', () => _showDotTooltip(dotEl, text));
	dotEl.addEventListener('mouseleave', () => _hideDotTooltip(dotEl, 0));
	dotEl.addEventListener('touchstart', e => {
		e.stopPropagation();
		const tip = _getDotTooltip();
		if (tip.classList.contains('visible') && dotEl.classList.contains('dot-active')) {
			_hideDotTooltip(dotEl, 0);
		} else {
			_showDotTooltip(dotEl, text);
			_hideDotTooltip(dotEl, 3000);
		}
	}, { passive: true });
}

function buildIPTimeline(domainEl) {
	const raw = domainEl.dataset.ipHistory;
	if (!raw) return;

	let entries;
	try {
		entries = JSON.parse(raw);
	} catch {
		return;
	}

	if (!Array.isArray(entries) || entries.length < 2) return;

	const container = domainEl.querySelector('.ip-timeline-wrap');
	if (!container) return;

	const parseTime = e => {
		const p = String(e.time || '').match(
			/^(\d{1,2})\.(\d{1,2})\.(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/
		);
		if (!p) return NaN;
		return new Date(+p[3], +p[2] - 1, +p[1], +p[4], +p[5], +(p[6] || 0)).getTime();
	};

	const points = entries
		.map(e => ({ e, t: parseTime(e) }))
		.filter(p => Number.isFinite(p.t))
		.filter((p, i, arr) => {
			if (i === 0) return true;
			const prev = arr[i - 1].e;
			return p.e.ipv4 !== prev.ipv4 || p.e.ipv6 !== prev.ipv6;
		});

	if (points.length < 2) return;

	const pct = (_, i) => {
		const raw = (i / Math.max(1, points.length - 1)) * 100;
		return 2.5 + (raw / 100) * 95;
	};
	const wrap = document.createElement('div');
	wrap.className = 'ip-timeline';

	const line = document.createElement('div');
	line.className = 'ip-timeline-line';
	wrap.appendChild(line);

	points.forEach((p, i) => {
		const x = pct(p, i).toFixed(3);
		const color = p.e.ipv4 ? '#38bdf8' : '#a78bfa';
		const tooltipText = [
			p.e.time || '',
			p.e.ipv4 ? 'IPv4: ' + p.e.ipv4 : '',
			p.e.ipv6 ? 'IPv6: ' + p.e.ipv6 : '',
		].filter(Boolean).join('\n');

		const dot = document.createElement('span');
		dot.className = 'ip-timeline-dot';
		dot.style.cssText = `left:${x}%;--dot-color:${color};`;
		dot.title = tooltipText;
		_attachDotEvents(dot, tooltipText);
		wrap.appendChild(dot);
	});

	const last = points[points.length - 1];
	const lastX = pct(last, points.length - 1).toFixed(3);
	const label = (last.e.ipv4 || last.e.ipv6 || '').slice(-15);
	if (label) {
		const lbl = document.createElement('span');
		lbl.className = 'ip-timeline-label ip-timeline-label--last';
		lbl.style.left = lastX + '%';
		lbl.textContent = label;
		wrap.appendChild(lbl);
	}

	container.innerHTML = '';
	container.appendChild(wrap);
}

function initIPTimelines() {
	document.querySelectorAll('.domain-item[data-ip-history]').forEach(buildIPTimeline);
}

function initKeyboardShortcuts() {
	document.addEventListener('keydown', e => {
		if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;
		switch (e.key.toLowerCase()) {
			case 'r': triggerUpdate(); break;
			case 's': navTo('settings'); break;
			case 'd': navTo('dashboard'); break;
			case 'm': navTo('metrics'); break;
			case 'i': navTo('diagnose'); break;
			case 'l': navTo('logs'); break;
			case '?':
				showToast('⌨️ R=Update  S=Settings  D=Dashboard  M=Metrics  L=Logs I=Diagnose', 'info');
				break;
		}
	});
}

const _notifHistory = [];

function addToNotifCenter(message, type) {
	_notifHistory.unshift({ message, type, time: new Date().toLocaleTimeString() });
	if (_notifHistory.length > 20) _notifHistory.pop();
	const badge = document.getElementById('notif-badge');
	if (badge) { badge.textContent = _notifHistory.length; badge.style.display = 'inline'; }
}

function toggleNotifCenter() {
	const panel = document.getElementById('notif-panel');
	if (!panel) return;
	panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
	if (panel.style.display === 'block') renderNotifCenter();
}

function renderNotifCenter() {
	const list = document.getElementById('notif-list');
	if (!list) return;
	if (_notifHistory.length === 0) {
		list.innerHTML = '<div style="padding:10px;opacity:0.4;font-size:0.8rem;">Keine Ereignisse</div>';
		return;
	}
	list.innerHTML = _notifHistory.map(n => {
		const color = n.type === 'error' ? 'var(--error)' : n.type === 'warning' ? 'var(--warning)' : 'var(--success)';
		return `<div style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;">
            <span style="color:${color};margin-right:6px;">●</span>${n.message}
            <span style="float:right;opacity:0.4;">${n.time}</span>
        </div>`;
	}).join('');
}

function initChangedBadges() {
	document.querySelectorAll('.changed-badge[data-changed-at]').forEach(badge => {
		const raw = badge.dataset.changedAt;
		const parts = raw.match(/(\d+)\.(\d+)\.(\d+) (\d+):(\d+):(\d+)/);
		if (!parts) return;
		const d = new Date(parts[3], parts[2] - 1, parts[1], parts[4], parts[5], parts[6]);
		const ageMs = Date.now() - d.getTime();
		if (ageMs < 15 * 60 * 1000) {
			badge.classList.remove('changed-badge--hidden');
			setTimeout(() => badge.classList.add('changed-badge--hidden'), 15 * 60 * 1000 - ageMs);
		} else {
			badge.classList.add('changed-badge--hidden');
		}
	});
}

// ============================================================================
// DIAGNOSE / HEALTH CENTER
// ============================================================================

async function refreshDiagnosis() {
	const box = document.getElementById('diagnose-content');
	if (!box) return;

	box.innerHTML = '<div class="diag-loading">⏳ ' + escHtml(tr('diagnose_loading', 'Loading diagnosis...')) + '</div>';

	try {
		const r = await fetch('/api/diagnose');
		const data = await r.json();

		if (!r.ok) {
			box.innerHTML = '<div class="diag-error-box">❌ ' + escHtml(data.error || tr('diagnose_load_failed', 'Diagnosis failed')) + '</div>';
			return;
		}

		renderDiagnosis(data);
	} catch (err) {
		box.innerHTML = '<div class="diag-error-box">❌ ' + escHtml(tr('diagnose_connection_failed', 'Connection failed')) + '</div>';
	}
}

function diagStatusLabel(status) {
	const key = 'diagnose_status_' + String(status || 'unknown').toLowerCase();
	const fallback = status || 'unknown';
	return tr(key, fallback);
}

function diagStatusIcon(status) {
	if (status === 'healthy') return '✅';
	if (status === 'degraded') return '⚠️';
	if (status === 'starting') return '⏳';
	return '❌';
}

function diagStatusClass(status) {
	if (status === 'healthy') return 'diag-ok';
	if (status === 'degraded' || status === 'starting') return 'diag-warn';
	return 'diag-bad';
}

function yesNo(v) {
	return v ? tr('diagnose_yes', 'Yes') : tr('diagnose_no', 'No');
}

function renderBoolBadge(label, value) {
	return '<span class="diag-badge ' + (value ? 'diag-ok' : 'diag-muted') + '">' +
		escHtml(label) + ': ' + yesNo(value) +
		'</span>';
}

function renderDiagnosis(d) {
	const box = document.getElementById('diagnose-content');
	if (!box) return;

	const providerRows = Object.entries(d.provider_counts || {})
		.map(([k, v]) => '<div class="diag-row"><span>' + escHtml(k) + '</span><strong>' + escHtml(v) + '</strong></div>')
		.join('') || '<div class="diag-muted-text">' + escHtml(tr('diagnose_no_providers', 'No providers found')) + '</div>';

	const warningRows = (d.warnings || [])
		.map(w => '<div class="diag-warning">⚠️ ' + escHtml(w) + '</div>')
		.join('') || '<div class="diag-success-line">✅ ' + escHtml(tr('diagnose_no_config_warnings', 'No config warnings')) + '</div>';

	const files = (d.files || [])
		.map(f => {
			const ok = f.exists;
			const fileMeta = ok
				? escHtml((f.size || 0) + ' ' + tr('diagnose_bytes', 'bytes') + ' · ' + (f.modified || ''))
				: escHtml(f.error || tr('diagnose_file_missing', 'missing'));

			return '<div class="diag-row">' +
				'<span>' + (ok ? '✅ ' : '❌ ') + escHtml(f.name) + '</span>' +
				'<small>' + fileMeta + '</small>' +
				'</div>';
		})
		.join('');

	const notifiers = Object.entries(d.notifiers || {})
		.map(([k, v]) => renderBoolBadge(k, v))
		.join(' ');

	const metrics = d.api_metrics || {};
	const cfg = d.config || {};

	box.innerHTML = `
		<div class="diag-status-card ${diagStatusClass(d.status)}">
			<div class="diag-status-icon">${diagStatusIcon(d.status)}</div>
			<div>
				<div class="diag-status-title">${escHtml(diagStatusLabel(d.status))}</div>
				<div class="diag-status-reason">${escHtml(d.reason || '')}</div>
			</div>
		</div>

		<div class="diag-grid">
			<div class="diag-card">
				<h3>${escHtml(tr('diagnose_system_title', 'System'))}</h3>
				<div class="diag-row"><span>${escHtml(tr('diagnose_uptime', 'Uptime'))}</span><strong>${escHtml(d.uptime || '-')}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_scheduler_ran', 'Scheduler ran'))}</span><strong>${yesNo(d.scheduler_ran_once)}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_last_run_ok', 'Last run OK'))}</span><strong>${yesNo(d.last_ok)}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_update_running', 'Update running'))}</span><strong>${yesNo(d.update_in_progress)}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_active_updates', 'Active updates'))}</span><strong>${escHtml(d.active_updates ?? 0)}</strong></div>
			</div>

			<div class="diag-card">
				<h3>${escHtml(tr('diagnose_ip_dns_title', 'IP / DNS'))}</h3>
				<div class="diag-row"><span>${escHtml(tr('diagnose_last_ipv4', 'Last IPv4'))}</span><code>${escHtml(d.last_known_ipv4 || '-')}</code></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_last_ipv6', 'Last IPv6'))}</span><code>${escHtml(d.last_known_ipv6 || '-')}</code></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_last_domain_change', 'Last domain change'))}</span><strong>${escHtml(d.last_domain_change || '-')}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_configured_domains', 'Domains in status'))}</span><strong>${escHtml(d.configured_domains ?? 0)}</strong></div>
			</div>

			<div class="diag-card">
				<h3>${escHtml(tr('diagnose_api_metrics_title', 'API metrics'))}</h3>
				<div class="diag-row"><span>${escHtml(tr('diagnose_total_requests', 'Total requests'))}</span><strong>${escHtml(metrics.total_requests ?? 0)}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_success_rate', 'Success rate'))}</span><strong>${escHtml(metrics.success_rate || '-')}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_average_latency', 'Average latency'))}</span><strong>${escHtml(metrics.avg_latency || '-')}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_log_errors', 'Log errors'))}</span><strong>${escHtml(d.log_errors ?? 0)}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_log_warnings', 'Log warnings'))}</span><strong>${escHtml(d.log_warnings ?? 0)}</strong></div>
			</div>

			<div class="diag-card">
				<h3>${escHtml(tr('diagnose_config_title', 'Config'))}</h3>
				<div class="diag-row"><span>${escHtml(tr('diagnose_ip_mode', 'IP mode'))}</span><strong>${escHtml(cfg.ip_mode || '-')}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_interval', 'Interval'))}</span><strong>${escHtml(cfg.interval || '-')}s</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_ipv4_endpoints', 'IPv4 endpoints'))}</span><strong>${escHtml(cfg.ipv4_endpoints ?? 0)}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_ipv6_endpoints', 'IPv6 endpoints'))}</span><strong>${escHtml(cfg.ipv6_endpoints ?? 0)}</strong></div>
				<div class="diag-badge-row">
					${renderBoolBadge('Dry Run', cfg.dry_run)}
					${renderBoolBadge('Debug', cfg.debug)}
					${renderBoolBadge('HTTP Raw', cfg.debug_http_raw)}
				</div>
			</div>

			<div class="diag-card">
				<h3>${escHtml(tr('diagnose_provider_title', 'Provider'))}</h3>
				${providerRows}
			</div>

			<div class="diag-card">
				<h3>${escHtml(tr('diagnose_notifier_title', 'Notifier'))}</h3>
				<div class="diag-badge-row">${notifiers || '<span class="diag-muted-text">' + escHtml(tr('diagnose_no_notifiers', 'No notifiers')) + '</span>'}</div>
			</div>

			<div class="diag-card diag-card-wide">
				<h3>${escHtml(tr('diagnose_warnings_title', 'Warnings'))}</h3>
				${warningRows}
			</div>

			<div class="diag-card diag-card-wide">
				<h3>${escHtml(tr('diagnose_files_title', 'Files'))}</h3>
				${files}
			</div>
		</div>
	`;
}

// ============================================================================
// BACKUP & RESTORE
// ============================================================================

function downloadFullBackup() {
	fetch('/api/backup/download')
		.then(async r => {
			if (!r.ok) throw new Error(await r.text());
			return r.blob();
		})
		.then(blob => {
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = 'dyndns-backup-' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19) + '.json';
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
			showToast(tr('backup_download_success', '✅ Backup downloaded'), 'success');
		})
		.catch(err => {
			console.error(err);
			showToast(tr('backup_download_failed', '❌ Backup failed'), 'error');
		});
}

function restoreFullBackup() {
	const fileInput = document.getElementById('backup-file');
	const result = document.getElementById('backup-result');

	if (!fileInput || !fileInput.files || !fileInput.files[0]) {
		showToast(tr('backup_select_file', '❌ Please select a backup file'), 'error');
		return;
	}

	const restoreConfig = document.getElementById('restore-config')?.checked;
	const restoreStatus = document.getElementById('restore-status')?.checked;
	const restoreUsers = document.getElementById('restore-users')?.checked;

	if (!restoreConfig && !restoreStatus && !restoreUsers) {
		showToast(tr('backup_select_area', '❌ Please select at least one area'), 'error');
		return;
	}

	const msg = [
		tr('backup_confirm_title', 'Really restore backup?'),
		'',
		restoreConfig ? tr('backup_confirm_config', '• Config will be overwritten') : '',
		restoreStatus ? tr('backup_confirm_status', '• Domain status will be overwritten') : '',
		restoreUsers ? tr('backup_confirm_users', '• Users will be overwritten') : '',
		'',
		tr('backup_confirm_hint', 'This action may replace existing data.')
	].filter(Boolean).join('\n');

	if (!confirm(msg)) return;

	const fd = new FormData();
	fd.append('backup', fileInput.files[0]);
	fd.append('config', restoreConfig ? '1' : '0');
	fd.append('status', restoreStatus ? '1' : '0');
	fd.append('users', restoreUsers ? '1' : '0');

	if (result) {
		result.style.display = 'block';
		result.className = 'backup-result';
		result.textContent = tr('backup_restore_running', '⏳ Restore running...');
	}

	fetch('/api/backup/restore', {
		method: 'POST',
		body: fd
	})
		.then(async r => {
			const data = await r.json().catch(() => ({}));
			if (!r.ok) throw new Error(data.error || tr('backup_restore_failed', '❌ Restore failed'));
			return data;
		})
		.then(data => {
			const restored = (data.restored || []).join(', ');
			const successText = trf('backup_restore_success_format', { restored }, '✅ Restored: {restored}');

			if (result) {
				result.className = 'backup-result backup-result-ok';
				result.textContent = successText;
			}

			showToast(successText, 'success');

			setTimeout(() => location.reload(), 1200);
		})
		.catch(err => {
			if (result) {
				result.className = 'backup-result backup-result-error';
				result.textContent = '❌ ' + err.message;
			}
			showToast(tr('backup_restore_failed', '❌ Restore failed'), 'error');
		});
}