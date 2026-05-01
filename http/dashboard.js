let blinkTimer = null;
let currentLevel = 'ok';
let ws = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
const reconnectDelayMax = 10000;

let tempDomainConfigs = [];

if (typeof initialConfig !== 'undefined' && initialConfig !== null) {
	tempDomainConfigs = (Array.isArray(initialConfig) ? initialConfig : []).map(d => ({...d}));
}

document.addEventListener('DOMContentLoaded', () => {
   if (!localStorage.getItem('theme')) {
       localStorage.setItem('theme',
           window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
       );
   }
   const savedTheme = localStorage.getItem('theme');
	document.documentElement.setAttribute('data-theme', savedTheme);

	renderSettingsDomainList();

	const initialMetrics = {
		avg_latency: (document.getElementById('mLatency')?.textContent || '').trim(),
		success_rate: (document.getElementById('mSuccess')?.textContent || '').trim(),
		total_requests: (document.getElementById('mTotal')?.textContent || '0').trim(),
	};
	currentLevel = calcLevelFromMetrics(initialMetrics);
	applyFavicon(savedTheme, currentLevel, false);
	setBlinking(savedTheme, currentLevel);

	document.querySelectorAll('details.card').forEach(details => {
		const id = details.id;
		const saved = id ? localStorage.getItem('collapse-' + id) : null;
		if (saved === 'open') details.setAttribute('open', '');
		else if (saved === 'closed') details.removeAttribute('open');
		
		if (id) {
			details.addEventListener('toggle', () => {
				localStorage.setItem('collapse-' + id, details.open ? 'open' : 'closed');
			});
		}
	});
	document.addEventListener('visibilitychange', () => {
		if (document.visibilityState === 'visible') {
			if (!ws || ws.readyState === WebSocket.CLOSED) {
				reconnectDelay = 1000;
				connectWS();
			}
		}
	});
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

function calcLevelFromMetrics(m) {
	const total = toNum(m.total_requests, 0);
	const successRate = toNum(m.success_rate, 100);
	const successAge = toNum(m.last_success_age_secs, -1);
	const errorAge   = toNum(m.last_error_age_secs,   -1);
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

function updateMetrics(m) {
	const setTxt = (id, val) => { const el = document.getElementById(id); if(el) el.textContent = val; };
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
	if (days > 0)     uptime = days + 'd ' + h + 'h ' + min + 'm';
	else if (h > 0)   uptime = h + 'h ' + min + 'm';
	else if (min > 0) uptime = min + 'm ' + s + 's';
	else              uptime = s + 's';
	setTxt('uptime', uptime);
}

function connectWS() {
	const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
	ws = new WebSocket(proto + location.host + '/ws');
	ws.onmessage = (e) => {
		let msg;
     try { msg = JSON.parse(e.data); } catch { return; }
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
	};
	ws.onclose = () => scheduleReconnect();
	ws.onopen = () => { reconnectDelay = 1000; if(reconnectTimer) clearTimeout(reconnectTimer); };
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
	if(type === 'error') { borderColor = 'var(--error)'; duration = 5000; }
	else if(type === 'warning') { borderColor = '#facc15'; duration = 4000; }
	else if(type === 'info') { borderColor = '#3b82f6'; duration = 2500; }
	toast.style.borderLeft = '4px solid ' + borderColor;
  toast.classList.add('show');
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
		try { document.execCommand('copy'); showToast(tr('copied', '✓ Copied: ') + text);} 
		catch (err) { showToast(tr('copy_error', '❌ Fehler'), 'error'); }
		document.body.removeChild(ta);
	};
	if (navigator.clipboard && window.isSecureContext) {
		navigator.clipboard.writeText(text).then(() => showToast(tr('copied', '✓ Copied: ') + text)).catch(() => fallback(text));
	} else fallback(text);
}

function filterLogs(filter) {
	document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.filter === filter));
	document.querySelectorAll('.log-entry').forEach(entry => {
		const action = (entry.dataset.action || '').toUpperCase();
		const level = (entry.dataset.level || '').toUpperCase();
		if (filter === 'all') { entry.style.display = ''; return; }
		const shouldShow = (filter.toUpperCase() === 'ERR' && level === 'ERR') || 
							(filter.toUpperCase() === 'WARN' && level === 'WARN') || 
							(action === filter.toUpperCase());
		entry.style.display = shouldShow ? '' : 'none';
	});
}

function triggerUpdate() {
  const btn = document.getElementById('update-button');
  const token = localStorage.getItem('triggerToken') || '';
  if (btn) btn.disabled = true;
  showToast(tr('update_starting', '⏳ Update wird gestartet...'), 'info');
  fetch('/api/trigger', { 
    method: 'POST', 
    headers: token ? {'X-Trigger-Token': token} : {} 
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

function exportData() {
	fetch('/api/export').then(r => r.blob()).then(blob => {
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url; a.download = 'dyndns-export-' + new Date().toISOString().split('T')[0] + '.json';
		document.body.appendChild(a);
		a.click(); 
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
		showToast(tr('export_started', '✓ Export gestartet'));
	}).catch(() => showToast(tr('export_failed', 'Export fehlgeschlagen'), 'error'));
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
		setTimeout(() => { if(dotEl) dotEl.classList.remove('dot-recent'); }, 3600000);
	}
	showToast(trf('domain_updated', {domain: data.domain}, '✓ {domain} updated'));
}

function _getVal(id) { const el = document.getElementById(id); return el ? el.value : ''; }
function _setVal(id, v) { const el = document.getElementById(id); if (el) el.value = v != null ? String(v) : ''; }
function _setChk(id, v) {
    const el = document.getElementById(id);
    if (!el) return;
    el.checked = !!v;
    updateCheckboxLabel(el);
}

function openSettings() {
	document.getElementById('settingsOverlay').classList.add('open');

	const saved = localStorage.getItem('triggerToken') || '';
	const inp = document.getElementById('s-token');
	if (inp) inp.placeholder = saved ? tr('token_saved_masked', '●●●●●● (gespeichert)') : tr('token_enter', 'Token eingeben...');

	const sys = (typeof initialSystem !== 'undefined' && initialSystem) ? initialSystem : {};
	const mqtt = sys.mqtt || {};
	_setVal('cfg-ip-mode',        sys.ip_mode           || 'BOTH');
	_setVal('cfg-interval',       sys.interval          || 300);
	_setVal('cfg-health-port',    sys.health_port       || '8080');
	_setVal('cfg-iface',          sys.iface_name        || '');
	_setVal('cfg-dns',            (sys.dns_servers 		|| []).join(', '));
	_setVal('cfg-max-log',        sys.max_log_lines     || 500);
	_setVal('cfg-max-retries',    sys.max_api_retries   || 3);
	_setVal('cfg-max-concurrent', sys.max_concurrent    || 5);
	_setVal('cfg-hourly-limit',   sys.hourly_rate_limit || 1200);
	_setVal('cfg-lang',           sys.lang              || 'de');
	_setChk('cfg-dry-run',        sys.dry_run           || false);
	_setChk('cfg-debug',       	  sys.debug_enabled     || false);
	_setChk('cfg-debug-http',  	  sys.debug_http_raw    || false);
	_setVal('cfg-ipv4_endpoints', (sys.ipv4_endpoints 	|| []).join(', '));
	_setVal('cfg-ipv6_endpoints', (sys.ipv6_endpoints 	|| []).join(', '));

	// Notifications
	_setChk('cfg-notify-enabled',  sys.notify_enabled   || false);
	const activeEvents = new Set((sys.notify_events || []).map(e => e.toUpperCase()));
  	document.querySelectorAll('input[name="notify-event"]').forEach(cb => {
      cb.checked = activeEvents.has(cb.value);
  	});
	_setVal('cfg-tg-token',        	sys.telegram_token   	|| '');
	_setVal('cfg-tg-chat-id',       	sys.telegram_chat_id 	|| '');
	_setVal('cfg-gotify-url',      	sys.gotify_url        	|| '');
	_setVal('cfg-gotify-token',    	sys.gotify_token      	|| '');
	_setVal('cfg-webhook-url',    	sys.webhook_url    		|| '');
	_setVal('cfg-webhook-secret', 	sys.webhook_secret 		|| '');
	_setVal('cfg-mqtt-broker',            mqtt.broker || '');
	_setVal('cfg-mqtt-clientid',          mqtt.client_id || '');
	_setVal('cfg-mqtt-username',          mqtt.username || '');
	_setVal('cfg-mqtt-password',          mqtt.password || '');
	_setVal('cfg-mqtt-topic',             mqtt.topic || '');
	_setVal('cfg-mqtt-qos',               mqtt.qos ?? 0);
	_setChk('cfg-mqtt-retain',            mqtt.retain || false);
	_setChk('cfg-mqtt-discovery',         mqtt.discovery || false);
	_setVal('cfg-mqtt-discovery-prefix',  mqtt.discovery_prefix || 'homeassistant');

	renderSettingsDomainList();
	loadUsers();
}

function closeSettings() { 
	const el = document.getElementById('settingsOverlay');
	if(el) el.classList.remove('open'); 
}

function closeSettingsOutside(e) { if (e.target.id === 'settingsOverlay') closeSettings(); }

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
	tempDomainConfigs.forEach((d, index) => {
		const providerColor = {IONOS:'#3b82f6', CLOUDFLARE:'#f97316', IPV64:'#a855f7'}[d.provider] || '#64748b';
		const div = document.createElement('div');
		div.className = 'domain-pill';
		div.innerHTML =
			'<div style="flex:1;min-width:0;">' +
				'<span style="font-weight:600;word-break:break-all;">' + escHtml(d.fqdn) + '</span>' +
				'<span class="provider-badge" style="background:' + providerColor + '20;color:' + providerColor + ';border:1px solid ' + providerColor + '40;margin-left:6px;">' + escHtml(d.provider) + '</span>' +
				(d.ttl ? '<span class="provider-badge" style="margin-left:6px;">TTL ' + escHtml(d.ttl) + '</span>' : '') +
				(d.provider === 'CLOUDFLARE' && d.cf_proxied ? '<span class="provider-badge" style="margin-left:6px;">proxied</span>' : '') +
			'</div>' +
			'<div style="display:flex;gap:6px;flex-shrink:0;">' +
				'<button onclick="editDomain(' + index + ')" style="background:none;border:1px solid var(--border);color:var(--text);border-radius:5px;padding:3px 8px;cursor:pointer;font-size:0.75rem;">✏️</button>' +
				'<button onclick="removeDomainFromList(' + index + ')" style="background:none;border:none;color:var(--error);cursor:pointer;font-weight:bold;font-size:1rem;padding:0 4px;">✕</button>' +
			'</div>';
		container.appendChild(div);
	});
}

function escHtml(s) {
	return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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
	_setVal('new-ionos-prefix', '');
	_setVal('new-ionos-secret', '');
	_setVal('new-cf-token', '');
	_setVal('new-cf-email', '');
	_setVal('new-cf-secret', '');
	_setVal('new-ipv64-token', '');
	_setChk('new-cf-proxied', false);

	const provSel = document.getElementById('new-domain-provider');
	if (provSel) provSel.value = 'IONOS';

	toggleProviderFields();
}

function editDomain(index) {
	const d = tempDomainConfigs[index];
	if (!d) return;

	resetDomainForm();

	_setVal('new-domain-fqdn', d.fqdn || '');

	const provSel = document.getElementById('new-domain-provider');
	if (provSel) provSel.value = String(d.provider || '').toUpperCase() || 'IONOS';

	toggleProviderFields();

	_setVal('new-domain-ttl', d.ttl || '');

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
	}

	tempDomainConfigs.splice(index, 1);
	renderSettingsDomainList();
	openAddDomainSection();

	document.getElementById('new-domain-fqdn')?.focus();
}

function toggleProviderFields() {
	const p = document.getElementById('new-domain-provider').value;
	document.getElementById('fields-ionos').style.display = p === 'IONOS' ? 'block' : 'none';
	document.getElementById('fields-cloudflare').style.display = p === 'CLOUDFLARE' ? 'block' : 'none';
	document.getElementById('fields-ipv64').style.display = p === 'IPV64' ? 'block' : 'none';
}

function addDomainToList() {
	const fqdn = document.getElementById('new-domain-fqdn').value.trim().toLowerCase();
	const provider = document.getElementById('new-domain-provider').value;
	const ttlRaw = _getVal('new-domain-ttl').trim();
	const ttl = ttlRaw === '' ? 0 : parseInt(ttlRaw, 10);
	if (!fqdn) return showToast(tr('fqdn_missing', 'FQDN fehlt'), 'error');

	let entry = {
		fqdn: fqdn,
		provider: provider,
		ttl: Number.isFinite(ttl) && ttl > 0 ? ttl : 0
	};
	if(provider === 'IONOS') {
		entry.api_prefix = _getVal('new-ionos-prefix');
		entry.api_secret = _getVal('new-ionos-secret');
	} else if(provider === 'CLOUDFLARE') {
		entry.cf_token  = _getVal('new-cf-token');
		entry.cf_email  = _getVal('new-cf-email');
		entry.cf_secret = _getVal('new-cf-secret');
		entry.cf_proxied = document.getElementById('new-cf-proxied')?.checked || false;
	} else if(provider === 'IPV64') {
		entry.ipv64_token = _getVal('new-ipv64-token');
	}
	tempDomainConfigs.push(entry);
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
	].forEach(id => _setVal(id,''));

	_setChk('new-cf-proxied', false);
}

function removeDomainFromList(index) {
	tempDomainConfigs.splice(index, 1);
	renderSettingsDomainList();
}

function parseList(raw) {
	return (raw || '')
		.split(',')
		.map(s => s.trim())
		.filter(Boolean);
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
		dns_servers: parseList(_getVal('cfg-dns')),
		max_log_lines: parseInt(_getVal('cfg-max-log'), 10) || 500,
		max_api_retries: parseInt(_getVal('cfg-max-retries'), 10) || 4,
		max_concurrent: parseInt(_getVal('cfg-max-concurrent'), 10) || 5,
		hourly_rate_limit: parseInt(_getVal('cfg-hourly-limit'), 10) || 1200,
		lang: _getVal('cfg-lang') || 'de',
		dry_run: document.getElementById('cfg-dry-run')?.checked || false,
		debug_enabled: document.getElementById('cfg-debug')?.checked || false,
		debug_http_raw: document.getElementById('cfg-debug-http')?.checked || false,
		notify_enabled: document.getElementById('cfg-notify-enabled')?.checked || false,
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
			retain: document.getElementById('cfg-mqtt-retain')?.checked || false,
			discovery: document.getElementById('cfg-mqtt-discovery')?.checked || false,
			discovery_prefix: _getVal('cfg-mqtt-discovery-prefix') || 'homeassistant'
		},
		ipv4_endpoints: parseList(_getVal('cfg-ipv4_endpoints')),
		ipv6_endpoints: parseList(_getVal('cfg-ipv6_endpoints')),
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
			showToast(tr('error_prefix', tr('connection_error', '❌ Verbindungsfehler')) + txt, 'error');
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
		headers: token ? {'X-Trigger-Token': token} : {}
	})
	.then(r => {
		if (r.ok) { showToast(tr('metrics_reset_ok', '✅ Metriken zurückgesetzt'), 'success'); }
		else { showToast(tr('metrics_reset_failed', '❌ Reset fehlgeschlagen'), 'error'); }
	})
	.catch(() => showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error'));
}

function showNotifierTooltip(el, text) {
	const existing = document.getElementById('notifier-tooltip');
	if (existing) existing.remove();
	if (existing && existing._source === el) return;

	const tip = document.createElement('div');
	tip.id = 'notifier-tooltip';
	tip._source = el;
	tip.textContent = text;
	tip.style.cssText = `
		position: fixed;
		background: var(--card);
		color: var(--text);
		border: 1px solid var(--border);
		padding: 5px 10px;
		border-radius: 6px;
		font-size: 0.78rem;
		font-family: system-ui, sans-serif;
		box-shadow: 0 4px 12px rgba(0,0,0,0.3);
		pointer-events: none;
		z-index: 9999;
		white-space: nowrap;
	`;
	document.body.appendChild(tip);

	const rect = el.getBoundingClientRect();
	const tipW = tip.offsetWidth;
	let left = rect.left + rect.width / 2 - tipW / 2;
	if (left < 8) left = 8;
	if (left + tipW > window.innerWidth - 8) left = window.innerWidth - tipW - 8;
	tip.style.left = left + 'px';
	tip.style.top = (rect.bottom + 6) + 'px';

	const close = () => { tip.remove(); document.removeEventListener('click', close); };
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
			time:   r.querySelector('.log-entry-time')?.textContent.trim() || '',
			action: r.dataset.action || '',
			level:  r.dataset.level || '',
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

function filterDomains(query) {
    const container = document.getElementById('domainContainer');
    if (!container) return;
    const search = query.toLowerCase();
    container.querySelectorAll('.domain-item').forEach(d => {
        const name = (d.getAttribute('data-domain') || '').toLowerCase();
        d.classList.toggle('hidden', !name.includes(search));
    });
}


function deleteDomain(domain, btn) {
	if (!confirm(trf('delete_domain_confirm', { domain }, 'Domain "{domain}" wirklich aus dem Status entfernen?'))) return;
	const token = localStorage.getItem('triggerToken') || '';
	btn.disabled = true;
	btn.textContent = '⏳';
	fetch('/api/domain/delete?domain=' + encodeURIComponent(domain), {
		method: 'POST',
		headers: token ? {'X-Trigger-Token': token} : {}
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
				'<div style="color:red;font-size:0.8rem;">' + tr('user_load_failed', 'Fehler beim Laden') + '</div>';
			console.error(err);
		});
}

function renderUsersList(users) {
	const container = document.getElementById('users-list');
	if (!container) return;
	if (!users || users.length === 0) {
		container.innerHTML = '<div style="font-size:0.8rem;opacity:0.5;">' + tr('no_users_found', 'Keine Benutzer gefunden.') + '</div>';
		return;
	}

	const roleIcon = { admin: '👑', editor: '✏️', viewer: '👁️' };
	const roleLabel = {admin: tr('role_admin', 'Admin'),editor: tr('role_editor', 'Editor'),viewer: tr('role_viewer', 'Viewer')};

	container.innerHTML = users.map(u => `
		<div class="domain-pill" style="margin-bottom:6px;">
			<div style="flex:1;min-width:0;">
				<span style="font-weight:600;">${escHtml(u.username)}</span>
				<span class="provider-badge" style="margin-left:6px;background:rgba(99,102,241,0.15);color:#818cf8;border:1px solid rgba(99,102,241,0.3);">
					${roleIcon[u.role] || '?'} ${roleLabel[u.role] || u.role}
				</span>
				${u.last_login ? `<span style="font-size:0.7rem;opacity:0.4;margin-left:6px;">Letzter Login: ${new Date(u.last_login).toLocaleString()}</span>` : ''}
			</div>
			<div style="display:flex;gap:6px;flex-shrink:0;">
				<select onchange="changeUserRole('${u.id}', this.value)"
					style="font-size:0.75rem;padding:3px 6px;background:var(--border);border:1px solid var(--border);border-radius:5px;color:var(--text);cursor:pointer;">
					<option value="viewer" ${u.role==='viewer'?'selected':''}>👁️ ${tr('role_viewer', 'Viewer')}</option>
					<option value="editor" ${u.role==='editor'?'selected':''}>✏️ ${tr('role_editor', 'Editor')}</option>
					<option value="admin" ${u.role==='admin'?'selected':''}>👑 ${tr('role_admin', 'Admin')}</option>
				</select>
				<button onclick="deleteUser('${u.id}', '${escHtml(u.username)}')"
					style="background:none;border:none;color:var(--error);cursor:pointer;font-weight:bold;font-size:1rem;padding:0 4px;">✕</button>
			</div>
		</div>`
	).join('');
}

function addUser() {
	const username = (document.getElementById('new-user-name')?.value || '').trim();
	const password = document.getElementById('new-user-pass')?.value || '';
	const role     = document.getElementById('new-user-role')?.value || 'viewer';

	if (username.length < 3) return showToast('Benutzername min. 3 Zeichen', 'error');
	if (password.length < 8) return showToast('Passwort min. 8 Zeichen', 'error');

	const token = localStorage.getItem('triggerToken') || '';
	fetch('/api/users', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...(token ? {'X-Trigger-Token': token} : {}) },
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
		headers: { 'Content-Type': 'application/json', ...(token ? {'X-Trigger-Token': token} : {}) },
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
		headers: token ? {'X-Trigger-Token': token} : {}
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
        return `<span style="padding:3px 8px;border-radius:6px;font-size:0.78rem;font-family:monospace;`
            + `background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);">`
            + `${icon} ${host} <span style="opacity:0.4">${ageStr}</span></span>`;
    }).join('');
}

function showLoadingToast(text = '⏳ Speichere...') {
	let el = document.getElementById('loading-toast');
	if (!el) {
		el = document.createElement('div');
		el.id = 'loading-toast';
		el.style.cssText = `
			background: var(--card);
			color: var(--text);
			border: 1px solid var(--border);
			position: fixed;
			bottom: 20px;
			right: 20px;
			padding: 14px 18px;
			border-radius: 8px;
			box-shadow: 0 4px 12px rgba(0,0,0,0.3);
			font-family: sans-serif;
			min-width: 250px;
			z-index: 9999;
		`;

		el.innerHTML = `
			<div id="loading-text">${text}</div>
			<div style="margin-top:8px;height:4px;background:var(--border);border-radius:2px;overflow:hidden;">
				<div id="loading-bar" style="
					height:100%;
					width:30%;
					background:var(--success);
					animation: loadingAnim 1.2s infinite linear;
				"></div>
			</div>
		`;

		document.body.appendChild(el);

		const style = document.createElement('style');
		style.innerHTML = `
			@keyframes loadingAnim {
				0% { margin-left: -30%; width: 30%; }
				50% { width: 60%; }
				100% { margin-left: 100%; width: 30%; }
			}
		`;
		document.head.appendChild(style);
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