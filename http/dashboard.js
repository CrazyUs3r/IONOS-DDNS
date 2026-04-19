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
	const savedTheme = localStorage.getItem('theme') || 'dark';
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
}

function connectWS() {
	const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
	ws = new WebSocket(proto + location.host + '/ws');
	ws.onmessage = (e) => {
		const msg = JSON.parse(e.data);
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

function showToast(message, type = 'success') {
	const toast = document.getElementById('toast');
	if(!toast) return;
	toast.textContent = message;
	let borderColor = 'var(--success)';
	let duration = 4000;
	if(type === 'error') { borderColor = 'var(--error)'; duration = 5000; }
	else if(type === 'warning') { borderColor = '#facc15'; duration = 4000; }
	else if(type === 'info') { borderColor = '#3b82f6'; duration = 2500; }
	toast.style.borderLeft = '4px solid ' + borderColor;
	toast.classList.add('show');
	setTimeout(() => toast.classList.remove('show'), duration);
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
		catch (err) { showToast('❌ Fehler', 'error'); }
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
	const token = localStorage.getItem('triggerToken') || '';
	showToast(tr('update_starting', '⏳ Update wird gestartet...'), 'info');
	fetch('/api/trigger', { method: 'POST', headers: token ? {'X-Trigger-Token': token} : {} })
	.then(r => r.json().then(j => {
		if (j.error) showToast('⚠️ ' + j.error, 'warning');
		else showToast(tr('update_started', '✅ Update gestartet'), 'success');
	})).catch(() => showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error'));
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
		showToast('✓ Export gestartet');
	}).catch(() => showToast('Export fehlgeschlagen', 'error'));
}

function sanitizeBase(s) {
	s = (s || '').toLowerCase();
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
	const buf = await crypto.subtle.digest('SHA-1', data);
	return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 8);
}

async function makeSafeID(domain) {
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
	showToast('✓ ' + data.domain + ' updated');
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
	if (inp) inp.placeholder = saved ? '●●●●●● (gespeichert)' : 'Token eingeben...';

	const sys = (typeof initialSystem !== 'undefined' && initialSystem) ? initialSystem : {};
	_setVal('cfg-ip-mode',        sys.ip_mode           || 'BOTH');
	_setVal('cfg-interval',       sys.interval          || 300);
	_setVal('cfg-health-port',    sys.health_port       || '8080');
	_setVal('cfg-iface',          sys.iface_name        || '');
	_setVal('cfg-dns',            (sys.dns_servers || []).join(', '));
	_setVal('cfg-max-log',        sys.max_log_lines     || 500);
	_setVal('cfg-max-retries',    sys.max_api_retries   || 3);
	_setVal('cfg-max-concurrent', sys.max_concurrent    || 5);
	_setVal('cfg-hourly-limit',   sys.hourly_rate_limit || 1200);
	_setVal('cfg-lang',           sys.lang              || 'de');
	_setChk('cfg-dry-run',        sys.dry_run           || false);
	_setChk('cfg-debug',       	  sys.debug_enabled     || false);
	_setChk('cfg-debug-http',  	  sys.debug_http_raw    || false);

	// Notifications
	_setChk('cfg-notify-enabled',  sys.notify_enabled   || false);
	const activeEvents = new Set((sys.notify_events || []).map(e => e.toUpperCase()));
  	document.querySelectorAll('input[name="notify-event"]').forEach(cb => {
      cb.checked = activeEvents.has(cb.value);
  });
	_setVal('cfg-tg-token',        sys.telegram_token   || '');
	_setVal('cfg-tg-chatid',       sys.telegram_chat_id || '');
	_setVal('cfg-gotify-url',      sys.gotify_url        || '');
	_setVal('cfg-gotify-token',    sys.gotify_token      || '');

	renderSettingsDomainList();
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
		document.getElementById('s-token').placeholder = '●●●●●● (gespeichert)';
		showToast('✅ Token gespeichert', 'success');
	} else {
		localStorage.removeItem('triggerToken');
		document.getElementById('s-token').placeholder = 'Token eingeben...';
		showToast('🗑️ Token gelöscht', 'info');
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

	// Formular vorher sauber leeren
	resetDomainForm();

	_setVal('new-domain-fqdn', d.fqdn || '');

	const provSel = document.getElementById('new-domain-provider');
	if (provSel) provSel.value = d.provider || 'IONOS';

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

async function saveFullConfig() {
	if (!confirm(tr('save_config_confirm', 'Alle Einstellungen in config.json speichern?'))) return;
	const token = localStorage.getItem('triggerToken') || '';

	const dnsRaw = _getVal('cfg-dns');
	const dnsServers = dnsRaw.split(',').map(s => s.trim()).filter(Boolean);

  const notifyEvents = [...document.querySelectorAll('input[name="notify-event"]:checked')]
      .map(cb => cb.value);

	const system = {
		ip_mode:          _getVal('cfg-ip-mode') || 'BOTH',
		interval:         parseInt(_getVal('cfg-interval'),  10) || 300,
		health_port:       _getVal('cfg-health-port') || '8080',
		iface_name:        _getVal('cfg-iface'),
		dns_servers:       dnsServers,
		max_log_lines:     parseInt(_getVal('cfg-max-log'),        10) || 500,
		max_api_retries:   parseInt(_getVal('cfg-max-retries'), 10) || 4,
		max_concurrent:    parseInt(_getVal('cfg-max-concurrent'), 10) || 5,
		hourly_rate_limit: parseInt(_getVal('cfg-hourly-limit'),   10) || 1200,
		lang:              _getVal('cfg-lang') || 'de',
		dry_run:           document.getElementById('cfg-dry-run')?.checked || false,
    	debug_enabled:     document.getElementById('cfg-debug')?.checked || false,
    	debug_http_raw:    document.getElementById('cfg-debug-http')?.checked || false,
		notify_enabled:   document.getElementById('cfg-notify-enabled')?.checked || false,
		notify_events:    notifyEvents,
		telegram_token:   _getVal('cfg-tg-token'),
		telegram_chat_id: _getVal('cfg-tg-chatid'),
		gotify_url:       _getVal('cfg-gotify-url'),
		gotify_token:     _getVal('cfg-gotify-token'),
	};

	try {
		const r = await fetch('/api/save-config', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', ...(token ? {'X-Trigger-Token': token} : {}) },
			body: JSON.stringify({ domain_configs: tempDomainConfigs, system })
		});
    const newLang = _getVal('cfg-lang');
    if (newLang && newLang !== (initialSystem?.lang || 'de')) {
        await fetch('/api/set-language?lang=' + encodeURIComponent(newLang), {
            method: 'POST',
            headers: token ? { 'X-Trigger-Token': token } : {}
        });
    }
		if (r.ok) {
			showToast(tr('saved_reload', '✅ Gespeichert! Seite wird neu geladen...'), 'success');
			setTimeout(() => location.reload(), 1800);
		} else {
			const txt = await r.text();
			showToast(tr('error_prefix', '❌ Fehler: ') + txt, 'error');
		}
	} catch (e) { showToast('❌ Netzwerkfehler', 'error'); }
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
		else { showToast('❌ Reset fehlgeschlagen', 'error'); }
	})
	.catch(() => showToast('❌ Verbindungsfehler', 'error'));
}

function filterDomains(query) {
	document.querySelectorAll('.domain-item').forEach(d => {
		const name = (d.getAttribute('data-domain') || '').toLowerCase();
		d.style.display = name.includes(query.toLowerCase()) ? '' : 'none';
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
			btn.disabled = false; btn.textContent = '🗑️ Entfernen';
			showToast('❌ ' + (j.error || 'Fehler beim Löschen'), 'error');
		}
	})
	.catch(() => { btn.disabled = false; btn.textContent = tr('remove_btn', '🗑️ Entfernen'); showToast('❌ Verbindungsfehler', 'error'); });
}

function fallbackCopy(text) {
	const ta = document.createElement('textarea');
	ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px';
	document.body.appendChild(ta); ta.focus(); ta.select();
	try { document.execCommand('copy'); showToast('✓ Kopiert: ' + text, 'success'); }
	catch { showToast('❌ Kopieren fehlgeschlagen', 'error'); }
	document.body.removeChild(ta);
}

function startClock() {
	const el = document.getElementById('clock');
	if (!el) return;
	const tick = () => { 
		const d = new Date();
		el.textContent = [d.getHours(), d.getMinutes(), d.getSeconds()].map(n => String(n).padStart(2, '0')).join(':');
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