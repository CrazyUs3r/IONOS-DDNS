// ============================================================================
// SECURITY BOOTSTRAP — CSRF + declarative event handlers
// ============================================================================
const nativeFetch = window.fetch.bind(window);

function currentCSRFToken() {
	const meta = document.querySelector('meta[name="csrf-token"]');
	return meta ? String(meta.content || '') : '';
}

window.fetch = function secureFetch(input, init = {}) {
	const requestURL = new URL(
		typeof input === 'string' || input instanceof URL ? input : input.url,
		window.location.href
	);
	const method = String(init.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
	const isUnsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method);

	if (requestURL.origin === window.location.origin && isUnsafe) {
		const headers = new Headers(input instanceof Request ? input.headers : undefined);
		new Headers(init.headers || {}).forEach((value, key) => headers.set(key, value));
		const csrfToken = currentCSRFToken();
		if (csrfToken) headers.set('X-CSRF-Token', csrfToken);
		init = { ...init, headers };
	}

	return nativeFetch(input, init);
};

function splitDeclarativeArgs(source) {
	const args = [];
	let current = '';
	let quote = '';
	let escaped = false;

	for (const ch of source) {
		if (escaped) {
			current += '\\' + ch;
			escaped = false;
			continue;
		}
		if (ch === '\\' && quote) {
			escaped = true;
			continue;
		}
		if (quote) {
			current += ch;
			if (ch === quote) quote = '';
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			current += ch;
			continue;
		}
		if (ch === ',') {
			args.push(current.trim());
			current = '';
			continue;
		}
		current += ch;
	}
	if (current.trim() || source.trim()) args.push(current.trim());
	return args;
}

function decodeDeclarativeString(raw) {
	const value = String(raw || '').trim();
	if (value.length < 2 || !['"', "'"].includes(value[0]) || value.at(-1) !== value[0]) {
		return value;
	}
	return value.slice(1, -1).replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|n|r|t|b|f|v|0|.|$)/g, (_, escape) => {
		if (escape.startsWith('x')) return String.fromCharCode(parseInt(escape.slice(1), 16));
		if (escape.startsWith('u')) return String.fromCharCode(parseInt(escape.slice(1), 16));
		return ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', 0: '\0' })[escape] ?? escape;
	});
}

const DECLARATIVE_ACTIONS = Object.freeze({
	addDomainToList: ({ element }) => addDomainToList(element),
	addUser: () => addUser(),
	cancelEdit: () => cancelEdit(),
	clearDebugLog: () => clearDebugLog(),
	closeSidebar: () => closeSidebar(),
	copyIP: ({ args }) => copyIP(args[0]),
	copyLogEntry: ({ element }) => copyLogEntry(element),
	deleteLogEntry: ({ element }) => deleteLogEntry(element),
	copyAuditEntry: ({ element }) => copyAuditEntry(element),
	deleteAuditEntry: ({ element }) => deleteAuditEntry(element),
	deleteDomain: ({ args, element }) => deleteDomain(args[0], element),
	deleteUser: ({ args }) => deleteUser(args[0], args[1]),
	editDomain: ({ args }) => editDomain(Number(args[0])),
	downloadFullBackup: () => downloadFullBackup(),
	exportData: () => exportData(),
	exportLogs: ({ args }) => exportLogs(args[0]),
	filterDebugLog: ({ element }) => filterDebugLog(element.value),
	filterDomains: ({ element }) => filterDomains(element.value),
	filterLogs: ({ args }) => filterLogs(args[0]),
	changeUserRole: ({ args, element }) => changeUserRole(args[0], element.value),
	ipv64AddDomain: () => ipv64AddDomain(),
	ipv64DeleteDomain: () => ipv64DeleteDomain(),
	navTo: ({ args }) => navTo(args[0]),
	removeDomainFromList: ({ args }) => removeDomainFromList(Number(args[0])),
	refreshDiagnosis: () => refreshDiagnosis(),
	refreshAuditLog: () => refreshAuditLog(),
	runDNSPropagation: () => runDNSPropagation(),
	resetMetrics: () => resetMetrics(),
	restoreFullBackup: () => restoreFullBackup(),
	saveFullConfig: () => saveFullConfig(),
	saveToken: () => saveToken(),
	sendNotifyTest: () => sendNotifyTest(),
	showNotifierTooltip: ({ args, element }) => showNotifierTooltip(element, element.dataset.tooltip || args[1] || args[0] || ''),
	toggleNotifCenter: () => toggleNotifCenter(),
	togglePassword: ({ args, element }) => togglePassword(args[0], element),
	toggleProviderFields: () => toggleProviderFields(),
	toggleSidebar: () => toggleSidebar(),
	toggleTheme: () => toggleTheme(),
	triggerUpdate: () => triggerUpdate(),
	updateCheckboxLabel: ({ element }) => updateCheckboxLabel(element),
});

function runDeclarativeAction(rawCommand, element, event) {
	let command = String(rawCommand || '').trim();
	if (!command) return;

	while (command.startsWith('event.preventDefault();') || command.startsWith('event.stopPropagation();')) {
		if (command.startsWith('event.preventDefault();')) {
			event.preventDefault();
			command = command.slice('event.preventDefault();'.length).trim();
		}
		if (command.startsWith('event.stopPropagation();')) {
			event.stopPropagation();
			command = command.slice('event.stopPropagation();'.length).trim();
		}
	}

	const match = command.match(/^([A-Za-z_$][\w$]*)\((.*)\);?$/s);
	if (!match) {
		console.warn('Blocked unknown declarative action:', command);
		return;
	}
	const name = match[1];
	const args = splitDeclarativeArgs(match[2]).map(arg => {
		if (arg === 'this') return element;
		if (arg === 'this.value') return element.value;
		return decodeDeclarativeString(arg);
	});

	const action = DECLARATIVE_ACTIONS[name];
	if (!action) {
		console.warn('Blocked non-allowlisted action:', name);
		return;
	}
	action({ args, element, event });
}

function declarativeTarget(event, attribute) {
	const target = event.target instanceof Element ? event.target : event.target?.parentElement;
	return target ? target.closest(`[${attribute}]`) : null;
}

document.addEventListener('click', event => {
	const element = declarativeTarget(event, 'data-click');
	if (element) runDeclarativeAction(element.getAttribute('data-click'), element, event);
});
document.addEventListener('change', event => {
	const element = declarativeTarget(event, 'data-change');
	if (element) runDeclarativeAction(element.getAttribute('data-change'), element, event);
});
document.addEventListener('input', event => {
	const element = declarativeTarget(event, 'data-input');
	if (element) runDeclarativeAction(element.getAttribute('data-input'), element, event);
});
document.addEventListener('mouseover', event => {
	const element = declarativeTarget(event, 'data-mouseenter');
	if (element && !element.contains(event.relatedTarget)) {
		runDeclarativeAction(element.getAttribute('data-mouseenter'), element, event);
	}
}, true);
document.addEventListener('focusin', event => {
	const element = declarativeTarget(event, 'data-focus');
	if (element) runDeclarativeAction(element.getAttribute('data-focus'), element, event);
});
document.addEventListener('keydown', event => {
	if (
		event.key === 'Enter' &&
		event.target instanceof HTMLInputElement &&
		event.target.id === 'ipv64-domain-input'
	) {
		event.preventDefault();
		ipv64AddDomain();
	}
});
document.addEventListener('pointerdown', (e) => {
	const el = e.target.closest?.('[data-unlock-input]');
	if (!el || !el.hasAttribute('readonly')) return;
	window.setTimeout(() => {
		if (el.isConnected && el.hasAttribute('readonly')) {
			el.removeAttribute('readonly');
		}
	}, 200);
}, true);
document.addEventListener('keydown', (e) => {
	const el = e.target.closest?.('[data-unlock-input]');
	if (el && el.hasAttribute('readonly')) {
		el.removeAttribute('readonly');
	}
}, true);
document.addEventListener('paste', (e) => {
	const el = e.target.closest?.('[data-unlock-input]');
	if (el && el.hasAttribute('readonly')) {
		el.removeAttribute('readonly');
	}
}, true);

let blinkTimer = null;
let faviconState = '';
let blinkingState = '';
let currentLevel = 'ok';
let ws = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
let editIndex = null;
let tempDomainConfigs = [];
const reconnectDelayMax = 10000;

function isDashboardRuntime() {
	return !!document.querySelector('.app-layout, .sidebar, .main-content, #page-title, .page-section');
}

function isAuthRuntime() {
	return !!document.querySelector('.auth-wrap, .auth-card, form[action="/login"], form[action="/setup"], form[action="/2fa"]');
}

function shouldRunDashboardBoot() {
	const path = window.location.pathname || '';
	if (
		path === '/login' ||
		path === '/setup' ||
		path === '/2fa' ||
		path.startsWith('/settings/2fa')
	) {
		return false;
	}
	return isDashboardRuntime() && !isAuthRuntime();
}

// ============================================================================
// SIDEBAR NAVIGATION
// ============================================================================
function onlyWhenPageChanges(handler) {
	return context => {
		if (context.changed) return handler(context);
	};
}

const PAGE_CACHE_TTL = Object.freeze({
	dashboard: 15000,
	domains: 15000,
	metrics: 15000,
	diagnose: 0,
	audit: 5000,
	logs: 5000,
	debug: 30000,
	backup: Infinity,
	settings: Infinity,
	totp: 30000,
	users: 10000,
});

const PAGE_CONFIG = Object.freeze({
	dashboard: Object.freeze({
		title: () => tr('nav_dashboard', '🌐 Dashboard'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('dashboard')),
	}),
	domains: Object.freeze({
		title: () => tr('nav_domains', '🌐 Domains'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('domains')),
	}),
	metrics: Object.freeze({
		title: () => tr('nav_metrics', '📊 Metrics'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('metrics')),
	}),
	diagnose: Object.freeze({
		title: () => tr('nav_diagnose', '🩺 Diagnose'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('diagnose', { force: true })),
	}),
	audit: Object.freeze({
		title: () => tr('nav_audit', '🛡️ Audit & DNS'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('audit')),
	}),
	logs: Object.freeze({
		title: () => tr('nav_logs', '🧾 Logs'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('logs')),
	}),
	debug: Object.freeze({
		title: () => tr('nav_debug', '🐞 Debug'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('debug')),
	}),
	backup: Object.freeze({
		title: () => tr('nav_backup', '💾 Backup & Restore'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('backup')),
	}),
	settings: Object.freeze({
		title: () => tr('nav_settings', '⚙️ Settings'),
		onOpen: () => openSettingsPage(),
	}),
	totp: Object.freeze({
		title: () => tr('nav_totp', '🔐 2FA / Account Security'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('totp')),
	}),
	users: Object.freeze({
		title: () => tr('nav_users', '👥 User Management'),
		onOpen: onlyWhenPageChanges(() => ensurePageLoaded('users')),
	}),
});

const DEFAULT_PAGE = 'dashboard';
const PAGES = Object.freeze(Object.keys(PAGE_CONFIG));

let currentPage = DEFAULT_PAGE;
const pageRefreshControllers = new Map();
const pageLoadPromises = new Map();
const pageLoadedAt = new Map([[DEFAULT_PAGE, Date.now()]]);

function captureDashboardState(section) {
	if (!section) return null;

	return {
		endpointHTML: section.querySelector('#endpoint-status')?.innerHTML ?? '',
		lastUpdateText: section.querySelector('#lastUpdate')?.textContent ?? '',
		clockText: section.querySelector('#clock')?.textContent ?? '',
		uptimeText: section.querySelector('#uptime')?.textContent ?? '',
	};
}

function restoreDashboardState(section, state) {
	if (!section || !state) return;

	const endpointStatusElement = section.querySelector('#endpoint-status');
	if (endpointStatusElement && state.endpointHTML && Object.keys(endpointStatus).length === 0) {
		endpointStatusElement.innerHTML = state.endpointHTML;
	}

	const lastUpdate = section.querySelector('#lastUpdate');
	if (lastUpdate && state.lastUpdateText) lastUpdate.textContent = state.lastUpdateText;

	const clock = section.querySelector('#clock');
	if (clock && state.clockText) clock.textContent = state.clockText;

	const uptime = section.querySelector('#uptime');
	if (uptime && state.uptimeText) uptime.textContent = state.uptimeText;

	startClock();
	startStatusUptimeClock();
}

function capturePageState(page, section) {
	if (!section) return null;
	if (page === 'dashboard') return captureDashboardState(section);
	if (page === 'domains') return { search: section.querySelector('#domainSearch')?.value || '' };
	if (page === 'logs') {
		return {
			filter: section.querySelector('.filter-btn.active[data-filter]')?.dataset.filter || 'all',
		};
	}
	return null;
}

function initializeLoadedPage(page, section, state) {
	if (page === 'dashboard') {
		restoreDashboardState(section, state);
		renderEndpointStatus();
		return;
	}

	if (page === 'metrics') {
		initChartTooltips(section);
		return;
	}

	if (page === 'domains') {
		const searchInput = section.querySelector('#domainSearch');
		if (searchInput && state?.search) {
			searchInput.value = state.search;
			filterDomains(state.search);
		}
		initDomainDetailsState();
		initIPTimelines();
		initChangedBadges();
		initChartTooltips(section);
		startUptimeClocks();
		return;
	}

	if (page === 'logs') {
		filterLogs(state?.filter || 'all');
		return;
	}

	if (page === 'diagnose') {
		refreshDiagnosis();
		return;
	}

	if (page === 'audit') {
		refreshAuditLog();
		return;
	}

	if (page === 'totp') {
		initTOTPSettings(false);
		return;
	}

	if (page === 'users') loadUsers();
}

function isPageSectionLoaded(page) {
	const section = document.querySelector(`.page-section[data-section="${page}"]`);
	return Boolean(
		section &&
		section.dataset.loaded !== '0' &&
		!section.classList.contains('page-section--placeholder')
	);
}

async function refreshPageSection(page) {
	const oldSection = document.querySelector(`.page-section[data-section="${page}"]`);
	if (!oldSection) return false;

	pageRefreshControllers.get(page)?.abort();
	const controller = new AbortController();
	pageRefreshControllers.set(page, controller);
	oldSection.setAttribute('aria-busy', 'true');

	const state = capturePageState(page, oldSection);

	try {
		const response = await fetch('/api/page?name=' + encodeURIComponent(page), {
			method: 'GET',
			cache: 'no-store',
			headers: { Accept: 'application/json' },
			signal: controller.signal,
		});

		if (!response.ok) throw new Error('HTTP ' + response.status);
		const data = await response.json();
		if (!data.html) throw new Error('Empty page fragment');

		const template = document.createElement('template');
		template.innerHTML = String(data.html).trim();
		const newSection = template.content.firstElementChild;
		if (!newSection || newSection.dataset.section !== page) {
			throw new Error('Invalid page fragment');
		}

		newSection.dataset.loaded = '1';
		newSection.classList.remove('page-section--placeholder');
		oldSection.replaceWith(newSection);
		newSection.style.display = currentPage === page ? '' : 'none';
		pageLoadedAt.set(page, Date.now());
		initializeLoadedPage(page, newSection, state);
		return true;
	} catch (error) {
		if (error?.name === 'AbortError') return false;
		console.error(`${page} reload failed:`, error);
		showToast('❌ ' + tr('page_reload_failed', 'Seite konnte nicht aktualisiert werden'), 'error');
		return false;
	} finally {
		oldSection.removeAttribute('aria-busy');
		if (pageRefreshControllers.get(page) === controller) {
			pageRefreshControllers.delete(page);
		}
	}
}

function ensurePageLoaded(page, { force = false } = {}) {
	const existingPromise = pageLoadPromises.get(page);
	if (existingPromise && !force) return existingPromise;

	const loaded = isPageSectionLoaded(page);
	if (loaded && !pageLoadedAt.has(page)) pageLoadedAt.set(page, Date.now());

	const maxAge = PAGE_CACHE_TTL[page] ?? Infinity;
	const age = Date.now() - (pageLoadedAt.get(page) || 0);
	if (!force && loaded && age <= maxAge) return Promise.resolve(true);

	const promise = refreshPageSection(page).finally(() => {
		if (pageLoadPromises.get(page) === promise) pageLoadPromises.delete(page);
	});
	pageLoadPromises.set(page, promise);
	return promise;
}

async function openSettingsPage() {
	try {
		await Promise.all([
			ensurePageLoaded('settings'),
			ensureInitialConfig(),
		]);
		if (currentPage === 'settings') _initSettingsFields();
	} catch (error) {
		console.error('Settings load failed:', error);
		showToast('❌ ' + tr('settings_reload_failed', 'Einstellungen konnten nicht geladen werden'), 'error');
	}
}

let initialConfigLoaded = false;
let initialConfigPromise = null;

function applyInitialConfig(data) {
	tempDomainConfigs = (Array.isArray(data?.domain_configs) ? data.domain_configs : [])
		.map(domain => ({ ...domain }));
	window.initialSystem = data?.system ?? {};
	initialConfigLoaded = true;
}

async function requestInitialConfig() {
	const response = await fetch('/api/config', {
		method: 'GET',
		cache: 'no-store',
		headers: { Accept: 'application/json' },
	});
	if (!response.ok) throw new Error('HTTP ' + response.status);
	applyInitialConfig(await response.json());
	return true;
}

function ensureInitialConfig({ force = false } = {}) {
	if (!force && initialConfigLoaded) return Promise.resolve(true);
	if (!force && initialConfigPromise) return initialConfigPromise;

	const promise = requestInitialConfig()
		.catch(error => {
			initialConfigLoaded = false;
			if (initialConfigPromise === promise) initialConfigPromise = null;
			throw error;
		});
	initialConfigPromise = promise;
	return promise;
}

function navTo(page) {
	if (!isDashboardRuntime()) return;

	page = Object.prototype.hasOwnProperty.call(PAGE_CONFIG, page) ? page : DEFAULT_PAGE;
	const previousPage = currentPage;
	const changed = previousPage !== page;
	const pageConfig = PAGE_CONFIG[page];
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

	const titleEl = document.getElementById('page-title');
	if (titleEl) titleEl.textContent = pageConfig.title();

	pageConfig.onOpen?.({
		page,
		previousPage,
		changed,
	});

	try { localStorage.setItem('nav-page', page); } catch { }
	try {
		const newHash = '#' + page;
		if (window.location.hash !== newHash) history.replaceState(null, '', newHash);
	} catch { }

	if (window.innerWidth < 768) closeSidebar();
}

function setSidebarOpen(open) {
	const isOpen = Boolean(open);
	const sidebar = document.getElementById('sidebar');
	const overlay = document.getElementById('sidebar-overlay');
	const toggle = document.querySelector('.hamburger-btn');
	if (sidebar) sidebar.classList.toggle('sidebar-open', isOpen);
	if (overlay) overlay.classList.toggle('visible', isOpen);
	if (toggle) toggle.setAttribute('aria-expanded', String(isOpen));
}

function toggleSidebar() {
	const sidebar = document.getElementById('sidebar');
	setSidebarOpen(!(sidebar && sidebar.classList.contains('sidebar-open')));
}

function closeSidebar() {
	setSidebarOpen(false);
}


// ============================================================================
// 2FA SETTINGS INLINE SECTION
// ============================================================================
function initTOTPSettings(forceReload = false) {
	const container = document.getElementById('totp-settings-content');
	if (!container) return;
	bindTOTPForms();
	if (forceReload || !container.querySelector('.totp-settings-inline')) {
		loadTOTPSettings();
	}
}

async function loadTOTPSettings() {
	const container = document.getElementById('totp-settings-content');
	if (!container) return;

	try {
		const res = await fetch('/settings/2fa?fragment=1', {
			method: 'GET',
			credentials: 'same-origin',
			headers: { 'X-Requested-With': 'fetch' },
		});
		if (res.redirected && res.url.includes('/login')) {
			window.location.href = res.url;
			return;
		}
		if (res.status === 401) {
			window.location.href = '/login?redirect=/';
			return;
		}
		if (!res.ok) throw new Error(`HTTP ${res.status}`);

		container.innerHTML = await res.text();
		bindTOTPForms();
		focusTOTPCodeInput();
	} catch (err) {
		replaceWithTextElement(
			container,
			'div',
			'auth-error',
			`⚠️ ${tr('totp_settings_load_failed', '2FA settings could not be loaded')}: ${String(err.message || err)}`,
		);
	}
}

function bindTOTPForms() {
	const container = document.getElementById('totp-settings-content');
	if (!container) return;

	container.querySelectorAll('form[data-totp-form]').forEach(form => {
		if (form.dataset.bound === '1') return;
		form.dataset.bound = '1';
		form.addEventListener('submit', submitTOTPForm);
	});
}

async function submitTOTPForm(event) {
	event.preventDefault();
	const form = event.currentTarget;
	const container = document.getElementById('totp-settings-content');
	if (!form || !container) return;

	const submitBtn = form.querySelector('button[type="submit"]');
	if (submitBtn) submitBtn.disabled = true;

	try {
		const url = new URL(form.getAttribute('action') || '/settings/2fa?fragment=1', window.location.origin);
		url.searchParams.set('fragment', '1');

		const res = await fetch(url.toString(), {
			method: 'POST',
			body: new FormData(form),
			credentials: 'same-origin',
			headers: { 'X-Requested-With': 'fetch' },
		});
		if (res.redirected && res.url.includes('/login')) {
			window.location.href = res.url;
			return;
		}
		if (res.status === 401) {
			window.location.href = '/login?redirect=/';
			return;
		}
		if (!res.ok) throw new Error(`HTTP ${res.status}`);

		container.innerHTML = await res.text();
		bindTOTPForms();
		focusTOTPCodeInput();

		if (document.getElementById('users-list')) {
			loadUsers();
		}
	} catch (err) {
		showToast('❌ ' + tr('totp_action_failed', '2FA action failed') + ': ' + String(err.message || err), 'error');
	} finally {
		if (submitBtn) submitBtn.disabled = false;
	}
}

function focusTOTPCodeInput() {
	const input = document.querySelector('#totp-settings-content input[name="totp_code"]');
	if (input) input.focus();
}

function applySavedTheme() {
	if (!localStorage.getItem('theme')) {
		localStorage.setItem(
			'theme',
			window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark',
		);
	}
	const theme = localStorage.getItem('theme') || 'dark';
	document.documentElement.setAttribute('data-theme', theme);
	return theme;
}

document.addEventListener('DOMContentLoaded', () => {
	const savedTheme = applySavedTheme();
	if (!shouldRunDashboardBoot()) return;

	const initialMetrics = {
		avg_latency: (document.getElementById('mLatency')?.textContent || '').trim(),
		success_rate: (document.getElementById('mSuccess')?.textContent || '').trim(),
		total_requests: (document.getElementById('mTotal')?.textContent || '0').trim(),
	};
	currentLevel = calcLevelFromMetrics(initialMetrics);
	applyFavicon(savedTheme, currentLevel, false);
	setBlinking(savedTheme, currentLevel);

	document.addEventListener('visibilitychange', () => {
		if (document.visibilityState !== 'visible' || !shouldRunDashboardBoot()) return;
		dashboardTick();
		if (!ws || ws.readyState === WebSocket.CLOSED) {
			reconnectDelay = 1000;
			connectWS();
		}
	});

	const hashPage = (window.location.hash || '').replace(/^#/, '');
	const savedPage = PAGES.includes(hashPage)
		? hashPage
		: (localStorage.getItem('nav-page') || DEFAULT_PAGE);
	navTo(savedPage);

	document.addEventListener('click', event => {
		if (window.innerWidth >= 768) return;
		const sidebar = document.getElementById('sidebar');
		const hamburger = document.querySelector('.hamburger-btn');
		if (
			sidebar?.classList.contains('sidebar-open') &&
			!sidebar.contains(event.target) &&
			(!hamburger || !hamburger.contains(event.target))
		) {
			closeSidebar();
		}
	});

	startUptimeClocks();
	startStatusUptimeClock();
	initKeyboardShortcuts();
	initChangedBadges();
	startClock();
	connectWS();


	document.addEventListener('keydown', event => {
		if (event.key === 'Escape') closeSettings();
	});
});

function faviconHref(theme, level, blink) {
	return '/favicon.svg?theme=' + encodeURIComponent(theme) +
		'&level=' + encodeURIComponent(level) +
		'&blink=' + (blink ? '1' : '0');
}

function applyFavicon(theme, level, blink) {
	const nextState = `${theme}:${level}:${blink ? 1 : 0}`;
	if (nextState === faviconState) return;

	const favicon = document.getElementById('favicon');
	if (!favicon) return;
	faviconState = nextState;
	favicon.href = faviconHref(theme, level, blink);
}

function setBlinking(theme, level) {
	const nextState = level === 'err' ? `${theme}:err` : '';
	if (nextState === blinkingState) return;
	blinkingState = nextState;

	if (blinkTimer) {
		clearInterval(blinkTimer);
		blinkTimer = null;
	}
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

let _dashboardTickTimer = null;
let _lastSlowTick = 0;
let _statusUptimeBaseSeconds = null;
let _statusUptimeReceivedAt = 0;

function dashboardTick() {
	if (document.hidden) return;

	renderClock();
	renderStatusUptime();

	const now = Date.now();
	if (now - _lastSlowTick >= 30000) {
		_lastSlowTick = now;
		updateUptimeClocks();
		updateChangedBadges();
	}
}

function ensureDashboardTicker() {
	dashboardTick();
	if (!_dashboardTickTimer) {
		_dashboardTickTimer = setInterval(dashboardTick, 1000);
	}
}

function formatStatusUptime(totalSeconds) {
	const u = Math.max(0, Math.floor(Number(totalSeconds) || 0));
	const days = Math.floor(u / 86400);
	const hours = Math.floor((u % 86400) / 3600);
	const minutes = Math.floor((u % 3600) / 60);
	const seconds = u % 60;

	if (days > 0) return days + 'd ' + hours + 'h ' + minutes + 'm';
	if (hours > 0) return hours + 'h ' + minutes + 'm';
	if (minutes > 0) return minutes + 'm ' + seconds + 's';
	return seconds + 's';
}

function renderStatusUptime() {
	if (!Number.isFinite(_statusUptimeBaseSeconds)) return;

	const uptime = document.getElementById('uptime');
	if (!uptime) return;

	const elapsedSeconds = Math.max(0, Math.floor((Date.now() - _statusUptimeReceivedAt) / 1000));
	uptime.textContent = formatStatusUptime(_statusUptimeBaseSeconds + elapsedSeconds);
}

function setStatusUptime(value) {
	const seconds = Number(value);
	if (!Number.isFinite(seconds) || seconds < 0) return;

	_statusUptimeBaseSeconds = Math.floor(seconds);
	_statusUptimeReceivedAt = Date.now();
	renderStatusUptime();
	startStatusUptimeClock();
}

function startStatusUptimeClock() {
	renderStatusUptime();
	ensureDashboardTicker();
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

	setStatusUptime(m.uptime_secs);
}

let _chartTooltip = null;

function getChartTooltip() {
	if (_chartTooltip && _chartTooltip.isConnected) return _chartTooltip;

	_chartTooltip = document.querySelector('.chart-tooltip') || document.createElement('div');
	_chartTooltip.className = 'chart-tooltip';
	_chartTooltip.setAttribute('role', 'status');
	_chartTooltip.setAttribute('aria-live', 'polite');
	if (!_chartTooltip.isConnected) document.body.appendChild(_chartTooltip);
	return _chartTooltip;
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

		const tooltip = getChartTooltip();

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
	});
}

let isSettingsOpen = false;
let updateRequestPending = false;
let updateStatusPollTimer = null;

function shouldSkipDashboardWSUpdate(messageType) {
	return isSettingsOpen && [
		'initial',
		'metrics',
		'domain_update',
		'ip_check_result',
	].includes(messageType);
}

async function updateProviderStatusIndicators(providerStatus) {
	const entries = Object.entries(providerStatus || {});
	let matched = 0;

	for (const [key, ok] of entries) {
		const safeID = await makeSafeID(key);
		const candidates = new Set([
			document.getElementById('pstatus-' + key),
			document.getElementById('pstatus-' + safeID),
		]);

		for (const element of candidates) {
			if (!element) continue;
			element.textContent = ok ? ' ✅' : ' ❌';
			matched++;
		}
	}

	// Preserve the old behavior only for one aggregate status value.
	if (matched === 0 && entries.length === 1) {
		const ok = Boolean(entries[0][1]);
		document.querySelectorAll('.provider-status-dot').forEach(element => {
			element.textContent = ok ? ' ✅' : ' ❌';
		});
	}
}

function connectWS() {
	if (!shouldRunDashboardBoot()) return;
	if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;

	const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
	const socket = new WebSocket(proto + location.host + '/ws');
	ws = socket;
	socket.onmessage = (event) => {
		let msg;
		try { msg = JSON.parse(event.data); } catch { return; }

		if (!shouldSkipDashboardWSUpdate(msg.type)) {
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
			} else if (msg.type === 'ip_check_result') {
				updateEndpointStatus(msg.data);
			}
		}

		// Notifications and debug logs must not be discarded while settings are open.
		if (msg.type === 'notification') {
			showToast(msg.data.message, msg.data.level || 'info');
		} else if (msg.type === 'debug_log') {
			appendDebugLog(msg.data);
		}

		if (!isSettingsOpen && msg.data && msg.data.provider_status) {
			updateProviderStatusIndicators(msg.data.provider_status).catch(err =>
				console.error('provider_status error:', err)
			);
		}
	};
	socket.onclose = () => {
		if (ws === socket) ws = null;
		scheduleReconnect();
	};
	socket.onerror = () => {
		try { socket.close(); } catch { }
	};
	socket.onopen = () => {
		if (ws !== socket) return;
		reconnectDelay = 1000;
		if (reconnectTimer) {
			clearTimeout(reconnectTimer);
			reconnectTimer = null;
		}
	};
}

function scheduleReconnect() {
	if (!shouldRunDashboardBoot() || document.visibilityState !== 'visible') return;
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

function legacyCopyText(text) {
	const textarea = document.createElement('textarea');
	textarea.value = text;
	textarea.className = 'clipboard-helper';
	document.body.appendChild(textarea);
	textarea.focus();
	textarea.select();
	const copied = document.execCommand('copy');
	textarea.remove();
	if (!copied) throw new Error('Copy command failed');
}

async function copyText(text, preview = text) {
	try {
		if (!navigator.clipboard || !window.isSecureContext) {
			legacyCopyText(text);
		} else {
			await navigator.clipboard.writeText(text);
		}
		showToast(tr('copied', '✓ Copied: ') + preview);
		return true;
	} catch (error) {
		console.error('Copy failed:', error);
		showToast(tr('copy_failed', '❌ Copy failed'), 'error');
		return false;
	}
}

function copyIP(text) {
	if (!text || text === 'N/A' || text === '-') {
		showToast(tr('no_ip_to_copy', '❌ No IP to copy'), 'error');
		return;
	}
	copyText(text, text);
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

function setUpdateButtonBusy(isBusy) {
	const button = document.getElementById('update-button');
	if (button) button.disabled = Boolean(isBusy);
}

async function readAPIResponse(response) {
	const contentType = response.headers.get('content-type') || '';

	if (contentType.includes('application/json')) {
		try {
			return await response.json();
		} catch {
			return {};
		}
	}

	const text = await response.text();
	return {
		error: text.trim() || `HTTP ${response.status}`,
	};
}

function stopUpdateStatusPolling() {
	if (updateStatusPollTimer) {
		clearTimeout(updateStatusPollTimer);
		updateStatusPollTimer = null;
	}
}

async function pollUpdateStatus() {
	const token = sessionStorage.getItem('triggerToken') || '';

	try {
		const response = await fetch('/api/trigger/status', {
			headers: token ? { 'X-Trigger-Token': token } : {},
		});
		const data = await readAPIResponse(response);

		if (!response.ok) {
			throw new Error(data.error || `HTTP ${response.status}`);
		}

		if (data.update_in_progress) {
			setUpdateButtonBusy(true);
			updateStatusPollTimer = setTimeout(pollUpdateStatus, 1500);
			return;
		}
	} catch (error) {
		console.warn('Update status check failed:', error);
	}

	stopUpdateStatusPolling();
	setUpdateButtonBusy(false);
}

function monitorUpdateStatus() {
	stopUpdateStatusPolling();
	setUpdateButtonBusy(true);
	updateStatusPollTimer = setTimeout(pollUpdateStatus, 750);
}

async function triggerUpdate() {
	if (updateRequestPending) return;

	updateRequestPending = true;
	setUpdateButtonBusy(true);

	const token = sessionStorage.getItem('triggerToken') || '';
	showToast(tr('update_starting', '⏳ Update wird gestartet...'), 'info');

	try {
		const response = await fetch('/api/trigger', {
			method: 'POST',
			headers: token ? { 'X-Trigger-Token': token } : {},
		});
		const data = await readAPIResponse(response);

		if (response.status === 409) {
			showToast('⚠️ ' + (data.error || tr('update_running', 'Update läuft bereits')), 'warning');
			monitorUpdateStatus();
			return;
		}

		if (!response.ok) {
			throw new Error(data.error || `HTTP ${response.status}`);
		}

		showToast(tr('update_started', '✅ Update gestartet'), 'success');
		monitorUpdateStatus();
	} catch (error) {
		showToast('❌ ' + (error.message || tr('connection_error', 'Verbindungsfehler')), 'error');
		setUpdateButtonBusy(false);
	} finally {
		updateRequestPending = false;
	}
}

async function sendNotifyTest() {
	const btn = document.getElementById('notify-test-btn');
	const result = document.getElementById('notify-test-result');
	const token = sessionStorage.getItem('triggerToken') || '';

	if (btn) {
		btn.disabled = true;
		btn.textContent = tr('notify_btn_sending', '⏳ Sende...');
	}
	if (result) {
		result.style.display = 'none';
		result.className = 'notify-test-result';
		result.replaceChildren();
	}

	try {
		const response = await fetch('/api/notify/test', {
			method: 'POST',
			headers: token ? { 'X-Trigger-Token': token } : {},
		});

		if (response.status === 401) {
			if (result) {
				result.style.display = 'block';
				replaceWithTextElement(
					result,
					'span',
					'notify-result--error',
					tr('notify_test_unauthorized', '❌ Unauthorized (check token)'),
				);
			}
			return;
		}

		if (!response.ok) throw new Error(`HTTP ${response.status}`);
		const data = await response.json();
		if (!result) return;

		result.style.display = 'block';

		if (data.status === 'no_notifiers') {
			replaceWithTextElement(
				result,
				'span',
				'notify-result--warn',
				tr('notify_no_notifier', '⚠️ Keine aktiven Notifier konfiguriert.'),
			);
			return;
		}

		if (data.status !== 'done') {
			replaceWithTextElement(
				result,
				'span',
				'notify-result--error',
				tr('notify_test_error', '❌ Error while sending'),
			);
			return;
		}

		const sent = Number(data.sent) || 0;
		const total = Number(data.total) || 0;
		const allOk = sent === total;
		const fragment = document.createDocumentFragment();
		const summary = document.createElement('div');
		summary.className = 'notify-result-summary';
		summary.textContent = allOk
			? tr('notify_test_success', '✅ Test message sent successfully!')
			: `${sent}/${total} ${tr('notify_stat_success', 'erfolgreich')}`;
		fragment.appendChild(summary);

		(data.results || []).forEach((entry, index) => {
			if (index > 0) fragment.appendChild(document.createElement('br'));
			fragment.appendChild(document.createTextNode(entry.ok ? '✅ ' : '❌ '));

			const name = document.createElement('strong');
			name.textContent = String(entry.name || '');
			fragment.appendChild(name);

			if (entry.error) {
				const detail = document.createElement('span');
				detail.className = 'notify-result--detail';
				detail.textContent = ` (${String(entry.error)})`;
				fragment.appendChild(detail);
			}
		});

		result.className = allOk
			? 'notify-test-result notify-result--ok'
			: 'notify-test-result notify-result--warn';
		result.replaceChildren(fragment);
	} catch (err) {
		console.error(err);
		if (result) {
			result.style.display = 'block';
			replaceWithTextElement(
				result,
				'span',
				'notify-result--error',
				tr('notify_test_conn_error', '❌ Connection error to server'),
			);
		}
	} finally {
		if (btn) {
			btn.disabled = false;
			btn.textContent = tr('notify_btn_test', '🧪 Test-Nachricht senden');
		}
	}
}

function exportData() {
	const token = sessionStorage.getItem('triggerToken') || '';
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
	const value = String(str || '');
	if (window.crypto && crypto.subtle) {
		const data = new TextEncoder().encode(value);
		const buf = await crypto.subtle.digest('SHA-256', data);
		return Array.from(new Uint8Array(buf))
			.map(b => b.toString(16).padStart(2, '0'))
			.join('')
			.slice(0, 8);
	}

	let hash = 0x811c9dc5;
	for (let i = 0; i < value.length; i++) {
		hash ^= value.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	return (hash >>> 0).toString(16).padStart(8, '0');
}


const safeIDCache = new Map();

async function makeSafeID(domain) {
	const normalized = String(domain || '').trim();
	if (!safeIDCache.has(normalized)) {
		safeIDCache.set(normalized, (async () => {
			const base = sanitizeBase(normalized);
			const suffix = await shortHash8(normalized);
			return (base === 'x' ? 'd-' : base + '-') + suffix;
		})());
	}
	return safeIDCache.get(normalized);
}

function declarativeStringArg(value) {
	return `'${String(value ?? '')
		.replaceAll('\\', '\\\\')
		.replaceAll("'", "\\'")
		.replaceAll('\n', '\\n')
		.replaceAll('\r', '\\r')}'`;
}

function updateLiveIP(element, value) {
	if (!element) return;
	const text = String(value ?? '');
	element.textContent = text;
	const copyButton = element.parentElement?.querySelector('.copy-btn');
	if (copyButton) copyButton.setAttribute('data-click', `copyIP(${declarativeStringArg(text)})`);
}

async function updateDomainDisplay(data) {
	const safeID = await makeSafeID(data.domain);
	if (Object.prototype.hasOwnProperty.call(data, 'ipv4')) {
		updateLiveIP(document.getElementById('ip4-' + safeID), data.ipv4);
	}
	if (Object.prototype.hasOwnProperty.call(data, 'ipv6')) {
		updateLiveIP(document.getElementById('ip6-' + safeID), data.ipv6);
	}

	const now = Date.now();
	const dotEl = document.getElementById('dot-' + safeID);
	if (dotEl) {
		dotEl.className = 'domain-status-dot dot-ok dot-recent';
		if (dotEl._recentTimer) clearTimeout(dotEl._recentTimer);
		dotEl._recentTimer = setTimeout(() => {
			if (dotEl.isConnected) dotEl.classList.remove('dot-recent');
		}, 15 * 60 * 1000);
	}

	const uptimeEl = document.getElementById('uptime-' + safeID);
	const metaEl = uptimeEl?.closest('[data-last-changed]');
	if (metaEl) {
		metaEl.dataset.lastChanged = String(data.time || '');
		metaEl.dataset.lastChangedUnix = String(now);
	}
	if (uptimeEl) uptimeEl.textContent = '0s';

	const changedAtEl = document.getElementById('last-change-' + safeID);
	if (changedAtEl && data.time) changedAtEl.textContent = String(data.time);

	const badge = document.getElementById('badge-' + safeID);
	if (badge) {
		badge.dataset.changedAt = String(data.time || '');
		badge.dataset.changedUnix = String(now);
		badge.classList.remove('changed-badge--hidden');
	}

	showToast(trf('domain_updated', { domain: data.domain }, '✓ {domain} updated'));
}

function _getVal(id) { const el = document.getElementById(id); return el ? el.value : ''; }
function _isChecked(id) { const el = document.getElementById(id); return el ? el.checked : false; }
function _parseList(raw) { return (raw || '').split(',').map(s => s.trim()).filter(Boolean); }
function _setVal(id, v) { const el = document.getElementById(id); if (!el || el === document.activeElement) return; const next = v != null ? String(v) : ''; if (el.value !== next) el.value = next; }
function _setChk(id, v) { const el = document.getElementById(id); if (!el || el === document.activeElement) return; const next = !!v; if (el.checked !== next) el.checked = next; updateCheckboxLabel(el); }

function _initSettingsFields() {
	isSettingsOpen = true;

	const saved = sessionStorage.getItem('triggerToken') || '';
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
	_setVal('cfg-ntfy-url', sys.ntfy_url || '');
	_setVal('cfg-ntfy-topic', sys.ntfy_topic || '');
	_setVal('cfg-ntfy-token', sys.ntfy_token || '');
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

function saveToken() {
	const input = document.getElementById('s-token');
	if (!input) return;

	const val = (input.value || '').trim();
	if (val) {
		sessionStorage.setItem('triggerToken', val);
		input.value = '';
		input.placeholder = tr('token_saved_masked', '●●●●●● (gespeichert)');
		showToast(tr('token_saved', '✅ Token gespeichert'), 'success');
	} else {
		sessionStorage.removeItem('triggerToken');
		input.placeholder = tr('token_enter', 'Token eingeben...');
		showToast(tr('token_deleted', '🗑️ Token gelöscht'), 'info');
	}
}

function renderSettingsDomainList() {
	const container = document.getElementById('settings-domain-list');
	if (!container) return;
	container.replaceChildren();

	const sorted = [...tempDomainConfigs].sort((a, b) => {
		if (a.provider !== b.provider) return a.provider.localeCompare(b.provider);
		return a.fqdn.localeCompare(b.fqdn);
	});

	const providerColors = {
		IONOS: '#3b82f6',
		CLOUDFLARE: '#f97316',
		IPV64: '#a855f7',
		HETZNER: '#14b8a6',
		HETZNERCLOUD: '#06b6d4',
		FEBAS: '#22c55e',
		DNSCALE: '#8b5cf6',
	};

	for (const domain of sorted) {
		const originalIndex = tempDomainConfigs.indexOf(domain);
		const providerColor = providerColors[domain.provider] || '#64748b';
		const pill = document.createElement('div');
		pill.className = 'domain-pill';

		const info = document.createElement('div');
		info.className = 'domain-pill-info';

		const fqdn = document.createElement('span');
		fqdn.className = 'domain-pill-fqdn';
		fqdn.textContent = String(domain.fqdn || '');
		info.appendChild(fqdn);

		const addBadge = (text, decorateProvider = false) => {
			const badge = document.createElement('span');
			badge.className = 'provider-badge';
			badge.style.marginLeft = '6px';
			badge.textContent = String(text);
			if (decorateProvider) {
				badge.style.background = `${providerColor}20`;
				badge.style.color = providerColor;
				badge.style.border = `1px solid ${providerColor}40`;
			}
			info.appendChild(badge);
		};

		addBadge(domain.provider || '', true);
		if (domain.ttl) addBadge(`TTL ${domain.ttl}`);
		if (domain.ip_mode) addBadge(domain.ip_mode);
		if (domain.provider === 'CLOUDFLARE' && domain.cf_proxied) addBadge('proxied');

		const actions = document.createElement('div');
		actions.className = 'domain-pill-actions';

		const editButton = document.createElement('button');
		editButton.type = 'button';
		editButton.className = 'domain-pill-edit-btn';
		editButton.textContent = '✏️';
		editButton.addEventListener('click', () => editDomain(originalIndex));

		const removeButton = document.createElement('button');
		removeButton.type = 'button';
		removeButton.className = 'domain-pill-remove-btn';
		removeButton.textContent = '✕';
		removeButton.addEventListener('click', () => removeDomainFromList(originalIndex));

		actions.append(editButton, removeButton);
		pill.append(info, actions);
		container.appendChild(pill);
	}
}

function replaceWithTextElement(container, tagName, className, text) {
	const element = document.createElement(tagName);
	if (className) element.className = className;
	element.textContent = String(text ?? '');
	container.replaceChildren(element);
	return element;
}

function escHtml(s) {
	return String(s ?? '')
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
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
	_setVal('new-febas-update-url', '');
	_setVal('new-dnscale-api-key', '');
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
	} else if (d.provider === 'FEBAS') {
		_setVal('new-febas-update-url', d.febas_update_url || '');
	} else if (d.provider === 'DNSCALE') {
		_setVal('new-dnscale-api-key', d.api_key || '');
	}

	renderSettingsDomainList();
	openAddDomainSection();
	const addBtn = document.querySelector('#add-domain-section button[data-click="addDomainToList()"]');
	if (addBtn) addBtn.textContent = tr('edit_domain_saved', 'Änderungen übernehmen');
	document.getElementById('new-domain-fqdn')?.focus();
}

function toggleProviderFields() {
	const providerSelect = document.getElementById('new-domain-provider');
	if (!providerSelect) return;

	const p = providerSelect.value;
	const show = (id, visible) => {
		const el = document.getElementById(id);
		if (el) el.style.display = visible ? 'block' : 'none';
	};

	show('fields-ionos', p === 'IONOS');
	show('fields-cloudflare', p === 'CLOUDFLARE');
	show('fields-ipv64', p === 'IPV64');
	show('fields-hetzner', p === 'HETZNER');
	show('fields-hetznercloud', p === 'HETZNERCLOUD');
	show('fields-febas', p === 'FEBAS');
	show('fields-dnscale', p === 'DNSCALE');
}

function addDomainToList() {
	const fqdnInput = document.getElementById('new-domain-fqdn');
	const providerSelect = document.getElementById('new-domain-provider');
	if (!fqdnInput || !providerSelect) return;

	const fqdn = fqdnInput.value.trim().toLowerCase();
	const provider = providerSelect.value;
	const supportedProviders = new Set([
		'IONOS', 'CLOUDFLARE', 'IPV64', 'HETZNER', 'HETZNERCLOUD', 'FEBAS', 'DNSCALE'
	]);
	if (!supportedProviders.has(provider)) {
		return showToast(tr('provider_invalid', 'Ungültiger Provider'), 'error');
	}
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
	} else if (provider === 'FEBAS') {
		entry.febas_update_url = _getVal('new-febas-update-url').trim();
		if (!entry.febas_update_url) {
			return showToast(tr('febas_update_url_missing', 'Febas DynDNS Update-URL fehlt'), 'error')
		};
	} else if (provider === 'DNSCALE') {
		entry.api_key = _getVal('new-dnscale-api-key').trim();
		if (!entry.api_key) {
			return showToast(tr('dnscale_api_key_missing', 'DNScale API Key fehlt'), 'error');
		}

	}
	if (editIndex !== null) {
		tempDomainConfigs[editIndex] = entry;
		editIndex = null;
	} else {
		tempDomainConfigs.push(entry);
	}

	renderSettingsDomainList();
	resetDomainForm();

	fqdnInput.value = '';
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
		'new-dnscale-api-key',
	].forEach(id => _setVal(id, ''));

	_setChk('new-cf-proxied', false);
	const addBtn = document.querySelector('#add-domain-section button[data-click="addDomainToList()"]');
	if (addBtn) addBtn.textContent = tr('settings_add_btn', 'Hinzufügen');
}

function cancelEdit() {
	editIndex = null;
	resetDomainForm();
	const addBtn = document.querySelector('#add-domain-section button[data-click="addDomainToList()"]');
	if (addBtn) addBtn.textContent = tr('settings_add_btn', 'Hinzufügen');
	const section = document.getElementById('add-domain-section');
	if (section) section.open = false;
	showToast(tr('edit_domain_cancelled', 'Edit cancelled'), 'info');
}

function removeDomainFromList(index) {
	tempDomainConfigs.splice(index, 1);
	renderSettingsDomainList();
}

async function saveFullConfig() {
	if (!confirm(tr('save_config_confirm', 'Alle Einstellungen in config.json speichern?'))) return;

	const token = sessionStorage.getItem('triggerToken') || '';

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
		ntfy_url: _getVal('cfg-ntfy-url'),
		ntfy_topic: _getVal('cfg-ntfy-topic'),
		ntfy_token: _getVal('cfg-ntfy-token'),
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
	const token = sessionStorage.getItem('triggerToken') || '';
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

function copyLogEntry(button) {
	const text = button.closest('.log-entry-row')?.dataset.copy || '';
	if (text) copyText(text, text.slice(0, 60));
}

function deleteLogEntry(btn) {
	const row = btn.closest('.log-entry-row');
	if (!row) return;
	const id = row.dataset.logId;
	if (!id) return;

	fetch('/api/logs/delete', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ id }),
	})
		.then(async r => {
			if (!r.ok) throw new Error(await r.text());
			const next = row.nextElementSibling;
			if (next) next.classList.add('no-hover');

			row.style.transition = 'opacity 0.2s ease, max-height 0.25s ease';
			row.style.overflow = 'hidden';
			row.style.opacity = '0';
			row.style.maxHeight = row.offsetHeight + 'px';
			requestAnimationFrame(() => {
				row.style.maxHeight = '0';
				row.style.paddingTop = '0';
				row.style.paddingBottom = '0';
				row.style.marginTop = '0';
				row.style.marginBottom = '0';
			});
			setTimeout(() => {
				row.remove();
				if (next) next.classList.remove('no-hover');
			}, 270);
			showToast('🗑️ ' + tr('log_entry_deleted', 'Eintrag gelöscht'), 'success');
		})
		.catch(err => {
			console.error('Log delete failed:', err);
			showToast('❌ ' + (err.message || tr('log_delete_failed', 'Löschen fehlgeschlagen')), 'error');
		});
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
	const token = sessionStorage.getItem('triggerToken') || '';
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
		showToast('❌ ' + tr('fqdn_missing', 'FQDN fehlt'), 'error');
		return;
	}

	const token = sessionStorage.getItem('triggerToken') || '';
	if (result) { result.style.display = 'none'; result.replaceChildren(); }

	showToast(
		action === 'add'
			? tr('ipv64_domain_add_running', '⏳ IPv64 Domain wird hinzugefügt...')
			: tr('ipv64_domain_delete_running', '⏳ IPv64 Domain wird gelöscht...'),
		'info',
	);

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
				const msg = '❌ ' + (j.error || tr('generic_error', 'Fehler'));
				showToast(msg, 'error');
				if (result) {
					result.style.display = 'block';
					result.className = 'ipv64-result notify-result--error';
					result.textContent = msg;
				}
				return;
			}
			const fqdnText = String(j.fqdn || fqdn);
			const successText = trf(
				action === 'add' ? 'ipv64_domain_add_success' : 'ipv64_domain_delete_success',
				{ fqdn: fqdnText },
				action === 'add' ? '✅ IPv64 Domain hinzugefügt: {fqdn}' : '🗑️ IPv64 Domain gelöscht: {fqdn}',
			);
			showToast(successText, 'success');
			if (result) {
				result.style.display = 'block';
				result.className = 'ipv64-result notify-result--ok';
				result.textContent = successText;
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
	if (!fqdn) { showToast('❌ ' + tr('fqdn_missing', 'FQDN fehlt'), 'error'); return; }
	if (!confirm(trf('ipv64_domain_delete_confirm', { fqdn }, 'IPv64 Domain "{fqdn}" wirklich löschen? Diese Aktion kann nicht rückgängig gemacht werden.'))) return;
	_ipv64DomainAction('delete');
}

function renderClock() {
	const element = document.getElementById('clock');
	if (!element) return;
	const date = new Date();
	element.textContent = [date.getHours(), date.getMinutes(), date.getSeconds()]
		.map(value => String(value).padStart(2, '0'))
		.join(':');
}

function startClock() {
	renderClock();
	ensureDashboardTicker();
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
	const textOn = cb.getAttribute('data-label-on') || tr('settings_checkbox_active', 'Aktiv');
	const textOff = cb.getAttribute('data-label-off') || tr('settings_checkbox_inactive', 'Inaktiv');
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
		container.replaceChildren();
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

	container.replaceChildren();

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
	const container = document.getElementById('users-list');
	if (!container) return;

	fetch('/api/users')
		.then(response => {
			if (!response.ok) throw new Error('HTTP ' + response.status);
			return response.json();
		})
		.then(users => renderUsersList(users))
		.catch(err => {
			replaceWithTextElement(
				container,
				'div',
				'user-load-error',
				tr('user_load_failed', 'Fehler beim Laden'),
			);
			console.error(err);
		});
}

function renderUsersList(users) {
	const container = document.getElementById('users-list');
	if (!container) return;
	container.replaceChildren();

	if (!Array.isArray(users) || users.length === 0) {
		replaceWithTextElement(
			container,
			'div',
			'users-empty',
			tr('no_users_found', 'Keine Benutzer gefunden.'),
		);
		return;
	}

	const roleIcons = { admin: '👑', editor: '✏️', viewer: '👁️' };
	const roles = [
		{ value: 'viewer', icon: '👁️', label: tr('role_viewer', 'Viewer') },
		{ value: 'editor', icon: '✏️', label: tr('role_editor', 'Editor') },
		{ value: 'admin', icon: '👑', label: tr('role_admin', 'Admin') },
	];

	for (const user of users) {
		const userID = String(user.id || '');
		const username = String(user.username || '');
		const role = String(user.role || '');
		const totpEnabled = Boolean(user.totp_enabled ?? user.totpEnabled ?? user.TOTPEnabled);

		const pill = document.createElement('div');
		pill.className = 'domain-pill';

		const info = document.createElement('div');
		info.className = 'user-pill-info';

		const usernameElement = document.createElement('span');
		usernameElement.className = 'user-pill-username';
		usernameElement.textContent = username;

		const roleBadge = document.createElement('span');
		roleBadge.className = 'provider-badge user-role-badge';
		const roleLabel = roles.find(item => item.value === role)?.label || role;
		roleBadge.textContent = `${roleIcons[role] || '?'} ${roleLabel}`;

		const totpBadge = document.createElement('span');
		totpBadge.className = `provider-badge ${totpEnabled ? 'user-2fa-badge-on' : 'user-2fa-badge-off'}`;
		totpBadge.textContent = totpEnabled
			? tr('totp_badge_active', '🔐 2FA active')
			: tr('totp_badge_inactive', '🔓 2FA inactive');

		info.append(usernameElement, roleBadge, totpBadge);

		if (user.last_login) {
			const lastLogin = document.createElement('span');
			lastLogin.className = 'user-last-login';
			lastLogin.textContent = trf('user_last_login', { time: new Date(user.last_login).toLocaleString() }, 'Letzter Login: {time}');
			info.appendChild(lastLogin);
		}

		const actions = document.createElement('div');
		actions.className = 'domain-pill-actions';

		const select = document.createElement('select');
		select.className = 'user-role-select';
		for (const item of roles) {
			const option = document.createElement('option');
			option.value = item.value;
			option.textContent = `${item.icon} ${item.label}`;
			option.selected = role === item.value;
			select.appendChild(option);
		}
		select.addEventListener('change', () => changeUserRole(userID, select.value));

		const resetButton = document.createElement('button');
		resetButton.type = 'button';
		resetButton.className = 'user-reset-btn';
		resetButton.textContent = '🔑';
		resetButton.title = tr('reset_password', 'Passwort setzen');
		resetButton.addEventListener('click', () => resetUserPassword(userID, username));

		const deleteButton = document.createElement('button');
		deleteButton.type = 'button';
		deleteButton.className = 'user-delete-btn';
		deleteButton.textContent = '✕';
		deleteButton.addEventListener('click', () => deleteUser(userID, username));

		actions.append(select, resetButton, deleteButton);
		pill.append(info, actions);
		container.appendChild(pill);
	}
}

function addUser() {
	const username = (document.getElementById('new-user-name')?.value || '').trim();
	const password = document.getElementById('new-user-pass')?.value || '';
	const role = document.getElementById('new-user-role')?.value || 'viewer';

	if (username.length < 3) return showToast(tr('auth_user_min', 'Benutzername min. 3 Zeichen'), 'error');
	if (password.length < 8) return showToast(tr('auth_pass_min', 'Passwort min. 8 Zeichen'), 'error');

	const token = sessionStorage.getItem('triggerToken') || '';
	fetch('/api/users', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Trigger-Token': token } : {}) },
		body: JSON.stringify({ username, password, role })
	})
		.then(r => r.json().then(j => ({ ok: r.ok, j })))
		.then(({ ok, j }) => {
			if (!ok) return showToast('❌ ' + (j.error || tr('generic_error', 'Fehler')), 'error');
			showToast('✅ ' + tr('user_created', 'Benutzer erstellt'), 'success');
			const nameInput = document.getElementById('new-user-name');
			const passInput = document.getElementById('new-user-pass');
			if (nameInput) nameInput.value = '';
			if (passInput) passInput.value = '';
			loadUsers();
		})
		.catch(() => showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error'));
}

function changeUserRole(id, role) {
	const token = sessionStorage.getItem('triggerToken') || '';
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

function resetUserPassword(id, username) {
	const password = prompt(trf('reset_password_prompt', { username }, `New password for "${username}":`));
	if (password === null) return;
	if (password.length < 8) return showToast(tr('auth_pass_min', 'Passwort min. 8 Zeichen'), 'error');

	const token = sessionStorage.getItem('triggerToken') || '';
	fetch('/api/users/' + id, {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Trigger-Token': token } : {}) },
		body: JSON.stringify({ password })
	})
		.then(r => r.json().then(j => ({ ok: r.ok, j })))
		.then(({ ok, j }) => {
			if (!ok) return showToast('❌ ' + (j.error || tr('generic_error', 'Fehler')), 'error');
			showToast('✅ ' + tr('password_reset', 'Passwort geändert'), 'success');
		})
		.catch(() => showToast(tr('connection_error', '❌ Verbindungsfehler'), 'error'));
}

function deleteUser(id, username) {
	if (!confirm(trf('user_delete_confirm', { username }, 'Benutzer "{username}" wirklich löschen?'))) return;
	const token = sessionStorage.getItem('triggerToken') || '';
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

const endpointStatus = Object.create(null);
const endpointChipElements = new Map();

function endpointHost(url) {
	try {
		return new URL(url).hostname;
	} catch {
		return url;
	}
}

function endpointAge(timestamp) {
	const difference = Math.max(0, Date.now() - timestamp);
	if (difference < 1000) return `${difference}ms`;
	if (difference < 60000) return `${(difference / 1000).toFixed(0)}s`;
	return `${Math.round(difference / 60000)}m`;
}

function updateEndpointChip(container, url, status) {
	let chip = endpointChipElements.get(url);
	if (!chip?.isConnected || chip.parentElement !== container) {
		chip = document.createElement('span');
		chip.className = 'endpoint-chip';
		chip.dataset.endpointUrl = url;
		endpointChipElements.set(url, chip);
		container.appendChild(chip);
	}

	const ageElement = document.createElement('span');
	ageElement.className = 'endpoint-chip-age';
	ageElement.textContent = endpointAge(status.ts);
	chip.replaceChildren(
		document.createTextNode(`${status.ok ? '✅' : '❌'} ${endpointHost(url)} `),
		ageElement,
	);
}

function updateEndpointStatus(data) {
	const url = String(data?.url || '').trim();
	if (!url) return;
	endpointStatus[url] = { ok: Boolean(data.ok), ts: Date.now() };
	renderEndpointStatus(url);
}

function renderEndpointStatus(changedURL = '') {
	const container = document.getElementById('endpoint-status');
	if (!container) return;

	const entries = Object.entries(endpointStatus);
	if (entries.length === 0) return;
	container.querySelector('.endpoint-waiting')?.remove();

	if (changedURL && endpointStatus[changedURL]) {
		updateEndpointChip(container, changedURL, endpointStatus[changedURL]);
		return;
	}

	for (const [url, status] of entries) {
		updateEndpointChip(container, url, status);
	}
}

function showLoadingToast(text = '⏳ Speichere...') {
	let el = document.getElementById('loading-toast');
	if (!el) {
		el = document.createElement('div');
		el.id = 'loading-toast';

		const textElement = document.createElement('div');
		textElement.id = 'loading-text';
		textElement.textContent = String(text);

		const track = document.createElement('div');
		track.className = 'loading-toast-track';
		const bar = document.createElement('div');
		bar.id = 'loading-bar';
		track.appendChild(bar);
		el.replaceChildren(textElement, track);

		document.body.appendChild(el);
	} else {
		el.style.display = 'block';
		const textEl = document.getElementById('loading-text');
		if (textEl) textEl.textContent = text;
	}
	if (el._timeout) clearTimeout(el._timeout);
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

function statusTimestampToMs(raw, unixValue) {
	const unixMs = Number(unixValue);
	if (Number.isFinite(unixMs) && unixMs > 0) return unixMs;

	const value = String(raw || '').trim();
	if (!value || value === '0001-01-01 00:00:00') return NaN;
	const parts = value.match(/(\d+)\.(\d+)\.(\d+) (\d+):(\d+):(\d+)/);
	if (!parts) return NaN;
	return new Date(+parts[3], +parts[2] - 1, +parts[1], +parts[4], +parts[5], +parts[6]).getTime();
}

function formatUptime(lastChangedStr, unixValue) {
	const changedAt = statusTimestampToMs(lastChangedStr, unixValue);
	if (!Number.isFinite(changedAt) || new Date(changedAt).getFullYear() < 2020) return '—';
	const diff = Math.max(0, Math.floor((Date.now() - changedAt) / 1000));
	if (diff < 60) return diff + 's';
	if (diff < 3600) return Math.floor(diff / 60) + 'm';
	if (diff < 86400) return Math.floor(diff / 3600) + 'h ' + Math.floor((diff % 3600) / 60) + 'm';
	return Math.floor(diff / 86400) + 'd ' + Math.floor((diff % 86400) / 3600) + 'h';
}

function updateUptimeClocks() {
	document.querySelectorAll('[data-last-changed]').forEach(element => {
		const target = document.getElementById('uptime-' + element.dataset.uptimeId);
		if (target) {
			target.textContent = formatUptime(
				element.dataset.lastChanged,
				element.dataset.lastChangedUnix,
			);
		}
	});
}

function startUptimeClocks() {
	updateUptimeClocks();
	ensureDashboardTicker();
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

	container.replaceChildren();
	container.appendChild(wrap);
}

function initIPTimelines() {
	document.querySelectorAll('.domain-item[data-ip-history]').forEach(buildIPTimeline);
}

function initKeyboardShortcuts() {
	document.addEventListener('keydown', event => {
		if (event.repeat || event.ctrlKey || event.metaKey || event.altKey) return;

		const target = event.target;
		if (
			target instanceof HTMLElement &&
			(target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)
		) {
			return;
		}

		switch (event.key.toLowerCase()) {
			case 'r':
				event.preventDefault();
				triggerUpdate();
				break;
			case 's': navTo('settings'); break;
			case 'd': navTo('dashboard'); break;
			case 'm': navTo('metrics'); break;
			case 'i': navTo('diagnose'); break;
			case 'l': navTo('logs'); break;
			case '?':
				showToast(tr('keyboard_shortcuts_help', '⌨️ R=Update  S=Settings  D=Dashboard  M=Metrics  L=Logs  I=Diagnose'), 'info');
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
	const toggle = document.querySelector('.notif-toggle');
	const isOpen = window.getComputedStyle(panel).display !== 'none';
	const nextOpen = !isOpen;
	panel.style.display = nextOpen ? 'block' : 'none';
	if (toggle) toggle.setAttribute('aria-expanded', String(nextOpen));
	if (nextOpen) renderNotifCenter();
}

function renderNotifCenter() {
	const list = document.getElementById('notif-list');
	if (!list) return;
	list.replaceChildren();

	if (_notifHistory.length === 0) {
		const empty = document.createElement('div');
		empty.style.cssText = 'padding:10px;opacity:0.4;font-size:0.8rem;';
		empty.textContent = tr('notif_empty', 'Keine Ereignisse');
		list.appendChild(empty);
		return;
	}

	for (const notification of _notifHistory) {
		const row = document.createElement('div');
		row.style.cssText = 'padding:8px 12px;border-bottom:1px solid var(--border);font-size:0.78rem;';

		const dot = document.createElement('span');
		dot.style.marginRight = '6px';
		dot.style.color = notification.type === 'error'
			? 'var(--error)'
			: notification.type === 'warning'
				? 'var(--warning)'
				: 'var(--success)';
		dot.textContent = '●';

		const message = document.createTextNode(String(notification.message || ''));

		const time = document.createElement('span');
		time.style.cssText = 'float:right;opacity:0.4;';
		time.textContent = String(notification.time || '');

		row.append(dot, message, time);
		list.appendChild(row);
	}
}


function updateChangedBadges() {
	const now = Date.now();
	document.querySelectorAll('.changed-badge[data-changed-at], .changed-badge[data-changed-unix]').forEach(badge => {
		const changedAt = statusTimestampToMs(badge.dataset.changedAt, badge.dataset.changedUnix);
		const ageMs = Number.isFinite(changedAt) ? Math.max(0, now - changedAt) : Infinity;
		badge.classList.toggle('changed-badge--hidden', ageMs >= 15 * 60 * 1000);
	});
}

function initChangedBadges() {
	updateChangedBadges();
	ensureDashboardTicker();
}

// ============================================================================
// DIAGNOSE / HEALTH CENTER
// ============================================================================

async function refreshDiagnosis() {
	const box = document.getElementById('diagnose-content');
	if (!box) return;

	replaceWithTextElement(
		box,
		'div',
		'diag-loading',
		'⏳ ' + tr('diagnose_loading', 'Loading diagnosis...'),
	);

	try {
		const response = await fetch('/api/diagnose');
		const data = await response.json();

		if (!response.ok) {
			replaceWithTextElement(
				box,
				'div',
				'diag-error-box',
				'❌ ' + (data.error || tr('diagnose_load_failed', 'Diagnosis failed')),
			);
			return;
		}

		renderDiagnosis(data);
	} catch (err) {
		console.error(err);
		replaceWithTextElement(
			box,
			'div',
			'diag-error-box',
			'❌ ' + tr('diagnose_connection_failed', 'Connection failed'),
		);
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
		escHtml(label) + ': ' + escHtml(yesNo(value)) +
		'</span>';
}

function formatDiagnosisUptime(value) {
	const uptime = String(value || '').trim();
	const match = uptime.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?$/);
	if (!match) return uptime || '-';

	const totalHours = Number(match[1] || 0);
	if (totalHours < 24) return uptime;

	const days = Math.floor(totalHours / 24);
	const hours = totalHours % 24;
	const minutes = Number(match[2] || 0);

	return `${days}d ${hours}h ${minutes}m`;
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
				<div class="diag-row"><span>${escHtml(tr('diagnose_uptime', 'Uptime'))}</span><strong>${escHtml(formatDiagnosisUptime(d.uptime))}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_scheduler_ran', 'Scheduler ran'))}</span><strong>${escHtml(yesNo(d.scheduler_ran_once))}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_last_run_ok', 'Last run OK'))}</span><strong>${escHtml(yesNo(d.last_ok))}</strong></div>
				<div class="diag-row"><span>${escHtml(tr('diagnose_update_running', 'Update running'))}</span><strong>${escHtml(yesNo(d.update_in_progress))}</strong></div>
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
					${renderBoolBadge(tr('diagnose_flag_dry_run', 'Dry Run'), cfg.dry_run)}
					${renderBoolBadge(tr('diagnose_flag_debug', 'Debug'), cfg.debug)}
					${renderBoolBadge(tr('diagnose_flag_http_raw', 'HTTP Raw'), cfg.debug_http_raw)}
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
// AUDIT LOG & DNS PROPAGATION
// ============================================================================

function formatAuditTimestamp(value) {
	const date = new Date(value);
	if (Number.isNaN(date.getTime())) return String(value || '-');
	return date.toLocaleString();
}

function renderAuditEntries(entries) {
	const box = document.getElementById('audit-log-content');
	if (!box) return;
	if (!Array.isArray(entries) || entries.length === 0) {
		box.innerHTML = '<div class="audit-empty">' + escHtml(tr('audit_empty', 'Noch keine Audit-Einträge vorhanden.')) + '</div>';
		return;
	}

	const labels = {
		time: tr('audit_col_time', 'Zeit'),
		user: tr('audit_col_user', 'Benutzer'),
		action: tr('audit_col_action', 'Aktion'),
		status: tr('audit_col_status', 'Status'),
		ip: tr('audit_col_ip', 'IP'),
	};

	const rows = entries.map(entry => {
		const status = Number(entry.status || 0);
		const resultClass = status >= 400 ? 'audit-result-error' : 'audit-result-ok';
		const time = formatAuditTimestamp(entry.timestamp);
		const actor = entry.actor || '-';
		const role = entry.role || '';
		const method = entry.method || '';
		const path = entry.path || '';
		const ip = entry.ip || '-';
		const copyText = [time, actor, role, method, path, status, ip].filter(Boolean).join(' ');
		const actionTitle = [method, path].filter(Boolean).join(' ');

		return `<tr class="audit-entry-row" data-audit-id="${escHtml(entry.id || '')}" data-copy="${escHtml(copyText)}">
			<td title="${escHtml(time)}">${escHtml(time)}</td>
			<td><span class="audit-user-value"><strong>${escHtml(actor)}</strong>${role ? `<small>${escHtml(role)}</small>` : ''}</span></td>
			<td title="${escHtml(actionTitle)}"><span class="audit-action-value"><code class="audit-method">${escHtml(method)}</code><span class="audit-path">${escHtml(path)}</span></span></td>
			<td><span class="audit-result ${resultClass}">${escHtml(status || '-')}</span></td>
			<td><code class="audit-ip">${escHtml(ip)}</code></td>
			<td class="audit-actions"><span class="audit-action-buttons">
				<button class="copy-btn log-copy-btn" data-click="copyAuditEntry(this)" title="${escHtml(tr('copy_title', 'Kopieren'))}">📋</button>
				<button class="copy-btn log-delete-btn" data-click="deleteAuditEntry(this)" title="${escHtml(tr('delete_entry_title', 'Eintrag löschen'))}">🗑️</button>
			</span></td>
		</tr>`;
	}).join('');

	box.innerHTML = `<div class="audit-table-wrap audit-log-scroll"><table class="audit-table">
		<thead><tr><th>${escHtml(labels.time)}</th><th>${escHtml(labels.user)}</th><th>${escHtml(labels.action)}</th><th>${escHtml(labels.status)}</th><th>${escHtml(labels.ip)}</th><th></th></tr></thead>
 		<tbody>${rows}</tbody>
	</table></div>`;
}

function copyAuditEntry(button) {
	const text = button.closest('.audit-entry-row')?.dataset.copy || '';
	if (text) copyText(text, text.slice(0, 60));
}

function deleteAuditEntry(btn) {
	const row = btn.closest('.audit-entry-row');
	if (!row) return;
	const id = row.dataset.auditId;
	if (!id) return;

	fetch('/api/audit/delete', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ id }),
	})
		.then(async r => {
			if (!r.ok) throw new Error(await r.text());
			const next = row.nextElementSibling;
			if (next) next.classList.add('no-hover');

			row.style.transition = 'opacity 0.2s ease';
			row.style.opacity = '0';
			setTimeout(() => {
				row.remove();
				if (next) next.classList.remove('no-hover');
			}, 220);
			showToast('🗑️ ' + tr('audit_entry_deleted', 'Audit-Eintrag gelöscht'), 'success');
		})
		.catch(err => {
			console.error('Audit delete failed:', err);
			showToast('❌ ' + (err.message || tr('audit_delete_failed', 'Löschen fehlgeschlagen')), 'error');
		});
}

async function refreshAuditLog() {
	const box = document.getElementById('audit-log-content');
	if (!box) return;
	box.textContent = tr('audit_loading', 'Audit-Einträge werden geladen…');
	box.classList.add('audit-loading');
	try {
		const response = await fetch('/api/audit', { cache: 'no-store' });
		const data = await response.json().catch(() => ({}));
		if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
		box.classList.remove('audit-loading');
		renderAuditEntries(data.entries || []);
	} catch (error) {
		box.classList.remove('audit-loading');
		box.innerHTML = '<div class="diag-error-box">❌ ' + escHtml(error.message || tr('audit_load_failed', 'Audit-Log konnte nicht geladen werden.')) + '</div>';
	}
}

function dnsValues(values) {
	if (!Array.isArray(values) || values.length === 0) return '<span class="dns-empty">–</span>';
	return values.map(value => '<code>' + escHtml(value) + '</code>').join('<br>');
}

function dnsMatchBadge(hasExpected, matches) {
	if (!hasExpected) return '<span class="dns-match dns-match-muted">' + escHtml(tr('dns_no_expected', 'kein Sollwert')) + '</span>';
	return matches
		? '<span class="dns-match dns-match-ok">' + escHtml(tr('dns_match_ok', 'passt')) + '</span>'
		: '<span class="dns-match dns-match-error">' + escHtml(tr('dns_match_mismatch', 'abweichend')) + '</span>';
}

function renderDNSPropagation(data) {
	const box = document.getElementById('dns-propagation-result');
	if (!box) return;
	const expectedV4 = String(data.expected_ipv4 || '');
	const expectedV6 = String(data.expected_ipv6 || '');
	const rows = (data.results || []).map(result => `<tr>
		<td><strong>${escHtml(result.resolver || '-')}</strong><small>${escHtml(result.address || '')}</small></td>
		<td>${dnsValues(result.ipv4)} ${dnsMatchBadge(Boolean(expectedV4), Boolean(result.match_ipv4))}</td>
		<td>${dnsValues(result.ipv6)} ${dnsMatchBadge(Boolean(expectedV6), Boolean(result.match_ipv6))}</td>
		<td>${result.error ? '<span class="dns-error">' + escHtml(result.error) + '</span>' : escHtml((result.duration_ms ?? 0) + ' ms')}</td>
	</tr>`).join('');

	box.innerHTML = `<div class="dns-summary">
		<strong>${escHtml(data.domain || '')}</strong>
		<span>${escHtml(tr('dns_expected_ipv4', 'IPv4-Soll'))}: <code>${escHtml(expectedV4 || '-')}</code></span>
		<span>${escHtml(tr('dns_expected_ipv6', 'IPv6-Soll'))}: <code>${escHtml(expectedV6 || '-')}</code></span>
 	</div>
	<div class="audit-table-wrap"><table class="audit-table dns-table">
		<thead><tr><th>${escHtml(tr('dns_col_resolver', 'Resolver'))}</th><th>${escHtml(tr('dns_col_ipv4', 'IPv4'))}</th><th>${escHtml(tr('dns_col_ipv6', 'IPv6'))}</th><th>${escHtml(tr('dns_col_duration_error', 'Dauer / Fehler'))}</th></tr></thead>
		<tbody>${rows || '<tr><td colspan="4">' + escHtml(tr('dns_no_results', 'Keine Ergebnisse.')) + '</td></tr>'}</tbody>
 	</table></div>`;
}

async function runDNSPropagation() {
	const input = document.getElementById('dns-propagation-domain');
	const box = document.getElementById('dns-propagation-result');
	const domain = String(input?.value || '').trim();
	if (!domain) {
		showToast(tr('dns_domain_required', '❌ Bitte eine Domain eingeben.'), 'error');
		input?.focus();
		return;
	}
	if (box) box.innerHTML = '<div class="audit-loading">' + escHtml(tr('dns_loading', 'DNS-Resolver werden abgefragt…')) + '</div>';

	try {
		const response = await fetch('/api/dns/propagation', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
			body: JSON.stringify({ domain }),
		});
		const data = await response.json().catch(() => ({}));
		if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
		renderDNSPropagation(data);
		refreshAuditLog();
	} catch (error) {
		if (box) box.innerHTML = '<div class="diag-error-box">❌ ' + escHtml(error.message || tr('dns_check_failed', 'DNS-Prüfung fehlgeschlagen.')) + '</div>';
	}
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
