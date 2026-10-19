// Lightweight bootstrap for login, setup and standalone 2FA pages.

function tr(key, fallback = '') {
	const val = window.I18N?.[key];
	return (typeof val === 'string' && val.trim() !== '') ? val : fallback;
}

// ---- Passwort-Sichtbarkeit (identisch in auth.js und dashboard.js) ----
function setPasswordVisibility(btn, input, show) {
	input.type = show ? 'text' : 'password';
	btn.textContent = show ? '🙈' : '👁️';

	const label = show
		? tr('password_hide', 'Passwort ausblenden')
		: tr('password_show', 'Passwort anzeigen');

	btn.setAttribute('aria-pressed', String(show));
	btn.setAttribute('aria-label', label);
	btn.setAttribute('title', label);
}

function setupPasswordToggles() {
	document.addEventListener('click', event => {
		const btn = event.target.closest?.('[data-toggle-password]');
		if (!btn) return;

		const input = document.getElementById(btn.dataset.togglePassword);
		if (!input) return;

		setPasswordVisibility(btn, input, input.type === 'password');
	});
}

(() => {
	const root = document.documentElement;
	let savedTheme = null;
	try { savedTheme = localStorage.getItem('theme'); } catch { /* Storage blockiert */ }
	const theme = savedTheme || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
	root.setAttribute('data-theme', theme);
	setupPasswordToggles();

	const sun = document.querySelector('.auth-sun');
	if (!sun) return;

	const now = new Date();
	const hour = now.getHours();
	const minutes = hour * 60 + now.getMinutes();

	const skyTime = hour >= 5 && hour < 11 ? 'morning'
		: hour >= 11 && hour < 17 ? 'day'
			: hour >= 17 && hour < 21 ? 'evening'
				: 'night';
	root.setAttribute('data-sky-time', skyTime);

	const dayStart = 5 * 60;
	const dayEnd = 21 * 60;
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

	root.style.setProperty('--sun-x', `${12 + progress * 76}%`);
	root.style.setProperty('--sun-y', `${30 - Math.sin(progress * Math.PI) * 24}%`);
})();
