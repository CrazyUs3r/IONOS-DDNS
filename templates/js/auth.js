// Lightweight bootstrap for login, setup and standalone 2FA pages.
(() => {
	const root = document.documentElement;
	const savedTheme = localStorage.getItem('theme');
	const theme = savedTheme || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
	root.setAttribute('data-theme', theme);

	const sun = document.querySelector('.auth-sun');
	if (!sun) return;

	const now = new Date();
	const hour = now.getHours();
	const minutes = hour * 60 + now.getMinutes();

	let variables;
	if (hour >= 5 && hour < 11) {
		variables = {
			'--sky-1': '#9be7ff', '--sky-2': '#5b7cff', '--floor': '#172554',
			'--sun-core': 'rgba(255,230,120,0.95)', '--sun-glow': 'rgba(255,184,77,0.55)',
			'--grid-color': 'rgba(34,211,238,0.36)', '--horizon': 'rgba(56,189,248,0.75)',
			'--mountain': '#172554', '--mountain-dark': '#0f172a',
		};
	} else if (hour >= 11 && hour < 17) {
		variables = {
			'--sky-1': '#60a5fa', '--sky-2': '#3730a3', '--floor': '#111827',
			'--sun-core': 'rgba(34,211,238,0.95)', '--sun-glow': 'rgba(59,130,246,0.65)',
			'--grid-color': 'rgba(125,211,252,0.36)', '--horizon': 'rgba(59,130,246,0.8)',
			'--mountain': '#1e1b4b', '--mountain-dark': '#020617',
		};
	} else if (hour >= 17 && hour < 21) {
		variables = {
			'--sky-1': '#312e81', '--sky-2': '#db2777', '--floor': '#020617',
			'--sun-core': 'rgba(251,191,36,0.98)', '--sun-glow': 'rgba(236,72,153,0.7)',
			'--grid-color': 'rgba(244,114,182,0.42)', '--horizon': 'rgba(236,72,153,0.9)',
			'--mountain': '#1e1b4b', '--mountain-dark': '#020617',
		};
	} else {
		variables = {
			'--sky-1': '#020617', '--sky-2': '#1e1b4b', '--floor': '#020617',
			'--sun-core': 'rgba(34,211,238,0.98)', '--sun-glow': 'rgba(168,85,247,0.75)',
			'--grid-color': 'rgba(34,211,238,0.46)', '--horizon': 'rgba(34,211,238,0.95)',
			'--mountain': '#0f172a', '--mountain-dark': '#020617',
		};
	}

	for (const [name, value] of Object.entries(variables)) {
		root.style.setProperty(name, value);
	}

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
