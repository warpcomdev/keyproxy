import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	kit: {
		// Generate static files
		adapter: adapter({
			pages:  'podstatic',
			assets: 'podstatic',
			fallback: null
		}),
		// Serve under /podstatic
		paths: {
			base:   '/podstatic',
		},
		// hydrate the <div id="svelte"> element in src/app.html
		target: '#svelte',
	}
};

export default config;
