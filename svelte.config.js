import adapter from '@sveltejs/adapter-static';
import preprocess from 'svelte-preprocess';

/** @type {import('@sveltejs/kit').Config} */
const config = {

	// Consult https://github.com/sveltejs/svelte-preprocess
	// for more information about preprocessors
	preprocess: preprocess(),

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
		target: '#svelte'
	}
};

export default config;
