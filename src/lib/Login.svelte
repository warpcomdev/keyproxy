<script>
	import { onMount } from 'svelte';
	import { createEventDispatcher } from 'svelte';
	import { loginInfo, notifications } from '$lib/stores.js';
	import { loginURL } from '$lib/urls.js';

	export let service = '';
	export let username = '';
	let password = '';

	// Dispatch 'success' on successful login
	const dispatch = createEventDispatcher();

	// Component state
	let waitingToken = true;
	let csrfToken = '';

	// Reactive variables
	let passwordField = null;
	let usernameField = null;
	let submitDisabled = true;

	// Get CSRF token, raise on error
	async function getToken() {
		csrfToken = '';
		let response = await fetch(loginURL, {
			credentials: 'include',
			headers: {
				'Accept': 'application/json'
			}
		})
		return await parseResponse(response);
	}

	// Parse response promise, raise on error
	async function parseResponse(response) {
		csrfToken = response.headers.get("X-Csrf-Token")
		if (response.status != 200) {
			return {
				username: "",
				errMessage: await response.text()
			};
		}
		let apiResponse = await response.json();
		if (!!apiResponse.errMessage) {
			apiResponse.username = "";
		}
		return apiResponse;
	}

	// Post the token, raise on error.
	async function postToken() {
		let token = csrfToken;
		csrfToken = '';
		let response = await fetch(loginURL, {
			method: 'POST',
			credentials: 'include',
			headers: {
				'X-Csrf-Token': token,
				'Accept': 'application/json',
			},
			body: new URLSearchParams({
				'username': username,
				'password': password,
				'service': service
    		})
		});
		let apiResponse = await parseResponse(response);
		if (!!apiResponse.errMessage) {
			throw apiResponse.errMessage;
		}
		return apiResponse;
	}

	// Get the first CSRF token
	onMount(async () => {
		waitingToken = true;
		try {
			let apiResponse = await getToken();
			if (apiResponse.username !== "") {
				console.log('Dispatching success event', apiResponse);
				loginInfo.update(current => {
					current.username = apiResponse.username;
					current.service  = apiResponse.service;
					return current;
				})
				dispatch('success', apiResponse);
				return;
			}
			usernameField.focus();
		} catch (reason) {
			console.log(reason);
		} finally {
			waitingToken = false;
		}
	});

	// Submit the form
	async function clicked() {
		waitingToken = true;
		let apiResponse;
		try {
			if (csrfToken === "") {
				apiResponse = await getToken();
				if (!!apiResponse.errMessage || apiResponse.username === "") {
					apiResponse = await postToken();
				};
			} else {
				apiResponse = await postToken();
			}
			// Cleaning error message
			notifications.update(current => {
				current.error = "";
				return current;
			})
			console.log('Dispatching success event', apiResponse);
			loginInfo.update(current => {
				current.username = apiResponse.username;
				current.service  = apiResponse.service;
				return current;
			})
			dispatch('success', apiResponse);
		} catch (reason) {
			notifications.update(current => {
				current.error = reason;
				return current;
			})
			console.log(reason);
			// Mimic default post behaviour by cleaning password
			password = "";
			passwordField.focus()
		} finally {
			waitingToken = false;
		}
	}

	$: {
		submitDisabled = (username === "" || password === "" || service === "" || waitingToken);
		if (!submitDisabled) {
			notifications.update(current => {
				current.error = "";
				return current;
			})
		}
	}
</script>

<form method="POST" action="/podapi/login" class:cursor_wait={waitingToken}>
	<div class="field">
		<label for="username" class="label">Usuario</label>
	</div>
	<div class="field has-addons">
		<div class="control is-expanded">
			<input type="text " class="input" placeholder="Usuario" id="username" name="username" bind:value={username} bind:this={usernameField}/>
		</div>
		<div class="control">
			<label for="service" class="button is-static">@ Servicio</label>
		</div>
		<div class="control">
			<input type="text" class="input" placeholder="Servicio" id="service" name="service" bind:value={service} />
		</div>
	</div>
	<div class="field">
		<label for="password" class="label">Password</label>
		<div class="control">
			<input type="password" class="input" placeholder="password" id="password" name="password" bind:value={password} bind:this={passwordField}/>
		</div>
	</div>
	<button class="button is-primary is-fullwidth" on:click|preventDefault={clicked} disabled={submitDisabled}>Iniciar sesión</button>
</form>

<style>
	.cursor_wait { cursor: wait; }
</style>