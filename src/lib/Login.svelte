<script>
	import { onMount } from 'svelte';
	import { createEventDispatcher } from 'svelte';
	import { loginInfo } from '$lib/stores.js';

	export let service = '';
	export let username = '';
	let password = '';

	const loginURL  = `http://localhost:8080/podapi/login`;
	const logoutURL = `http://localhost:8080/podapi/logout`;
	// Dispatch 'success' on successful login
	const dispatch = createEventDispatcher();

	// Component state
	let waitingToken = true;
	let csrfToken = '';
	let errMsg = '';

	// Reactive variables
	let passwordField = null;
	let usernameField = null;
	let submitDisabled = true;

	// Get CSRF token, raise on error
	function getToken() {
		csrfToken = '';
		return fetch(loginURL, {
			credentials: 'include',
			headers: {
				'Accept': 'application/json'
			}
		})
		.then(parseResponse)
	}

	// Post the token, raise on error.
	function postToken() {
		let token = csrfToken;
		csrfToken = '';
		return fetch(loginURL, {
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
		})
		.then(parseResponse)
		.then(apiResponse => {
			if (apiResponse.username === "") {
				throw "invalid credentials";
			}
			return apiResponse;
		})
	}

	// Parse response promise, raise on error
	function parseResponse(response) {
		csrfToken = response.headers.get("X-Csrf-Token")
		if (response.status != 200) {
			return response.text().then(reason => {
				throw reason;
			})
		}
		return response.json()
		.then(apiResponse => {
			if (!!apiResponse.errMessage && apiResponse.errMessage !== "") {
				throw apiResponse.errMessage;
			}
			return apiResponse;
		})
	}

	// Get the first CSRF token
	onMount(async () => {
		waitingToken = true;
		errMsg = '';
		getToken()
		.then((apiResponse) => {
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
		})
		.catch(reason => {
			//errMsg = reason;
			console.log(reason);
		})
		.finally(() => {
			waitingToken = false;
		});
	});

	// Submit the form
	function clicked() {
		waitingToken = true;
		errMsg = '';
		let promise  = null;
		if (csrfToken != '') {
			promise = postToken();
		} else {
			// Need to get the token first,
			// and check the user is not logged in.
			promise = getToken()
			.then((apiResponse) => {
				// If the user is already logged in, no need to post
				if (apiResponse.username === "") {
					return postToken();
				}
			});
		}
		promise
		.then(apiResponse => {
			console.log('Dispatching success event', apiResponse);
			loginInfo.update(current => {
				current.username = apiResponse.username;
				current.service  = apiResponse.service;
				return current;
			})
			dispatch('success', apiResponse);
		})
		.catch(reason => {
			errMsg = reason;
			console.log(errMsg);
			// Mimic default post behaviour by cleaning password
			password = "";
			passwordField.focus()
		})
		.finally(() => {
			waitingToken = false;
		});
	}

	$: {
		submitDisabled = (username === "" || password === "" || service === "" || waitingToken);
	}
</script>

<form method="POST" action="/podapi/login" class:cursor_wait={waitingToken}>
	<fieldset>
		<legend>Inicio de sesión con Keystone</legend>
		<div class="container">
			<label for="username">Usuario</label>
			<input type="text" placeholder="Usuario" id="username" name="username" bind:value={username} bind:this={usernameField}/>
			<label for="password">Password</label>
			<input type="password" placeholder="password" id="password" name="password" bind:value={password} bind:this={passwordField}/>
			<label for="service">Servicio</label>
			<input type="text" placeholder="Servicio" id="service" name="service" bind:value={service} />
			<button on:click|preventDefault={clicked} disabled={submitDisabled}>Iniciar sesión</button>
			<div class:errbox={errMsg != ""} class="emptymsgbox">
				{errMsg}
			</div>
		</div>
	</fieldset>
</form>

<style>
	/* Labels to the left */
	div.container {
		display: grid;
		grid-template-columns: min-content auto;
		grid-gap: 1rem;
		padding: 16px;
	}
	div.container label {
		text-align: left;
	}
	div.container label:after {
		content: ':';
	}
	div.container div,button {
		grid-column: span 2;
	}
</style>
