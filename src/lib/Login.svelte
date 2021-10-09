<script>
	import { onMount } from 'svelte';
	import { createEventDispatcher } from 'svelte';
	import { loginInfo, notifications } from '$lib/stores.js';

	export let service = '';
	export let username = '';
	let password = '';

	const loginURL  = `http://172.27.96.250:8080/podapi/login`;
	const logoutURL = `http://172.27.96.250:8080/podapi/logout`;
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
			console.log(reason);
		})
		.finally(() => {
			waitingToken = false;
		});
	});

	// Submit the form
	function clicked() {
		waitingToken = true;
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
		})
		.catch(reason => {
			notifications.update(current => {
				current.error = reason;
				return current;
			})
			console.log(reason);
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
		if (!submitDisabled) {
			notifications.update(current => {
				current.error = "";
				return current;
			})
		}
	}
</script>

<form method="POST" action="/podapi/login" class:cursor_wait={waitingToken}>
	<fieldset>
		<legend>Inicio de sesión con Keystone</legend>
		<div class="container">
			<label for="username" class="form-label">Usuario</label>
			<div class="input-group">
				<input type="text " class="form-control" placeholder="Usuario" id="username" name="username" bind:value={username} bind:this={usernameField}/>
				<label for="service" class="form-label m-2">@ Servicio</label>
				<input type="text" class="form-control" placeholder="Servicio" id="service" name="service" bind:value={service} />
			</div>
			<label for="password" class="form-label mt-2">Password</label>
			<input type="password" class="form-control" placeholder="password" id="password" name="password" bind:value={password} bind:this={passwordField}/>
			<div class="d-grid mt-4">
			<button class="btn btn-primary" on:click|preventDefault={clicked} disabled={submitDisabled}>Iniciar sesión</button>
			</div>
		</div>
	</fieldset>
</form>
