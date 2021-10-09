<script>
	import { createEventDispatcher } from 'svelte';
	import { loginInfo, notifications, podInfo } from '$lib/stores.js';

	const logoutURL = "http://172.27.96.250:8080/podapi/logout";
	const killURL = "http://172.27.96.250:8080/podapi/kill";
	const spawnURL = "http://172.27.96.250:8080/podapi/spawn";

	// Dispatch events:
	// 'error': on error.
	// 'logout': when logged out.
	// 'spawn': after pod spawned.
	// 'kill': after pod killed.
	const dispatch = createEventDispatcher();
	
	function doGet(url, message) {
		return fetch(url, {
			credentials: 'include',
			headers: {
				'Accept': 'application/json'
			}
		})
		.then(response => {
			if (response.status != 200) {
				return response.text().then(text => { throw text; });
			}
			return response.json();
		})
		.then(() => {
			dispatch(message, message);
		})
		.catch(reason => {
			notifications.update(current => {
				current.error = reason;
				return current;
			});
			console.log(reason);
		})
	}

	function doLogout() {
		return doGet(logoutURL, 'logout');
	}

	function doSpawn() {
		return doGet(spawnURL, 'spawn');
	}

	function doKill() {
		return doGet(killURL, 'kill');
	}
</script>

<div class="btn-group d-flex" role="toolbar">
	<button class="btn btn-primary" on:click|preventDefault={doLogout} disabled={$loginInfo.username === ""}>Cerrar sesión</button>
	<button class="btn btn-primary" on:click|preventDefault={doSpawn}  disabled={$podInfo.event !== "DELETED"}>Arrancar el pod</button>
	<button class="btn btn-primary" on:click|preventDefault={doKill}   disabled={$podInfo.event === "DELETED"}>Eliminar pod</button>
</div>

<style>
</style>
