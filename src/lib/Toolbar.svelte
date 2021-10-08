<script>
	import { createEventDispatcher } from 'svelte';
	import { loginInfo, podInfo } from '$lib/stores.js';

	const logoutURL = "http://localhost:8080/podapi/logout";
	const killURL = "http://localhost:8080/podapi/kill";
	const spawnURL = "http://localhost:8080/podapi/spawn";

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
			console.log(reason);
			dispatch('error', reason);
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

<div class="container">
	<button on:click|preventDefault={doLogout} disabled={$loginInfo.username === ""}>Cerrar sesión</button>
	<button on:click|preventDefault={doSpawn}  disabled={$podInfo.event !== "DELETED"}>Arrancar el pod</button>
	<button on:click|preventDefault={doKill}   disabled={$podInfo.event === "DELETED"}>Eliminar pod</button>
</div>

<style>
	.container {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
	}
</style>
