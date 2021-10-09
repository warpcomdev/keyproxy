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
	
	async function doGet(url, message) {
		try {
			let response = await fetch(url, {
				credentials: 'include',
				headers: {
					'Accept': 'application/json'
				}
			});
			if (response.status != 200) {
				throw await response.text();
			}
			let apiResponse = await response.json();
			dispatch(message, message);
			return apiResponse;
		} catch (reason) {
			notifications.update(current => {
				current.error = reason;
				return current;
			});
			console.log(reason);
		}
	}

	async function doLogout() {
		return await doGet(logoutURL, 'logout');
	}

	async function doSpawn() {
		return await doGet(spawnURL, 'spawn');
	}

	async function doKill() {
		return await doGet(killURL, 'kill');
	}
</script>

<div class="btn-group d-flex" role="toolbar">
	<button class="btn btn-primary" on:click|preventDefault={doLogout} disabled={$loginInfo.username === ""}>Cerrar sesión</button>
	<button class="btn btn-primary" on:click|preventDefault={doSpawn}  disabled={$podInfo.event !== "DELETED"}>Arrancar el pod</button>
	<button class="btn btn-primary" on:click|preventDefault={doKill}   disabled={$podInfo.event === "DELETED"}>Eliminar pod</button>
</div>

<style>
</style>
