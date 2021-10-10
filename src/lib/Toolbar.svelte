<script>
	import { createEventDispatcher } from 'svelte';
	import { loginInfo, notifications, podInfo } from '$lib/stores.js';
	import { logoutURL, killURL, spawnURL } from '$lib/urls.js';

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

<div class="buttons is-centered">
	<button class="button is-primary is-flex-grow-1" on:click|preventDefault={doLogout} disabled={$loginInfo.username === ""}>Cerrar sesión</button>
	<button class="button is-primary is-flex-grow-1" on:click|preventDefault={doSpawn}  disabled={$podInfo.event !== "DELETED"}>Arrancar el pod</button>
	<button class="button is-primary is-flex-grow-1" on:click|preventDefault={doKill}   disabled={$podInfo.event === "DELETED"}>Eliminar pod</button>
</div>
