<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { PodTarget, loginInfo, notifications, podInfo, targetAcquired } from '$lib/stores';
	import { logoutURL, killURL, spawnURL } from '$lib/urls';

	// Dispatch events:
	// 'error': on error.
	// 'logout': when logged out.
	// 'spawn': after pod spawned.
	// 'kill': after pod killed.
	const dispatch = createEventDispatcher();

	async function doGet(url: string, message: string): Promise<object> {
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

	// Notify components of the new target
	function updateTarget(newTarget: PodTarget, msg: string) {
        podInfo.update(current => {
            current.target = newTarget;
            return current;
        })
        notifications.update(current => {
            current.info = msg;
			current.error = "";
            return current;
        });
    }

	async function doLogout() {
		await doGet(logoutURL, 'logout');
	}

	async function doSpawn() {
		updateTarget(PodTarget.Ready, "Iniciando pod, por favor espere unos minutos hasta que esté listo.");
		await doGet(spawnURL, 'spawn');
	}

	async function doKill() {
		updateTarget(PodTarget.Deleted, "Eliminando pod, puede cerrar sesión.");
		await doGet(killURL, 'kill');
	}

	$: {
        // Clean notification on target acquired
        if ($targetAcquired) {
            notifications.update(current => {
                current.info = "";
                return current;
            })
        }
    }
</script>

<div class="buttons is-flex-grow-1">
	<button class="button is-primary is-flex-grow-1" on:click|preventDefault={doLogout} disabled={$loginInfo.username === ""}>Cerrar sesión</button>
	<button class="button is-primary is-flex-grow-1" on:click|preventDefault={doSpawn}  disabled={$podInfo.event !== "DELETED"}>Arrancar el pod</button>
	<button class="button is-primary is-flex-grow-1" on:click|preventDefault={doKill}   disabled={$podInfo.event === "DELETED"}>Eliminar pod</button>
</div>
