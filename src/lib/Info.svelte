<script>
	import { onMount, onDestroy } from 'svelte';
	import { createEventDispatcher } from 'svelte';
	import { appInfo, loginInfo, podInfo, targetAcquired, notifications } from '$lib/stores.js';
	import { infoURL } from '$lib/urls.js';

	export let autoRefresh = 0; // seconds
	export const triggerRefresh = function() {
		if (podTimer !== null) {
			clearTimeout(podTimer);
		}
		if(autoRefresh > 0) {
			podTimer = setTimeout(refresh, 100);
		}
	}

	// Dispatch 'login' on auth failed, 'update' on status change
	const dispatch = createEventDispatcher();

	// Control del ciclo de refresco
	let lastUpdate = null;
	let podTimer = null;
	let waitingResponse = false;

	// Get pod info, raise on error
	async function getInfo() {
		waitingResponse = true;
		try {
			let response = await fetch(infoURL, {
				credentials: 'include',
				headers: {
					'Accept': 'application/json'
				}
			})
			if (response.status == 401) {
				// Generate a fake invalid credentials
				return {
					errMessage: await response.text(),
					username: "",
				};
			}
			if (response.status != 200) {
				throw await response.text();
			}
			return await response.json();
		} finally {
			waitingResponse = false;
		}
	}

	// Try to collect info for the first time
	onMount(async () => {
		await refresh();
	});

	// Clear refresh timer
	onDestroy(async () => {
		if (podTimer !== null) {
			clearTimeout(podTimer);
			podTimer = null;
		}
	})

	// Refresh the info
	async function refresh() {
		try {
			let apiResponse = await getInfo();
			if (!!apiResponse.errMessage || apiResponse.username === "") {
				console.log('Dispatching login event', apiResponse);
				dispatch('login', apiResponse);
				throw "Debe iniciar sesión en keystone";
			}
			loginInfo.update(current => {
				current.username = apiResponse.username;
				current.service = apiResponse.service;
				return current;
			});
			podInfo.update(current => {
				current.event = apiResponse.event_type;
			    current.phase = apiResponse.pod_phase;
    			current.ready = !!apiResponse.ready && apiResponse.ready && !!apiResponse.address && apiResponse.address !== "";
				return current;
			});
			appInfo.update(current => {
				current.host = apiResponse.appHost;
				current.scheme = apiResponse.appScheme;
				return current;
			});
			dispatch('update', apiResponse);
		} catch(reason) {
			notifications.update(current => {
				current.error = reason;
				return current;
			});
			console.log(reason);
		} finally {
			lastUpdate = (new Date()).toLocaleString();
			if (autoRefresh > 0) {
				if ($targetAcquired) {
					autoRefresh = 0;
				} else {
					podTimer = setTimeout(refresh, autoRefresh * 1000);
				}
			}
		}
	}

	$: {
		// Change timer depending on selected autoRefresh
		if ((autoRefresh > 0) && (podTimer === null)) {
			console.log("Arrancando timer")
			podTimer = setTimeout(refresh, 100);
		}
		if ((autoRefresh <= 0) && (podTimer !== null)) {
			console.log("Deteniendo timer")
			clearTimeout(podTimer);
			podTimer = null;
		}
	}
</script>

<table class="table is-fullwidth" class:cursor_wait={waitingResponse}>
	<tbody>
		<tr class="tr">
			<th class="th has-text-weight-normal">Nombre de usuario</th>
			<td class="td">{$loginInfo.username}</td>
		</tr>
		<tr class="tr">
			<th class="th has-text-weight-normal">Servicio</th>
			<td class="td">{$loginInfo.service}</td>
		</tr>
		<tr class="tr">
			<th class="th has-text-weight-normal">Última acción completada</th>
			<td class="td">{$podInfo.event}</td>
		</tr>
		<tr class="tr">
			<th class="th has-text-weight-normal">Estado actual de su pod</th>
			<td class="td">{$podInfo.phase}</td>
		</tr>
		<tr class="tr">
			<th class="th has-text-weight-normal">Acceso a aplicación</th>
			<td class="td">
				{#if $podInfo.ready}
				<a href="{$appInfo.scheme}://{$appInfo.host}" target="_blank" alt="Acceso a aplicación">Aplicación lista</a>
				{:else}
				No acepta conexión.
				{/if}
			</td>
		</tr>
		<tr class="tr">
			<th class="th has-text-weight-normal">Última actualización</th>
			<td class="td">{lastUpdate || ""}</td>
		</tr>
		<tr class="tr">
			<th class="th">
				<label for="autoRefresh" class="label has-text-weight-normal">Actualizar automáticamente</label>
			</th>
			<td class="td">
				<select id="autoRefresh" name="autoRefresh" class="select is-fullwidth" bind:value={autoRefresh} disabled={$targetAcquired}>
					<option value={0} >Desactivado</option>
					<option value={10}>Cada 10 segundos</option>
					<option value={15}>Cada 15 segundos</option>
					<option value={30}>Cada 30 segundos</option>
				</select>
			</td>
		</tr>
	</tbody>
</table>

<style>
	.cursor_wait { cursor: wait; }
</style>