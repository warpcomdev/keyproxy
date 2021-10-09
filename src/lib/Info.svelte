<script>
	import { onMount, onDestroy } from 'svelte';
	import { createEventDispatcher } from 'svelte';
	import { appInfo, loginInfo, podInfo, targetAcquired, notifications } from '$lib/stores.js';

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

	const infoURL = "http://172.27.96.250:8080/podapi/info";

	// Control del ciclo de refresco
	let lastUpdate = null;
	let podTimer = null;

	// Get pod info, raise on error
	async function getInfo() {
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
    			current.ready = apiResponse.ready && apiResponse.address && apiResponse.address !== "";
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

<div class="container">
	<dl>
		<div class="row">
			<dt class="col">Nombre de usuario</dt><dd class="col">{$loginInfo.username}</dd>
		</div>
		<div class="row">
			<dt class="col">Servicio</dt><dd class="col">{$loginInfo.service}</dd>
		</div>
		<div class="row">
			<dt class="col">Última acción completada</dt><dd class="col">{$podInfo.event}</dd>
		</div>
		<div class="row">
			<dt class="col">Estado actual de su pod</dt><dd class="col">{$podInfo.phase}</dd>
		</div>
		<div class="row">
			<dt class="col">Acceso a aplicación</dt>
			<dd class="col">
				{#if $podInfo.ready}
				<a href="{$appInfo.scheme}://{$appInfo.host}" target="_blank" alt="Acceso a aplicación">Aplicación lista</a>
				{:else}
				No acepta conexión.
				{/if}
			</dd>
		</div>
		<div class="row mb-2">
			<dt class="col">Última actualización</dt>
			<dd class="col">{lastUpdate || ""}</dd>
		</div>
	</dl>
</div>
<div class="input-group mb-4">
	<label for="autoRefresh" class="input-group-text">Refrescar automáticamente</label>
	<select id="autoRefresh" name="autoRefresh" class="form-select" bind:value={autoRefresh}>
		<option value={0} >Desactivado</option>
		<option value={10}>Cada 10 segundos</option>
		<option value={15}>Cada 15 segundos</option>
		<option value={30}>Cada 30 segundos</option>
	</select>
</div>
