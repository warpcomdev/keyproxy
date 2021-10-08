<script>
	import { onMount, onDestroy } from 'svelte';
	import { createEventDispatcher } from 'svelte';
	import { appInfo, loginInfo, podInfo } from '$lib/stores.js';

	export let target  = 0; // 0 = deleted, 1 = ready
	export let autoRefresh = 0; // seconds
	export const triggerRefresh = function() {
		if (podTimer !== null) {
			clearTimeout(podTimer);
		}
		if(autoRefresh > 0) {
			podTimer = setTimeout(function() { podPromise = refresh(); }, 100);
		}
	}

	// Dispatch 'login' on auth failed, 'update' on status change
	const dispatch = createEventDispatcher();

	const infoURL = "http://localhost:8080/podapi/info";

	// Control del proceso de actualización
	let podPromise = null;

	// Control del ciclo de refresco
	let lastUpdate = null;
	let podTimer = null;

	// Get pod info, raise on error
	function getInfo() {
		return fetch(infoURL, {
			credentials: 'include',
			headers: {
				'Accept': 'application/json'
			}
		})
		.then((response) => {
			if (response.status == 401) {
				// Generate a fake invalid credentials
				return response.text().then((text) => {
					return {
						errMessage: text,
						username: "",
					}
				});
			}
			if (response.status != 200) {
				return response.text().then(text => { throw text });
			}
			return response.json();
		});
	}

	// Try to collect info for the first time
	onMount(async () => {
		podPromise = refresh()
	});

	// Clear refresh timer
	onDestroy(async () => {
		if (podTimer !== null) {
			clearTimeout(podTimer);
			podTimer = null;
		}
	})

	// Refresh the info
	function refresh() {
		return getInfo()
		.then((apiResponse) => {
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
				//current.host = apiResponse.appHost;
				//current.scheme = apiResponse.appScheme;
			});
			dispatch('update', apiResponse);
		})
		.catch(reason => {
			dispatch('error', reason);
			console.log(reason);
		})
		.finally(() => {
			lastUpdate = (new Date()).toLocaleString();
			podPromise = null;
			if (autoRefresh > 0) {
				if ($podInfo.event === "DELETED" && target == 0) {
					// Si el target es 0, cortamos el refresco cuando esté borrado.
					autoRefresh = 0;
				} else if ($podInfo.ready === true && target == 1) {
					// Si el target es 1, cortamos el refresco cuando esté listo.
					autoRefresh = 0;
				} else {
					podTimer = setTimeout(refresh, autoRefresh * 1000);
				}
			}
		});
	}

	$: {
		// Change timer depending on selected autoRefresh
		if ((autoRefresh > 0) && (podTimer === null)) {
			console.log("Arrancando timer")
			podTimer = setTimeout(function() { podPromise = refresh(); }, 100);
		}
		if ((autoRefresh <= 0) && (podTimer !== null)) {
			console.log("Deteniendo timer")
			clearTimeout(podTimer);
			podTimer = null;
		}
	}
</script>

<div>
	<dl class="container">
		<dt>Nombre de usuario</dt><dd>{$loginInfo.username}</dd>
		<dt>Servicio</dt><dd>{$loginInfo.service}</dd>
		<dt>Última acción completada</dt><dd>{$podInfo.event}</dd>
		<dt>Estado actual de su pod</dt><dd>{$podInfo.phase}</dd>
		<dt>Acceso a aplicación</dt><dd>
			{#if $podInfo.ready}
			<a href="{$appInfo.scheme}://{$appInfo.host}" target="_blank">Aplicación lista</a>
			{:else}
			No acepta conexión.
			{/if}
		</dd>
	</dl>
	<div class="container">
		<span>Última actualización</span><span>{lastUpdate || ""}</span>
		<span>Refrescar automáticamente:</span>
		<select bind:value={autoRefresh}>
			<option value={0} >Desactivado</option>
			<option value={10}>Cada 10 segundos</option>
			<option value={15}>Cada 15 segundos</option>
			<option value={30}>Cada 30 segundos</option>
		</select>
	</div>
	<div class:infobox={podPromise !== null} class="emptyinfobox">
		{#await podPromise}
		Recuperando información de su pod...
		{/await}
	</div>
</div>

<style>
	.container {
		display: grid;
		grid-template-columns: max-content auto;
		grid-gap: 1rem;
		padding: 16px;
		border: 1px solid white;
	}
	select {
		width: max-content;
	}
	dl dd {
    	font-weight: bold;
	}
	dl dt:after {
    	content: ':';
	}
</style>
