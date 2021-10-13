<script lang="ts">
	import { dev } from '$app/env';
	import { notifications } from '$lib/stores';
</script>

<svelte:head>
	<link href="/podstatic/css/bulma.min.css" rel="stylesheet">
	<link href="/podstatic/css/overrides.css" rel="stylesheet">
	{#if dev}
	<link href="/css/bulma.min.css" rel="stylesheet">
	<link href="/css/overrides.css" rel="stylesheet">
	{/if}
</svelte:head>

<div class="top-layout">
	<div class="block">
		<slot />
	</div>
	<div class="block">
		<div class="notification is-danger is-light" class:d-none={$notifications.error === ""}>{$notifications.error}</div>
		<div class="notification is-info is-light" class:d-none={$notifications.info === ""}>{$notifications.info}</div>
	</div>
</div>

<style>
	.d-none {
		display: none;
	}
</style>