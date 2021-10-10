<script>
	import { dev } from '$app/env';
	import { notifications } from '$lib/stores.js';
</script>

<svelte:head>
	<link href="/podstatic/css/bulma.min.css" rel="stylesheet">
	{#if dev}
	<link href="/css/bulma.min.css" rel="stylesheet">
	{/if}
</svelte:head>

<div class="toplevel">
	<section class="block">
		<slot />
	</section>
	<section class="block">
        <div class="notification is-danger is-light" class:d-none={$notifications.error === ""}>{$notifications.error}</div>
        <div class="notification is-info is-light" class:d-none={$notifications.info === ""}>{$notifications.info}</div>
	</section>
</div>

<style>
	.toplevel {
		width: 36rem;
		margin: 2rem;
	}
	.d-none {
		display: none;
	}
</style>