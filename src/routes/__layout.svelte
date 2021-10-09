<script>
	import { notifications } from '$lib/stores.js';
</script>

<div class="toplevel">
	<slot />
    <div class="mt-3">
        <div class="alert alert-danger" class:d-none={$notifications.error === ""}>{$notifications.error}</div>
        <div class="alert alert-info" class:d-none={$notifications.info === ""}>{$notifications.info}</div>    
    </div>
</div>

<style>
	.toplevel {
		width: 42rem;
		margin: 3rem;
	}
</style>