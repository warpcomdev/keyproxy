<script>
    import { base } from '$app/paths';
    import { goto } from '$app/navigation';
    import { notifications } from '$lib/stores';
    import Info from "$lib/Info.svelte";
    import Toolbar from "$lib/Toolbar.svelte";

    // Bindings for Info
    let autoRefresh = 0;
    let triggerRefresh;

    function gotoLogin() {
        // Clean messages on navigation
        notifications.update(current => {
            current.error = "";
            current.info = "";
            return current;
        });
        goto(base + "/login");
    }

    function checkTrigger() {
        if (autoRefresh <= 0) {
            autoRefresh = 15;
        } else {
            triggerRefresh();
        }
    }
</script>

<div class="panel">
    <p class="panel-heading">Estado del pod</p>
    <div class="panel-block">
        <Info bind:autoRefresh bind:triggerRefresh on:login={gotoLogin}/>
    </div>
    <div class="panel-block">
        <Toolbar on:logout={gotoLogin} on:spawn={checkTrigger} on:kill={checkTrigger}/>
    </div>
</div>
