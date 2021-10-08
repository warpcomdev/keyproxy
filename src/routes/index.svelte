<script>
    import { base } from '$app/paths';
    import { goto } from '$app/navigation';
    import { podInfo } from '$lib/stores';
    import MsgBox from "$lib/MsgBox.svelte";
    import Info from "$lib/Info.svelte";
    import Toolbar from "$lib/Toolbar.svelte";

    // Bindings for Info
    let autoRefresh = 0;
    let triggerRefresh;
    let target = 0;

    // Bindings for MsgBox
    let errMsg = '';
    let infoMsg = '';

    function gotoLogin() {
        goto(base + "/login");
    }

    function updateTarget(newTarget, msg) {
        target = newTarget;
        errMsg  = "";
        infoMsg = msg;
        if (autoRefresh <= 0) {
            autoRefresh = 15;
        } else {
            triggerRefresh();
        }
    }

    function displayError(reason) {
        errMsg  = reason;
        infoMsg = "";
    }

    function onSpawn() {
        updateTarget(1, "Iniciando pod, por favor espere hasta que esté listo.");
    }

    function onKill() {
        updateTarget(0, "Eliminando pod, puede cerrar sesión.");
    }

    $: {
        // Clear info messages when target reached
        if (target == 0 && $podInfo.event === "DELETED") {
            infoMsg = '';
        }
        if (target == 1 && $podInfo.ready === true) {
            infoMsg = '';
        }
    }
</script>

<Info bind:autoRefresh bind:triggerRefresh target={target} on:login={gotoLogin} on:error={displayError}/>
<Toolbar on:logout={gotoLogin} on:error={displayError} on:spawn={onSpawn} on:kill={onKill}/>
<MsgBox infoMsg={infoMsg} errMsg={errMsg}/>
