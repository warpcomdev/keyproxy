<script>
    import { base } from '$app/paths';
    import { goto } from '$app/navigation';
    import MsgBox from "$lib/MsgBox.svelte";
    import Info from "$lib/Info.svelte";
    import Toolbar from "$lib/Toolbar.svelte";

    let autoRefresh = 0;
    let errMsg = '';
    let infoMsg = '';
    let triggered = false;

    function gotoLogin() {
        goto(base + "/login");
    }

    function displayError(reason) {
        errMsg  = reason;
        infoMsg = "";
    }

    function displayInfo() {
        errMsg  = "";
        infoMsg = "Modificación realizada con éxito!"
        if (autoRefresh <= 0) {
            // will bet triggered by the change in autorefresh
            autoRefresh = 15;
        } else {
            triggered = true;
        }
    }
</script>

<Info bind:autoRefresh bind:triggered on:login={gotoLogin} on:error={displayError}/>
<Toolbar on:logout={gotoLogin} on:error={displayError} on:spawn={displayInfo} on:kill={displayInfo}/>
<MsgBox infoMsg={infoMsg} errMsg={errMsg}/>
