<script>
    import { base } from '$app/paths';
    import { goto } from '$app/navigation';
    import Login from "$lib/Login.svelte";

    function gotoInfo() {
        goto(base + "/");
    }
</script>

<div class="panel">
	<p class="panel-heading">Inicio de sesión en Keystone</p>
	<div class="panel-block">
        <Login on:success={gotoInfo}/>
    </div>
</div>
