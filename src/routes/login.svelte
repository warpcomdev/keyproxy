<script>
    import { base } from '$app/paths';
    import { goto } from '$app/navigation';
    import Login from "$lib/Login.svelte";

    function gotoInfo() {
        goto(base + "/");
    }
</script>

<Login on:success={gotoInfo}/>


