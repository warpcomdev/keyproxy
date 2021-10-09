<script>
    import { base } from '$app/paths';
    import { goto } from '$app/navigation';
    import { notifications, podInfo, targetAcquired } from '$lib/stores';
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

    function updateTarget(newTarget, msg) {
        podInfo.update(current => {
            current.target = newTarget;
            return current;
        })
        notifications.update(current => {
            current.info = msg;
            return current;
        });
        if (autoRefresh <= 0) {
            autoRefresh = 15;
        } else {
            triggerRefresh();
        }
    }

    function onSpawn() {
        updateTarget(1, "Iniciando pod, por favor espere hasta que esté listo.");
    }

    function onKill() {
        updateTarget(0, "Eliminando pod, puede cerrar sesión.");
    }

    $: {
        // Clean notification on target acquired
        if ($targetAcquired) {
            notifications.update(current => {
                current.info = "";
                return current;
            })
        }
    }
</script>

<Info bind:autoRefresh bind:triggerRefresh on:login={gotoLogin}/>
<Toolbar on:logout={gotoLogin} on:spawn={onSpawn} on:kill={onKill}/>
