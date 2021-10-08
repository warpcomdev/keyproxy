<script>
    export let infoMsg = '';
    export let errMsg = '';
</script>

<div class:errbox={errMsg != ""} class="emptymsgbox">
    {errMsg}
</div>
<div class:infobox={infoMsg != ""} class="emptymsgbox">
    {infoMsg}
</div>
