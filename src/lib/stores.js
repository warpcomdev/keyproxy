import { readable, writable } from 'svelte/store';

export const appInfo = writable({
    scheme: "",
    host: ""
});

export const loginInfo = writable({
    username: "",
    service: ""
});

export const podInfo = writable({
    event: "",
    phase: "",
    ready: false
});
