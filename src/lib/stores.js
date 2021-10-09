import { writable, derived } from 'svelte/store';

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
    ready: false,
    target: 0
});

export const notifications = writable({
    info: "",
    error: "",
});

export const targetAcquired = derived(podInfo, ($podInfo) => {
    return ($podInfo.target === 0 && $podInfo.event === "DELETED") || ($podInfo.target === 1 && $podInfo.ready === true);
});
