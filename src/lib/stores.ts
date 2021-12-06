import { writable, derived } from 'svelte/store';

// LoginInfo shares info about logged in user
type LoginInfo = {
    username: string;
    service: string;
}

// PodTarget sets the goal for the pod status
export enum PodTarget {
    Deleted = 0,
    Ready   = 1,
}

// PodInfo shares info about pod status
type PodInfo = {
    event:  string;
    phase:  string;
    ready:  boolean;
    target: PodTarget;
    paths: string[];
}

// Notifications ahres info about active notifications
type Notifications = {
    info: string;
    error: string;
}

export const loginInfo = writable<LoginInfo>({
    username: "",
    service: ""
});

export const podInfo = writable<PodInfo>({
    event: "",
    phase: "",
    ready: false,
    target: PodTarget.Deleted,
    paths: new Array(),
});

export const notifications = writable<Notifications>({
    info: "",
    error: "",
});

export const targetAcquired = derived(podInfo, ($podInfo) => {
    return ($podInfo.target === PodTarget.Deleted && $podInfo.event === "DELETED") || ($podInfo.target === PodTarget.Ready && $podInfo.ready === true);
});
