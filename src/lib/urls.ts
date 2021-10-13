import { dev } from '$app/env';

export const infoURL   = dev ? `http://localhost:8080/podapi/info`   : "/podapi/info";
export const loginURL  = dev ? `http://localhost:8080/podapi/login`  : "/podapi/login";
export const logoutURL = dev ? `http://localhost:8080/podapi/logout` : "/podapi/logout";
export const killURL   = dev ? `http://localhost:8080/podapi/kill`   : "/podapi/kill";
export const spawnURL  = dev ? `http://localhost:8080/podapi/spawn`  : "/podapi/spawn";
