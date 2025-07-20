// The SSR breaks if using docker because Svelte devs did not consider this proxy setup 🤷
// I tried many things like setting hooks and forcing urls to be absolute, but the /home
// load() would always fail on fetch, if you are a Svelte wizard
export const ssr = false;
