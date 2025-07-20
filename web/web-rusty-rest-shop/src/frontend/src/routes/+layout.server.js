import { redirect } from '@sveltejs/kit';
export function load({ url }) {
	if (url.pathname === '/') {
		throw redirect(307, '/login');
	}
}
