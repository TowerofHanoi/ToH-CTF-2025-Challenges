import { error } from '@sveltejs/kit';
import { BASE } from '$lib/api';

export async function load({ fetch, url }) {
	const options = {
		method: 'GET'
	};

	const products = await fetch(BASE + '/products', options).then((r) => r.json());
	const productMap = new Map(products.map((p) => [p.product_id, p]));

	const sessionResponse = await fetch(BASE + '/session', options);
	if (!sessionResponse.ok) {
		throw error(sessionResponse.status, await sessionResponse.text());
	}
	let state = await sessionResponse.json();
	console.log(state);

	if (state) {
		state.owned = state.owned.map((p) => ({
			product: productMap.get(p.product_id),
			count: p.count
		}));
		state.cart = state.cart.map((p) => ({
			product: productMap.get(p.product_id),
			count: p.count
		}));
		state.cartValue = state.cart.map((p) => p.product.price * p.count).reduce((a, b) => a + b, 0);
	}

	return {
		state: state,
		products: products
	};
}
