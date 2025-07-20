<script lang="js">
	import {
		Card,
		Badge,
		Text,
		SimpleGrid,
		Button,
		Container,
		Stack,
		Title,
		Image,
		Space,
		Center,
		Group,
		Modal,
		Affix,
		Paper
	} from '@svelteuidev/core';
	import { CircleBackslash } from 'radix-icons-svelte';
	import { invalidateAll } from '$app/navigation';
	import { BASE } from '$lib/api';

	export let data;

	let modalOpen = false;
	let modalMessage = '';

	function closeModal() {
		modalOpen = false;
	}

	function showModal(msg) {
		modalMessage = msg;
		modalOpen = true;
	}

	async function purchase() {
		const options = {
			method: 'POST'
		};
		const resp = await fetch(BASE + '/cart/confirm', options);

		if (resp.ok) {
			invalidateAll();
		} else {
			showModal(resp.status + ': ' + (await resp.text()));
		}
	}

	async function addCart(e) {
		const product_id = parseInt(e.target.value);
		const product = data.products.find((p) => p.product_id == product_id);
		console.log(product);

		if (data.state.user.balance >= data.state.cartValue + product.price) {
			const options = {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ product_id: parseInt(e.target.value), count: 1 })
			};
			const resp = await fetch(BASE + '/cart/add', options);

			if (resp.ok) {
				invalidateAll();
			} else {
				showModal(resp.status + ': ' + (await resp.text()));
			}
		} else {
			showModal('Insufficient balance!');
		}
	}

	async function removeCart(product_id) {
		console.log(product_id);
		const options = {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ product_id: parseInt(product_id) })
		};
		const resp = await fetch(BASE + '/cart/rem', options);

		if (resp.ok) {
			invalidateAll();
		} else {
			showModal(resp.status + ': ' + (await resp.text()));
		}
	}

	async function logOut() {
		const options = {
			method: 'POST'
		};
		const resp = await fetch(BASE + '/logout', options);

		if (resp.ok) {
			invalidateAll();
			document.location = '/login';
		} else {
			showModal(resp.status + ': ' + (await resp.text()));
		}
	}

	async function ascend() {
		const options = {
			method: 'GET'
		};
		const resp = await fetch(BASE + '/flag', options);
		showModal((await resp.text()));
	}
</script>

<Modal centered opened={modalOpen} target={'body'} on:close={closeModal} withCloseButton={false}>
	<Text>{modalMessage}</Text>
</Modal>

<Container>
	<Stack spacing='xl'>
		<Center>
			<Title variant="gradient" weight="extrabold">Modern Digital Art Shop!</Title>
		</Center>
		<Group>
			<Paper>
				<Group>
					<Text>Balance:</Text>
					<Badge size="lg">{data.state.user.balance}</Badge>
					<Text>Cart:</Text><Badge size="lg">{data.state.cartValue}</Badge>
				</Group>
			</Paper>
		</Group>
		<SimpleGrid cols="3">
			{#each data.products as product}
				<Card p="lg">
					<Card.Section first padding="lg">
						<Image radius="md" src={product.image} height={200} alt="Random {product.name} image" />
					</Card.Section>
					<Stack>
						<Space />
						<Group>
							<Text size="xl" weight={500}>{product.name}</Text>
							<Badge>{product.price}</Badge>
						</Group>

						<Text size="sm">
							Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum
							has been the industry's standard dummy text ever since the 1500s, when an unknown
							printer took a galley of type and scrambled it to make a type specimen book.
						</Text>
						<Button on:click={addCart} value={product.product_id} fullSize>Add to Cart</Button>
					</Stack>
				</Card>
			{/each}
		</SimpleGrid>
	</Stack>
</Container>
<Affix position={{ top: 20, left: 20 }}>
	<Stack>
		<Paper>
			<Container size='xs'>
			<Stack>
				<Group>
					<Text
						>Logged in as <Text inherit root="a" variant="gradient">{data.state.user.username}</Text
						></Text
					>
					<Button variant="outline" size="xs" on:click={logOut}>Log Out</Button>
				</Group>
				<Title size="md">Owned</Title>
				{#each data.state.owned as p}
					<Card p="xs">
						<Group>
							<Image
								radius="md"
								src={p.product.image}
								height={32}
								width={32}
								alt="Random {p.product.name} image"
							/>
							<Text size="md">{p.product.name}</Text>
							<Badge>{p.count}</Badge>
						</Group>
					</Card>
				{/each}
				<Button on:click={ascend} variant="gradient" size="xl">SHOW OFF</Button>
			</Stack></Container></Paper
		>
		
		<Stack>
			{#each data.state.cart as p}
				<Card p="xs">
					<Group>
						<Image
							radius="md"
							src={p.product.image}
							height={32}
							width={32}
							alt="Random {p.product.name} image"
						/>
						<Text size="md">{p.product.name}</Text>
						<Badge>{p.count}</Badge>
						<Button
							size="xs"
							color="red"
							variant="outline"
							on:click={() => removeCart(p.product.product_id)}><CircleBackslash /></Button
						>
					</Group>
				</Card>
			{/each}
		</Stack>
		{#if data.state.cart.length > 0}
			<Button on:click={purchase}>Purchase</Button>
		{/if}
	</Stack>
</Affix>
<Affix position={{ top: 20, right: 20 }}>
	<Paper>
		<Container size={200} override={{px: 10}}>
		<Text>
			Since NFTs are not cool anymore, we decided to skip the blockchain and just
			sell you the rights <!-- lol  --> to digital images hosted on a centralized
			platform (we figured that it's what was happening often in practice, so why bother).
			
			Since sharing is caring, we also decide to allow users to buy duplicates. Revolutionary!<br/><br/>

			Anyway, if you want to show off properly to your discord friends, you need to have
			a proper collection, you know, like pokemon
		</Text>
		<Text variant='gradient'>Gotta catch them all!</Text>
	</Container>
	</Paper>
</Affix>
