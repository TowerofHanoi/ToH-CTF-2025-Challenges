<script lang="js">
	import {
		Button,
		TextInput,
		Notification,
		Container,
		Text,
		Title,
		Stack,
		Group
	} from '@svelteuidev/core';
	import { BASE } from '$lib/api';

	let email;
	let password;

	let toastOpen = false;
	let toastMsg = '';

	function showToast(s) {
		toastMsg = s;
		toastOpen = true;
	}

	function closeToast() {
		toastOpen = false;
	}

	async function onRegister() {
		const options = {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username: email, password: password })
		};
		const result = await fetch(BASE + '/register', options);

		showToast(result.status + ' ' + (await result.text()));
	}

	async function onLogin() {
		const options = {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username: email, password: password })
		};
		const result = await fetch(BASE + '/login', options);

		showToast(result.status + ' ' + (await result.text()));
		if (result.ok) {
			document.location = '/home';
		}
	}
</script>

<Container size="xs" p="xl">
	<Stack>
		<Title variant="gradient">Login</Title>
		<TextInput
			type="email"
			name="username"
			id="exampleEmail"
			placeholder="email"
			bind:value={email}
		/>

		<TextInput
			type="password"
			name="password"
			id="examplePassword"
			placeholder="password"
			bind:value={password}
		/>

		<Group grow>
			<Button variant="outline" on:click={onRegister}>Register</Button>
			<Button variant="gradient" on:click={onLogin}>Login</Button>
		</Group>

		{#if toastOpen}
			<Notification on:close={closeToast}>
				<Text>
					Result: {toastMsg}
				</Text>
			</Notification>
		{/if}
	</Stack>
</Container>
