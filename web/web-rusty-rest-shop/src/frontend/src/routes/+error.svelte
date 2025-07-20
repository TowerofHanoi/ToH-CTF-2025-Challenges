<script>
	import { Text, Title, Container, Stack, Code, Center, Space } from '@svelteuidev/core';
	import { page } from '$app/stores';
</script>

<Container size="xs" p="xl">
	<Stack>
		<Space h={100} />
		<Title>Something went <Text inherit variant="gradient" root="a">Wrong</Text>! 🫠</Title>
		<Center>
			<Code color="red" size="xl" align="center">{$page.status}: {$page.error.message}</Code>
		</Center>
	</Stack>
</Container>
