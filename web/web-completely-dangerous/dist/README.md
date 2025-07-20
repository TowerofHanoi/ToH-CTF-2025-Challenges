# Completely Dangerous<br><small style="color: #888;font-size: 20px;">handout @ ToH CTF 2025</small>
<span style="background-color: #121212; padding: 4px; border-radius: 3px; margin-right: 2px;">Category: `web`</span> <span style="background-color: #121212; padding: 4px; border-radius: 3px; margin-right: 2px;">Author: [Ricy](https://github.com/riccardosarro)</span>

> I am developing this app with a beautiful feature that allows users to color and choose their name and color. But... I believe something is not right.

**NOTE**: The bot uses a custom Firefox profile with saved credentials. For testing purposes, you will find fake credentials in the distributed sources, useful just for testing. However, the remote server uses different credentials. Brute-forcing is not an intended solution. Your goal is to find a way to leak the credentials and retrieve the flag!

**NOTE2**: Bot is deployed with environment variables `APP_HOST=completely-dangerous.ctf.towerofhanoi.it`

app: https://completely-dangerous.ctf.towerofhanoi.it
bot: https://bot.completely-dangerous.ctf.towerofhanoi.it

## Local testing
You can run locally to test the app using docker (easy way). You can run the following command to start the app:

```bash
docker compose up --build
```

