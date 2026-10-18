---
tags: [htb-academy, web-pentest, javascript, deobfuscation, revision]
module: JavaScript Deobfuscation
---

# JavaScript Deobfuscation: Revision Notes

> **Legend:** Unmarked = from your module text. **(Extra)** = my own added explanation or example. **⚠ Verify** = unclear or inconsistent in the source.
> **Authorization:** Only analyse and interact with systems you are authorized to test.
> **Assessment note:** No flags, secret keys, or skills-assessment answers are included. Section 6 gives approach only.

---

## 1. Main Concepts: What, Why, How

### 1.1 Locating Client-Side Source Code

- **What:** Websites ship HTML (structure), CSS (design) and JavaScript (functionality) to your browser. All of it is readable client-side.
- **Why:** Understanding a page's client-side behaviour starts with its source. HTML comments can hold developer notes and sometimes sensitive info, and JS can reveal hidden functionality.
- **How:**
  1. Open the page in a browser.
  2. Press `CTRL+U` to open the source view (`view-source:http://SERVER_IP:PORT`).
  3. Read the HTML, including comments.
  4. Spot where CSS and JS live:
     - **Internal:** between `<style>` or `<script>` tags.
     - **External:** `<link rel="stylesheet" href="style.css">` for CSS, `<script src="secret.js"></script>` for JS.
  5. Click the referenced `.js` file to open it.
- **Example from source:** A page called "Secret Serial Generator" shows no visible functionality, but the source references an external `secret.js` that is unreadable because it's obfuscated.

### 1.2 Code Obfuscation

- **What:** Making a script hard for humans to read while it still works the same (performance may be slower). Usually done automatically by a tool.
- **Why it exists (use cases):**
  - Hide the original code to prevent copying or reuse and make reverse engineering harder.
  - Add a (weak) security layer around authentication or encryption. The source stresses that client-side authentication/encryption is **not recommended**.
  - **Most common use: malicious.** Attackers obfuscate scripts to evade Intrusion Detection and Prevention systems.
- **Why JavaScript specifically:** Interpreted languages (Python, PHP, JS) run without compilation. Python and PHP usually sit server-side (hidden from users), but JavaScript is sent to the user and executed in cleartext in the browser, so obfuscation is very common.
- **How (typical idea):** Tools turn the code into a dictionary of its words and symbols, then rebuild the original during execution by referencing that dictionary.
- **Why it matters in pentests/red-blue exercises:** You can't tell what obfuscated code does (e.g. malware fetching a payload) until you deobfuscate it.

### 1.3 Types of Obfuscation Covered

| Type | What it does | Recognise it by | Weakness |
|---|---|---|---|
| **Minification** | Puts the whole code on a single (often long) line; files often named `.min.js` | One long line | Easy to undo (beautify) |
| **Packing** | Moves words/symbols into a dictionary and rebuilds with an `eval(function(p,a,c,k,e,d){...})` wrapper | **Six function arguments `(p,a,c,k,e,d)`** | Main strings still visible in cleartext |
| **Advanced obfuscators** (e.g. obfuscator.io with String Array Encoding set to Base64) | Hides all original strings (variable names like `_0x1ec6`, hex indexes, base64 string array, decoding helpers) | Variables like `_0x....`, long string arrays | Harder for automated tools; may need manual reverse engineering |
| **Symbol-only encoders** (JJ Encode, AA Encode, JSF-style) | Rewrites code with a tiny character set (e.g. `[]`, `!`, `+`) | Walls of `[]()!+` characters | **Slow to execute**; used only for a clear reason such as bypassing web filters |

- **Notes from source:**
  - Packers vary, but the `(p,a,c,k,e,d)` signature is the typical tell.
  - Obfuscated code still runs. Verify by pasting it into JSConsole before and after.
  - Custom obfuscators (made by attackers or professional developers) are harder to deobfuscate than public ones.

### 1.4 Deobfuscation (Beautify → Unpack → Reverse Engineer)

- **What:** Turning obfuscated or minified code back into something understandable.
- **Why:** Reveals hidden functionality (including possibly unreleased features that "tend to have bugs and vulnerabilities").
- **How:**
  1. **Beautify** (pretty-print): fixes formatting only.
     - Firefox: open the debugger (`CTRL+SHIFT+Z`), select the script, click the `{ }` button.
     - Or use Prettier, beautifier.io, code-editor plugins.
  2. **Recognise that beautifying isn't enough:** if the code is also obfuscated, it's still hard to read.
  3. **Deobfuscate/unpack:** use a tool such as **UnPacker** (matthewfl.com/unPacker.html).
     - Tip from source: leave **no empty lines** before the script, or the result may be inaccurate.
  4. **Alternative for packed code:** find the return value at the end of the packer function and use `console.log` to print it instead of executing it.
  5. **Manual reverse engineering** for custom or heavily obfuscated code (the source points to the Secure Coding 101 module for more depth).
- **Example from source:** A packed `secret.js` unpacks to a `generateSerial()` function that creates an `XMLHttpRequest`, sets a URL, opens a POST request and sends it.

### 1.5 Code Analysis

- **What:** Reading deobfuscated code to work out what it does.
- **Why:** Lets you replicate the behaviour yourself and discover server-side functionality that isn't linked in the UI.
- **How (as shown in the module):**
  1. Read line by line; look up unfamiliar functions (the source Googles `XMLHttpRequest`).
  2. `XMLHttpRequest` = JavaScript object that handles web requests.
  3. `url` variable = a relative path (same domain if no domain is given).
  4. `xhr.open("POST", url, true)` = defines the request method and target.
  5. `xhr.send(null)` = sends the request.
  6. Conclusion in the source: the function just sends an **empty POST** to `/serial.php`, with no data and no handling of a response.
  7. Notice nothing on the page calls it, which suggests an **unused or future feature**.
  8. Next step: replicate the request yourself and see if the server handles it.

### 1.6 Replicating Requests with cURL

- **What:** Using the command-line `curl` to send the same HTTP request the JS would send.
- **Why:** Tests whether the hidden endpoint is live on the server without needing the browser UI.
- **How:**
  1. `curl` the page to confirm you get the same HTML as the source view.
  2. Add `-X POST` to send a POST.
  3. Add `-d "param=value"` to include POST data.
  4. Read the response (it may be encoded, see §1.7).

### 1.7 Encodings Often Found in Obfuscated Code

- **What:** Text transformations that obscure strings. Obfuscated code often contains encoded text that gets decoded at runtime. (Encryption, by contrast, uses a key and is much harder to reverse if the key isn't in the script.)
- **Why:** Responses and strings may look like gibberish until decoded.
- **The three covered:**

| Encoding | How to spot it | Key facts |
|---|---|---|
| **Base64** | Only alphanumerics plus `+` and `/`; **`=` padding** at the end; length is a multiple of 4 | Reduces special characters; works for any input incl. binary |
| **Hex** | Only characters `0-9` and `a-f` | Each character becomes its ASCII hex value (a = 61, b = 62, ...); `man ascii` shows the table |
| **Caesar / ROT13** | Looks random but keeps some structure (e.g. `http://www` → `uggc://jjj`) | Shifts each letter by a fixed amount; ROT13 shifts 13 (encode and decode are the same operation) |

- **How to handle unknown encodings:** First identify the type, then find a decoder. **Cipher Identifier** can suggest the encoding. There are hundreds of other encodings that may need experience.

---

## 2. Important Terminology

| Term | Short definition |
|---|---|
| **Obfuscation** | Making code hard to read while keeping the same function |
| **Deobfuscation** | Reversing obfuscation to understand the code |
| **Minification** | Putting code on one line (often `.min.js`) |
| **Beautify / Pretty Print** | Reformatting code for readability (does not undo obfuscation) |
| **Packing / Packer** | Dictionary-based obfuscation with a `(p,a,c,k,e,d)` function |
| **`eval()`** | JavaScript function that executes a string as code (seen wrapping packed code) |
| **Interpreted language** | Run without compilation (JS, Python, PHP) |
| **Client-side** | Code that runs in the user's browser |
| **Reverse engineering** | Working out how something works from its output or code |
| **XMLHttpRequest (XHR)** | JS object used to make web requests |
| **cURL** | Command-line tool for web requests |
| **POST data** | Parameters sent in the request body (`-d "param1=sample"`) |
| **Encoding** | Reversible text transformation with no key (base64, hex, ROT13) |
| **Encryption** | Encoding with a key; hard to reverse without it |
| **Padding (`=`)** | Characters that make base64 length a multiple of 4 |
| **ASCII** | Table mapping characters to numbers (hex values come from it) |
| **Caesar cipher / ROT13** | Fixed-shift letter substitution / the 13-shift version |
| **IDS/IPS** | Intrusion Detection / Prevention Systems (obfuscation tries to evade them) |
| **JSConsole** | Online JS console used to test that code still runs |

---

## 3. Commands and Tools

### 3.1 Browser Actions

| Action | Shortcut / steps | Purpose |
|---|---|---|
| View page source | `CTRL+U` (or `view-source:http://SERVER_IP:PORT`) | Read the HTML, comments and script references |
| Open an external script | Click the `src` link in the source view | Read the `.js` file |
| Open debugger (Firefox) | `CTRL+SHIFT+Z`, select the script | See the script with formatting options |
| Pretty Print | Click the `{ }` button at the bottom of the debugger | Beautify minified code |

### 3.2 Online Tools Mentioned

| Tool | Use |
|---|---|
| **JSConsole** (jsconsole.com) | Run JS to verify behaviour before/after obfuscation |
| **javascript-minifier.com** | Minify code |
| **BeautifyTools JS obfuscator** | Produce packed code (the `(p,a,c,k,e,d)` style) |
| **obfuscator.io** | Advanced obfuscation (e.g. String Array Encoding = Base64) |
| **JSF** | Symbol-only obfuscation (can run slowly) |
| **Prettier** (prettier.io/playground) / **beautifier.io** | Beautify code |
| **UnPacker** (matthewfl.com/unPacker.html) | Unpack packed JavaScript |
| **Cipher Identifier** | Help identify an unknown encoding |
| **rot13 online tool** | Encode/decode ROT13 |

### 3.3 Command-Line Reference

#### curl: fetch a page
```bash
curl http://SERVER_IP:PORT/
```
- **Purpose:** Request a URL and print the response as text.
- **How it works:** Sends a GET request and prints the body.
- **Expected result:** The same HTML you see in the browser's source view.
- **When to use:** Quick check of a page's HTML from the terminal.

#### curl: POST request
```bash
curl -s http://SERVER_IP:PORT/ -X POST
```
- **Flags:**
  - `-X POST`: use the POST method.
  - `-s`: silent mode; reduces clutter (progress/extra data).
- **Expected result:** Whatever the server returns for an empty POST.
- **When to use:** Replicating a request found in the JavaScript.

#### curl: POST with data
```bash
curl -s http://SERVER_IP:PORT/ -X POST -d "param1=sample"
```
- **Flags:** `-d "param1=sample"` = POST body parameter(s), one per parameter.
- **Expected result:** Server response, which may be plain or encoded.

#### curl: the module's example against the discovered endpoint
```bash
curl http://SERVER_IP:PORT/serial.php -X POST -d "param1=sample"
```
- **Purpose:** Replicate what the deobfuscated JS function does, with a sample parameter.
- **Expected result (per source description):** A block of text that appears encoded. Decode it using the methods below.
- **⚠ Verify:** Section 8 says "replicate what **server.js** is doing", but the script in the module is **secret.js**. This looks like a typo.
- **(Extra)** Only run this against an authorized target.

#### Base64 encode / decode
```bash
echo https://www.hackthebox.eu/ | base64
echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d
```
- **Flags:** `-d` = decode.
- **How it works:** `echo` outputs the text, `|` pipes it to `base64`.
- **Expected result:** Encoding produces an alphanumeric string (usually with `=` padding); decoding returns the original text.
- **(Extra)** `echo` adds a trailing newline, which becomes part of the encoded data. Use `echo -n` if you don't want it. **⚠ Verify** on your system.

#### Hex encode / decode
```bash
echo https://www.hackthebox.eu/ | xxd -p
echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r
```
- **Flags:** `-p` = plain hex dump format; `-r` = reverse (hex → text).
- **Expected result:** Encoding gives a string of `0-9a-f` characters; `-p -r` returns the text.
- **Helper:** `man ascii` shows the ASCII table.

#### ROT13 encode / decode
```bash
echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```
- **How it works:** `tr` maps each letter in the first set to the matching letter in the second (shifted by 13). Same command encodes and decodes.
- **Expected result:** `uggcf://jjj.unpxgurobk.rh/` for the example input, and the reverse for decode (per source).

#### Manual unpacking trick (from source, no exact syntax given)
- Find the **return value at the end** of the packer function and `console.log` it instead of running it through `eval`.
- **⚠ Verify:** The source describes this idea but gives no exact command. Try it in a browser console on a copy of the code.

---

## 4. Practical Workflow

1. **Get authorization and scope** for the target.
2. **View the page source** (`CTRL+U`). Read all HTML, including comments.
3. **Identify scripts.** Note internal `<script>` blocks and external `src` files.
4. **Open each JS file.** If it's readable, analyse it. If not, continue.
5. **Identify the obfuscation type:**
   - One long line → minified.
   - `eval(function(p,a,c,k,e,d)...` → packed.
   - `_0x....` names and string arrays → obfuscator.io-style.
   - Only `[]()!+` → symbol-based encoder.
6. **Beautify** (browser Pretty Print, Prettier, beautifier.io).
7. **Deobfuscate:** UnPacker for packed code, or `console.log` the packer's return value. For custom or heavy obfuscation, reverse engineer manually.
8. **Analyse the deobfuscated code:** variables, functions, URLs, HTTP methods, any data being sent.
9. **Look up unfamiliar functions** rather than guessing.
10. **Replicate the behaviour with cURL** (`-X POST`, `-d`).
11. **Inspect the response.** If it looks like gibberish, identify the encoding (base64 / hex / ROT13), then decode it.
12. **Use the decoded value** as the code suggests (e.g. send it back in a follow-up request).
13. **Document** the findings: what the code does, hidden endpoints, and any risks.

### Common Mistakes
- Assuming beautifying = deobfuscating.
- Leaving empty lines before pasted code in UnPacker.
- Executing unknown obfuscated code blindly. **(Extra)** Treat it as potentially malicious and analyse it safely.
- Not checking whether the deobfuscated code still behaves like the original.
- Guessing what a function does instead of looking it up.
- Forgetting that `echo` adds a newline when encoding **(Extra)**.
- Misidentifying encodings (check character set, `=` padding, length).
- Assuming an unlinked function is dead. The module's whole point is that it may be live on the server.

### Troubleshooting
- **UnPacker output looks wrong:** remove empty lines before the script; confirm it's actually packed.
- **Code is too obfuscated for tools:** reverse engineer manually or identify the custom obfuscator's approach.
- **Obfuscated code is slow:** expected for symbol-based encoders.
- **Decoding gives garbage:** try another encoding, or use Cipher Identifier.
- **cURL output is cluttered:** add `-s`.
- **Encoded output decodes to nothing useful:** it may be encrypted rather than just encoded.

---

## 5. Quick Revision Sheet

### 5.1 Top 10 Things to Remember
1. HTML = structure, CSS = design, JS = functionality, and all of it is visible client-side.
2. `CTRL+U` shows page source; always read HTML comments.
3. JS can be internal (`<script>`) or external (`<script src="...">`).
4. Obfuscation hides readability while keeping behaviour; it's used for IP protection, weak security and, most commonly, malware evasion.
5. Minification = one line; packing = the `(p,a,c,k,e,d)` signature; advanced obfuscators hide all strings.
6. Beautifying only fixes formatting; **unpacking/deobfuscation** is a separate step.
7. UnPacker works on packed code (no empty lines first), and `console.log` on the packer's return value is an alternative.
8. Custom obfuscators may require manual reverse engineering.
9. Replicate JS requests with `curl -s URL -X POST -d "param=value"`.
10. Spot encodings: base64 (alphanumeric + `=`, multiple of 4), hex (`0-9a-f`), ROT13 (structured gibberish); decode with `base64 -d`, `xxd -p -r`, `tr 'A-Za-z' 'N-ZA-Mn-za-m'`.

### 5.2 Compact Command Reference

| Task | Command |
|---|---|
| View source | `CTRL+U` / `view-source:http://SERVER_IP:PORT` |
| GET a page | `curl http://SERVER_IP:PORT/` |
| Empty POST | `curl -s http://SERVER_IP:PORT/ -X POST` |
| POST with data | `curl -s http://SERVER_IP:PORT/ -X POST -d "param1=sample"` |
| Base64 encode | `echo TEXT \| base64` |
| Base64 decode | `echo STRING \| base64 -d` |
| Hex encode | `echo TEXT \| xxd -p` |
| Hex decode | `echo STRING \| xxd -p -r` |
| ROT13 (both ways) | `echo TEXT \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| ASCII table | `man ascii` |

### 5.3 Encoding Spotting Cheat Sheet

| Looks like... | Likely |
|---|---|
| `A–Z a–z 0–9 + /` with trailing `=` | Base64 |
| Only `0–9 a–f` | Hex |
| Text with a familiar shape but shifted letters (`uggc://jjj`) | ROT13 / Caesar |
| Strange text decoded with a key | Encryption (key needed) |

### 5.4 Revision Questions

1. **What is the difference between minification and obfuscation?**
   Minification puts code on one line; obfuscation rewrites it to be hard to read (strings, names, structure), though both keep it functional.
2. **Why is obfuscation so common in JavaScript?**
   JS is sent to the user and executed in cleartext in the browser, unlike server-side Python/PHP.
3. **How do you recognise packed JavaScript?**
   An `eval(function(p,a,c,k,e,d){...})` wrapper with those six arguments.
4. **Why isn't beautifying enough?**
   It fixes formatting only; obfuscated names and structure remain.
5. **Name two ways to unpack packed code.**
   Use a tool like UnPacker, or `console.log` the packer's return value instead of executing it.
6. **What does the unpacked `generateSerial` function do in the module?**
   It sends an empty POST request to `/serial.php` via `XMLHttpRequest`.
7. **Why is an unused function interesting to a pentester?**
   It may be live on the server, and unreleased functionality tends to contain bugs and vulnerabilities.
8. **What do `-s`, `-X` and `-d` do in cURL?**
   `-s` silent output, `-X` sets the HTTP method, `-d` sends POST data.
9. **How do you identify base64?**
   Alphanumeric characters plus `+` and `/`, often ending in `=` padding, with length a multiple of 4.
10. **What is the difference between encoding and encryption?**
    Encoding is a keyless, reversible transformation; encryption uses a key, making it much harder to reverse without it.

### 5.5 Two-Minute Final Summary

Start every client-side investigation by reading the page source with `CTRL+U`, including HTML comments, and locating internal or external scripts. If a script is unreadable, it is probably obfuscated. Minification squeezes code onto one line; packing uses the `(p,a,c,k,e,d)` dictionary approach; advanced obfuscators hide every string behind encoded arrays; and symbol-only encoders make code slow. Attackers mainly use obfuscation to dodge IDS/IPS.

To deobfuscate: beautify first (Pretty Print, Prettier, beautifier.io), then unpack (UnPacker, or `console.log` the packer's return value), and fall back to manual reverse engineering for custom obfuscation.

Then analyse the code. In the module, a `generateSerial` function only sent an empty POST to `/serial.php`. Since nothing on the page used it, it hinted at a hidden server-side feature worth testing. Replicate with `curl -s URL -X POST -d "param=value"`.

If the response looks encoded, identify it: base64 (alphanumeric with `=`), hex (`0-9a-f`), or ROT13 (shifted letters). Decode with `base64 -d`, `xxd -p -r`, or `tr 'A-Za-z' 'N-ZA-Mn-za-m'`. Cipher Identifier can help, and if a key is needed you're dealing with encryption, not mere encoding.

---

## 6. Skills Assessment: Approach Only

The assessment is a chain: inspect the page source and find the script, run or analyse it, deobfuscate it, work out its request behaviour, replicate it with `curl`, decode the result, and send a follow-up POST. These notes contain no answers. Use the workflow in §4 and the encoding cheat sheet in §5.3.
