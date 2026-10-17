---
tags: [htb-academy, web-pentest, fuzzing, revision]
module: Web Fuzzing
---

# Web Fuzzing: Revision Notes

> **Legend:** Everything unmarked comes from your module text. Anything marked **(Extra)** is my own added explanation or example. Anything marked **⚠ Verify** is uncertain or inconsistent in the source, so check it against `--help` or the docs before relying on it.
> **Authorization:** Only fuzz targets you are explicitly authorized to test.

---

## 1. Main Concepts: What, Why, How

### 1.1 Web Fuzzing

- **What:** Automated testing of a web app by sending it many unexpected, malformed or random inputs and watching how it reacts.
- **Why:**
  - Finds flaws manual testing can miss.
  - Automates repetitive input generation and sending.
  - Mimics attacker behaviour.
  - Exposes weak input validation (e.g. SQLi, XSS).
  - Fits into CI/CD for continuous security testing.
- **How:**
  1. Choose a scope (login page, one API endpoint, etc.).
  2. Pick a wordlist or payload set.
  3. Let a fuzzer send the payloads.
  4. Analyse the responses (status code, size, words, lines, error messages).
  5. Validate anything interesting by hand.
- **Fuzzing vs brute-forcing:**

| Fuzzing | Brute-forcing |
|---|---|
| Wide net: malformed data, invalid characters, odd combinations | Targeted: systematically try many possibilities for **one specific value** (password, ID) |
| Goal: see how the app handles unexpected input | Goal: guess the correct value |

  - Door analogy from the source: fuzzing throws everything at the door (keys, screwdriver, rubber duck). Brute-forcing tries every combination on one key ring.
  - For beginners the terms are often used interchangeably.

### 1.2 Directory and File Fuzzing

- **What:** Probing a web server with a wordlist of names to find hidden directories and files.
- **Why:** Hidden assets can hold sensitive data (backups, configs, logs), outdated vulnerable content, dev/staging/admin resources, and undocumented features. They often lack the protection of public pages.
- **How:**
  1. Put `FUZZ` in the URL where the wordlist entry should go (`http://IP:PORT/FUZZ`).
  2. The tool replaces `FUZZ` with each word and sends a request.
  3. It filters responses by status code, size, etc.
  4. For files, add extensions with `-e`.
- **Example (Extra):** Finding `config.php.bak` could expose DB credentials (the source gives this idea too).
- **Common extensions in the source:** `.php`, `.html`, `.txt`, `.bak`, `.js`.

### 1.3 Recursive Fuzzing

- **What:** Automatically fuzzing inside every directory the fuzzer discovers, to explore nested structures.
- **Why:** Saves time, is thorough, needs less manual effort, and scales to large apps.
- **How:**
  1. Fuzz the web root.
  2. A valid directory is found (e.g. a `301` response).
  3. The tool queues a new job on `.../found-dir/FUZZ`.
  4. Repeat until the depth limit is reached or nothing new is found.
- **Mental model:** The web root is the trunk, directories are branches, files are leaves.
- **Be responsible:** It can be resource-intensive. Limit it with `-recursion-depth`, `-rate` and `-timeout`.

### 1.4 Parameter and Value Fuzzing

- **What:** Manipulating parameter values (or names) in requests to see how the app processes them.
- **Why:** Parameters are the "gateways" into the app. Changing them can reveal pricing errors, unauthorized access, hidden features, or injection flaws (XSS, SQLi).
- **How (GET):**
  1. Probe manually with `curl` to learn the app's behaviour (missing vs invalid value).
  2. Put `FUZZ` in the parameter value.
  3. Hide the noise (e.g. 404s).
  4. Look for the response that differs from the rest.
- **How (POST):** The same idea, but the payload goes in the request **body** (`-d "y=FUZZ"`) and you set the `Content-Type` header.
- **GET vs POST:**

| GET | POST |
|---|---|
| Parameters in the URL after `?`, joined with `&` | Parameters in the request body |
| Visible (like a postcard); used for non-state-changing actions (search, filter) | Less visible (sealed envelope); used for sensitive data (logins, personal/financial data) |

- **POST encodings:** `application/x-www-form-urlencoded` (key=value pairs joined with `&`) and `multipart/form-data` (used when uploading files).

### 1.5 Virtual Host (vhost) and Subdomain Fuzzing

- **What:**
  - **Virtual hosts:** Multiple sites served from one server/IP, chosen by the HTTP `Host` header.
  - **Subdomains:** Extensions of a domain (`blog.example.com`), resolved through DNS records.
- **Why:** Misconfigured vhosts can expose internal apps or sensitive data. Mismanaged DNS can lead to subdomain takeover.
- **How:**
  - **vhost:** Gobuster takes each word, appends the base domain, and sends the request with that modified `Host` header. Compare the responses.
  - **Subdomain:** Gobuster generates names from the wordlist, appends the domain, and tries to resolve them via DNS. A name that resolves is valid.

| | Virtual Hosts | Subdomains |
|---|---|---|
| Identified by | `Host` header | DNS records |
| Purpose | Multiple sites on one server | Organise sections/services |
| Risk | Exposed internal apps | Subdomain takeover |

### 1.6 Filtering Fuzzing Output

- **What:** Using tool options to show or hide responses by status code, size, word count, line count, regex, or time.
- **Why:** Fuzzers produce huge output. Filtering is how you spot the one useful result among thousands of 404s.
- **How:**
  1. Find the pattern of the "noise" (e.g. every 404 has the same size).
  2. Hide it (`-fc`, `-fs`, `--hc`, etc.) or match only what you want (`-mc`, `-ms`, `--sc`).
  3. Combine several filters.
- **Key point:** ffuf already filters by default (matches `200-299,301,302,307,401,403,405,500`). With `-mc all` you get flooded with 404s.

### 1.7 Validating Findings

- **What:** Confirming a fuzzer hit is a real issue and not a false positive.
- **Why:** Confirms the vulnerability, shows its impact, makes it reproducible, and gives evidence for stakeholders.
- **How:**
  1. Reproduce the request with `curl` or a browser.
  2. Analyse the response (errors, unexpected content).
  3. Only with authorization, attempt a controlled, harmless proof of concept.
  4. Prefer low-impact checks. The source suggests checking **headers** (`curl -I`) rather than downloading sensitive files.
- **Example from the source:** A `/backup/` directory returns 200 and lists files. `curl -I` on a file shows `Content-Type` and `Content-Length`. A length above 0 means the file has real content.
- **PoC principle:** Show the vulnerability exists without causing damage. For SQLi, a harmless query that returns the DB version, not data extraction.

### 1.8 Web APIs and Endpoint Identification

- **What:** A Web API lets software applications communicate over the web. It is a bridge between a server and a client.
- **Why it matters for fuzzing:** You fuzz API **endpoints and parameters**, not hidden pages. You need to know where the endpoints are first.
- **API types:**

| Type | Key traits | Endpoint model |
|---|---|---|
| **REST** | Stateless; HTTP methods (GET/POST/PUT/DELETE) for CRUD; JSON/XML | Many URLs (`/users`, `/users/123`) |
| **SOAP** | XML messages in envelopes; WSDL describes the interface; built-in security/reliability features | Typically a **single** endpoint; the message content picks the operation |
| **GraphQL** | Query language; request exactly the data you need; strongly typed, introspection | Typically a **single** endpoint (like `/graphql`) |

- **REST parameter types:** Query (`/users?limit=10&sort=name`), Path (`/products/{id}`), Request Body (JSON in POST/PUT/PATCH).
- **Discovering endpoints/parameters:**
  - **REST:** API docs (Swagger/OpenAPI, RAML), network traffic analysis (Burp, browser dev tools), parameter name fuzzing (ffuf/wfuzz).
  - **SOAP:** WSDL analysis, traffic analysis (Wireshark/tcpdump), fuzzing parameter names/values.
  - **GraphQL:** Introspection, documentation (GraphiQL, GraphQL Playground), traffic analysis.
- **GraphQL basics:**
  - **Query** = fetch data (fields, relationships, nested objects, arguments).
  - **Mutation** = modify data (operation, arguments, selection).
- **Web server vs API:** A web server mainly serves pages to browsers. An API lets applications talk to each other and exchange data (JSON/XML), usually not used directly by people.

### 1.9 API Fuzzing

- **What:** Fuzzing tailored to web APIs. You send slightly modified requests to endpoints.
- **Why:** Uncovers hidden/undocumented endpoints, tests robustness against malformed input, and automates testing.
- **Types:**

| Type | Focus | Can reveal |
|---|---|---|
| **Parameter fuzzing** | Values in query params, headers, bodies | Injection, XSS, parameter tampering |
| **Data format fuzzing** | Structure/content/encoding of JSON/XML | Parsing errors, buffer overflows, bad handling of special chars |
| **Sequence fuzzing** | Order and timing of requests across endpoints | Race conditions, IDOR, authorization bypass |

- **How (from the source's demo):**
  1. Read the auto-generated docs (`/docs`) to learn the documented endpoints.
  2. Remember that hidden endpoints may exist (internal use, "security through obscurity", still in development).
  3. Run a wordlist-based API fuzzer to find undocumented endpoints.
  4. Compare the results against the docs. An endpoint that is valid but not documented is a finding.
  5. A `405 Method Not Allowed` hints you used the wrong HTTP method.
- **Further risks to test (from source):** Broken Object-Level Authorization, Broken Function-Level Authorization, SSRF.

---

## 2. Important Terminology

| Term | Short definition |
|---|---|
| **Fuzzing** | Sending unexpected/malformed/random input to see how the app reacts |
| **Brute-forcing** | Systematically trying many values for one specific target (password, ID) |
| **Wordlist** | List of names/values used as input (e.g. `common.txt`) |
| **Payload** | The actual data sent to the app |
| **Response analysis** | Studying status codes, errors and sizes to spot anomalies |
| **Fuzzer** | Tool that generates, sends and analyses payloads (ffuf, wfuzz, Burp Intruder) |
| **False positive** | Reported as a vulnerability but harmless |
| **False negative** | Real vulnerability the fuzzer missed |
| **Fuzzing scope** | The part of the app being targeted |
| **`FUZZ` keyword** | Placeholder in the URL/data that gets replaced by each wordlist entry (ffuf) |
| **SecLists** | Large open-source collection of wordlists |
| **Recursive fuzzing** | Auto-fuzzing inside each directory found |
| **Virtual host (vhost)** | One of several sites on one server, chosen by the `Host` header |
| **Subdomain** | Hierarchical extension of a domain, resolved via DNS |
| **Subdomain takeover** | Attack possible when DNS records are mismanaged |
| **GET / POST parameter** | Parameter in the URL / in the request body |
| **API / REST / SOAP / GraphQL** | See §1.8 |
| **Endpoint** | A URL (or operation) where an API accepts requests |
| **WSDL** | XML file describing a SOAP service's operations and message formats |
| **Swagger / OpenAPI** | Machine-readable API specification |
| **Introspection** | GraphQL feature that returns the schema of the API |
| **Query / Mutation** | GraphQL read operation / write operation |
| **IDOR** | Insecure Direct Object Reference (accessing objects by changing an identifier) |
| **PoC** | Proof of concept: harmless demonstration of a vulnerability |
| **TTFB** | Time to first byte (used by ffuf's `-mt`) |
| **Status codes seen** | 200 OK, 301 Moved Permanently, 404 Not Found, 405 Method Not Allowed |

---

## 3. Commands and Tools

### 3.0 Tools at a Glance

| Tool | Language | Best for (per source) |
|---|---|---|
| **ffuf** | Go | Fast directory/file/parameter fuzzing, brute force |
| **Gobuster** | Go | Content discovery, DNS subdomains, vhosts |
| **FeroxBuster** | Rust | Fast **recursive** content discovery (more "forced browsing" than a fuzzer) |
| **wenum** (fork of wfuzz) | Python | Parameter fuzzing; wfuzz syntax is interchangeable |

**Wordlists mentioned (SecLists):**

| Path under `Discovery/` | Notes |
|---|---|
| `Web-Content/common.txt` | General purpose, good starting point |
| `Web-Content/DirBuster-2007_directory-list-2.3-medium.txt` | Directory-focused, deeper |
| `Web-Content/raft-large-directories.txt` | Massive directory list |
| `Web-Content/big.txt` | Very large; directories and files |
| `DNS/subdomains-top1million-5000.txt` | Top 5000 subdomains |

- On Pwnbox the folder is `/usr/share/seclists/` (lowercase). Other distros may use `SecLists`, so check the path if a command fails.

---

### 3.1 Setup and Installation

#### Go, Python, pipx (Debian-based)

```bash
sudo apt update
sudo apt install -y golang
sudo apt install -y python3 python3-pip
sudo apt install pipx
pipx ensurepath
sudo pipx ensurepath --global
go version
python3 --version
```

- **Purpose:** Install the prerequisites. `pipx` installs Python apps in isolated environments so dependencies don't conflict.
- **Expected result:** `go version` and `python3 --version` print version info if installation worked.

#### Install the fuzzers

```bash
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

- **Notes:**
  - `go install` puts binaries in your Go bin directory. **(Extra)** Make sure it is on your `PATH` if the command isn't found.
  - **(Extra, safety)** The FeroxBuster line pipes a remote script into `sudo bash`. Consider downloading and reading the script first.
  - `pipx runpip wenum install setuptools` installs `setuptools` into wenum's environment. The source says wfuzz has install complications, so wenum is a substitute.

---

### 3.2 ffuf: Directory Fuzzing

**Command**
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ
```
- **Purpose:** Discover hidden directories on a web server.
- **Flags:**
  - `-w` path to the wordlist
  - `-u` target URL; `FUZZ` marks where words are inserted
- **How it works:**
  1. Read each word in the wordlist.
  2. Substitute it for `FUZZ` and send a GET request.
  3. Apply the default matcher (`200-299,301,302,307,401,403,405,500`).
  4. Print matches with Status, Size, Words, Lines.
- **Expected result:** A list of matching paths. A `301` suggests a directory (a redirect to the version with a trailing slash).
- **When to use:** First step of content discovery on an in-scope web app.

---

### 3.3 ffuf: File Fuzzing with Extensions

**Command**
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP:PORT/DIRECTORY/FUZZ -e .php,.html,.txt,.bak,.js -v
```
- **Purpose:** Find files inside a known directory by trying common extensions.
- **Flags:**
  - `-e` comma-separated extensions appended to each word
  - `-v` verbose: shows full URL and the FUZZ value per hit
- **How it works:** For each word, ffuf requests the plain word and each word + extension.
- **Expected result:** Hits with status, size, words, lines, and the full URL.
- **When to use:** After finding a directory, to look for pages, backups and scripts.
- **(Extra) Example:** Replace `DIRECTORY` with a directory found in the previous step.

---

### 3.4 ffuf: Recursive Fuzzing

**Command**
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -v -u http://IP:PORT/FUZZ -e .html -recursion
```
- **Purpose:** Fuzz directories and then automatically fuzz inside every directory found.
- **Flags:**
  - `-recursion` fuzz discovered directories automatically
  - `-ic` ignore comment lines (starting with `#`) in the wordlist
  - `-e .html` also try the `.html` extension
  - `-v` verbose output
- **How it works:** When a directory is found, ffuf logs `Adding a new job to the queue` and later `Starting queued job` for that path.
- **Expected result:** Jobs for each nested level, with files like `index.html` found at different depths. Compare sizes to spot files that stand out.

**Throttled / limited version**
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -e .html -recursion -recursion-depth 2 -rate 500
```
- `-recursion-depth 2` limits depth to two levels. `-rate 500` caps the request rate at 500 per second.
- `-timeout` sets the per-request timeout. The source mentions it but doesn't show a value. **⚠ Verify** the unit and usage with `ffuf -h`.
- **When to use:** Always consider limiting depth and rate on real engagements to avoid overloading the server.

---

### 3.5 curl: Manual Probing and Validation

| Command | Purpose |
|---|---|
| `curl http://IP:PORT/get.php` | Send a GET with no parameter to see how the app responds |
| `curl http://IP:PORT/get.php?x=1` | Test a GET parameter value by hand |
| `curl -d "" http://IP:PORT/post.php` | `-d` makes a POST; empty body shows what parameter the script expects |
| `curl -d "y=VALUE" http://IP:PORT/post.php` | Send a specific POST value |
| `curl http://IP:PORT/backup/` | Check if a directory listing is exposed |
| `curl -I http://IP:PORT/backup/password.txt` | `-I` fetches only headers (Content-Type, Content-Length) without the body |

- **How `curl -I` works:** It requests headers only, so you can judge file type and size without downloading sensitive content.
- **Expected result:** `Content-Type: text/plain` and a `Content-Length` above 0 means the file is non-empty.
- **When to use:** Before fuzzing (to learn behaviour) and after (to validate a hit).

---

### 3.6 wenum: GET Parameter Value Fuzzing

**Command**
```bash
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://IP:PORT/get.php?x=FUZZ"
```
- **Purpose:** Find the parameter value that produces a different response.
- **Flags:**
  - `-w` wordlist
  - `--hc 404` hide responses with status 404 (wenum logs every request by default)
  - `-u` URL with `FUZZ` in the parameter value
- **How it works:** Each wordlist entry replaces `FUZZ`. wenum prints code/lines/words/size per request.
- **Expected result:** Almost all responses repeat the "Invalid parameter value" message. One stands out (e.g. a 200 with a different size).
- **Next step:** Validate the standout value with `curl`.
- **When to use:** Testing parameters whose values are checked by the server.

---

### 3.7 ffuf: POST Parameter Fuzzing

**Command**
```bash
ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
```
- **Purpose:** Fuzz a POST body parameter.
- **Flags:**
  - `-X POST` HTTP method
  - `-H` custom header (sets the body encoding)
  - `-d "y=FUZZ"` request body with the payload position
  - `-mc 200` match only status 200
  - `-v` verbose
- **How it works:** Same loop as the GET case, but `FUZZ` sits inside the POST body.
- **Expected result:** Mostly filtered noise. The correct value appears as a distinct 200 hit.
- **Without `-mc`:** Defaults apply. With `-mc all` you flood on 404s (illustrates why filtering matters).

---

### 3.8 Gobuster: vhost Fuzzing

**Setup (hosts file)**
```bash
echo "IP inlanefreight.htb" | sudo tee -a /etc/hosts
```
- Adds a hostname to `/etc/hosts` so it resolves to the lab IP. Use `IP` of your spawned lab (placeholder here).

**Command**
```bash
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain
```
- **Purpose:** Find virtual hosts on a server by changing the `Host` header.
- **Flags:**
  - `vhost` mode
  - `-u` base URL (including port)
  - `-w` wordlist
  - `--append-domain` appends the base domain to each word (e.g. `admin.inlanefreight.htb`)
- **Expected result:** `Found:` lines with status and size. Focus on `200` results (e.g. an `admin.` vhost in the source's demo). Lines with `400` are likely noise.
- **When to use:** When one IP may host several sites or hidden internal apps.

---

### 3.9 Gobuster: DNS Subdomain Fuzzing

**Command (as in source)**
```bash
gobuster dns -d inlanefreight.com -w /usr/share/seclists/DNS/subdomains-top1million-5000.txt
```
- **Purpose:** Enumerate subdomains by trying to resolve candidates.
- **Flags:** `dns` mode, `-d` target domain, `-w` wordlist.
- **⚠ Version note from source:** In the latest Gobuster, `-d` sets the **delay between requests**. Use `--do` or `--domain` for the target domain.
  - **(Extra, based on that note)** Likely form on a new version: `gobuster dns --domain inlanefreight.com -w <wordlist>`. **⚠ Verify** with `gobuster dns -h`.
- **Expected result:** `Found: subdomain.domain` lines for names that resolve.
- **When to use:** Mapping the attack surface of an in-scope domain.

---

### 3.10 Gobuster: Content Filtering (dir mode)

```bash
gobuster dir -u http://example.com/ -w wordlist.txt -s 200,301 --exclude-length 0
```

| Flag | Meaning |
|---|---|
| `-s` | Include only these status codes (`dir` mode only) |
| `-b` | Exclude these status codes (`dir` mode only) |
| `--exclude-length` | Exclude by content length (comma-separated, ranges supported) |

- **Example from source:** Show only 200/301 and drop empty responses.

---

### 3.11 ffuf Filtering Reference

| Flag | Meaning |
|---|---|
| `-mc` | Match status codes (single, list, range; `all` allowed). Default: 200-299, 301, 302, 307, 401, 403, 405, 500 |
| `-fc` | Filter out status codes |
| `-ms` / `-fs` | Match / filter by response size |
| `-mw` / `-fw` | Match / filter by word count |
| `-ml` / `-fl` | Match / filter by line count |
| `-mt` | Match by time-to-first-byte (e.g. `>500` ms) |

**Examples from source**
```bash
ffuf -u http://example.com/FUZZ -w wordlist.txt -mc 200 -fw 427 -ms >500
ffuf -u http://example.com/FUZZ -w wordlist.txt -fc 404,401,302
ffuf -u http://example.com/FUZZ.bak -w wordlist.txt -fs 0-10239 -ms 10240-102400
ffuf -u http://example.com/FUZZ -w wordlist.txt -mt >500
```
- **(Extra) Shell tip:** In a shell, `>500` is a redirection. Quote it (`-ms ">500"`) so it is passed to ffuf. **⚠ Verify** this syntax with `ffuf -h`.
- **How to read them:** Example 1 keeps status 200, drops responses with 427 words, keeps sizes over 500. Example 3 looks for `.bak` files between roughly 10 KB and 100 KB.

---

### 3.12 wenum Filtering Reference

| Flag | Meaning |
|---|---|
| `--hc` / `--sc` | Hide / show status codes |
| `--hl` / `--sl` | Hide / show by line count |
| `--hw` / `--sw` | Hide / show by word count |
| `--hs` / `--ss` | Hide / show by size |
| `--hr` / `--sr` | Hide / show by regex on the body |
| `--filter` / `--hard-filter` | Regex show/hide; `--hard-filter` also prevents plugin post-processing |

**Examples from source**
```bash
wenum -w wordlist.txt --sc 200,301,302 -u https://example.com/FUZZ
wenum -w wordlist.txt --hc 404,400,500 -u https://example.com/FUZZ
wenum -w wordlist.txt --sw 5-10 -u https://example.com/FUZZ
wenum -w wordlist.txt --hs 10000 -u https://example.com/FUZZ
wenum -w wordlist.txt --sr "admin\|password" -u https://example.com/FUZZ
```
- **⚠ Verify:** The source has one example written as `wenu` (a typo for `wenum`). The regex alternation `\|` in the last example depends on the regex flavor. Check with `wenum --help`.
- **⚠ Verify:** The source describes `--hl`/`--sl` as "length (in lines)" and `--hs`/`--ss` as size. Confirm the exact meaning in `--help`.

---

### 3.13 FeroxBuster Filtering Reference

| Flag | Meaning |
|---|---|
| `--url` | Target URL (as used in the source's example) |
| `-w` | Wordlist (as used in the source's example) |
| `--dont-scan` | Exclude URLs/patterns from scanning (even if found during recursion) |
| `-S`, `--filter-size` | Exclude by size |
| `-X`, `--filter-regex` | Exclude by regex on body/headers |
| `-W`, `--filter-words` | Exclude by word count/range |
| `-N`, `--filter-lines` | Exclude by line count/range |
| `-C`, `--filter-status` | Exclude status codes (denylist) |
| `--filter-similar-to` | Exclude pages similar to a reference page |
| `-s`, `--status-codes` | Include only these status codes (allowlist; default all) |

**Example from source**
```bash
feroxbuster --url http://example.com -w wordlist.txt -s 200 -S 10240 -X "error"
```
- **⚠ Verify:** The source describes this as "excluding responses larger than 10KB", but `-S` is described elsewhere as excluding a **specific size** (e.g. `-S 1024`). Check `feroxbuster --help` before relying on this example.

---

### 3.14 API Fuzzer (course repo)

```bash
git clone https://github.com/PandaSt0rm/webfuzz_api.git
cd webfuzz_api
pip3 install -r requirements.txt
python3 api_fuzzer.py http://IP:PORT
```
- **Purpose:** Wordlist-based discovery of undocumented API endpoints.
- **How it works:** Requests each candidate path, records status codes, and summarises valid endpoints and unusual codes.
- **Expected result (per source description):** Mostly 404s, a few valid endpoints (documented ones like `/docs` plus any undocumented one), and unusual codes such as 405 listed separately.
- **When to use:** Comparing real endpoints against the documented ones.
- **Note:** This is a course-provided tool and I've only used the syntax shown above. Check the repo's README for other options.

---

## 4. Practical Workflow

1. **Confirm authorization and scope.** Know exactly which hosts, paths and rates are allowed.
2. **Learn the target manually.** Use `curl` or a browser to see normal behaviour (missing vs invalid parameters, headers, error messages). Check `/docs` or other documentation for APIs.
3. **Pick the right wordlist.** Start small (`common.txt`), then move to larger lists such as `DirBuster-2007_directory-list-2.3-medium.txt`, `raft-large-directories.txt` or `big.txt` if needed. Use `-ic` when lists contain `#` comments.
4. **Discover directories, then files.** Use `FUZZ` in the URL, then add `-e` extensions on interesting directories.
5. **Go recursive when the structure is nested.** Set `-recursion`, plus `-recursion-depth` and `-rate` to stay polite.
6. **Fuzz parameters.** GET: `FUZZ` in the URL. POST: `-d "param=FUZZ"` with `-H` for the content type.
7. **Expand the attack surface.** Fuzz vhosts (`gobuster vhost`) and subdomains (`gobuster dns`).
8. **For APIs:** Find endpoints (docs, traffic, introspection, WSDL), then fuzz endpoints and parameters.
9. **Filter the noise.** Identify the common "boring" response (size/words/lines/status) and filter it out.
10. **Interpret results.** Look for outliers in status code, size, word count or line count.
11. **Validate manually.** Reproduce with `curl`, prefer header checks (`-I`), keep PoCs harmless.
12. **Document.** Record the request, response evidence and impact for the report.

### Common Mistakes
- Forgetting `FUZZ` (or placing it in the wrong spot).
- Not filtering, so 404s bury real results (or filtering so hard you hide real ones).
- Using the wrong wordlist path (`seclists` vs `SecLists`).
- Using the wrong HTTP method or content type for POST fuzzing.
- Forgetting `--append-domain` in vhost mode.
- Forgetting the hosts-file entry for a lab vhost.
- Using Gobuster's `-d` as the domain on the latest version (it is a delay now; use `--do`/`--domain`).
- Running unlimited recursion at full speed against a fragile server.
- Treating every hit as a vulnerability instead of validating it.
- Downloading or opening sensitive files when a header check would prove the point.

### Troubleshooting
- **Command not found after `go install`:** Check that your Go bin directory is on `PATH` **(Extra)**.
- **Wordlist not found:** Check the SecLists path for your distro.
- **Everything matches (or nothing does):** Adjust `-mc`/`-fc`/size filters. Use `-mc all` temporarily to see what the server really returns.
- **Many identical hits:** Filter by size, words or lines.
- **wfuzz won't install:** Use wenum (same syntax per the source).
- **Gobuster flag errors:** Check the version and flag meanings with `-h`.

---

## 5. Quick Revision Sheet

### 5.1 Top 10 Things to Remember
1. Fuzzing = wide net of unexpected input; brute-forcing = targeted guessing of one value.
2. `FUZZ` is the placeholder that the wordlist replaces (ffuf).
3. Wordlists come from external files; SecLists is the standard collection.
4. A `301` in directory fuzzing often means a directory was found.
5. `-e` adds extensions for file fuzzing; `-recursion` explores nested directories.
6. Limit recursion with `-recursion-depth`, `-rate`, `-timeout`.
7. GET params go in the URL; POST params go in the body (`-d`) with a `Content-Type` header.
8. vhosts are found through the `Host` header (`gobuster vhost --append-domain`); subdomains through DNS (`gobuster dns`).
9. Filtering (match vs filter) is what makes fuzz output readable.
10. Always validate manually, with the least intrusive method (e.g. `curl -I`), and stay within authorization.

### 5.2 Compact Command Reference

| Task | Command |
|---|---|
| Directory fuzz | `ffuf -w WORDLIST -u http://IP:PORT/FUZZ` |
| File fuzz | `ffuf -w WORDLIST -u http://IP:PORT/DIR/FUZZ -e .php,.html,.txt,.bak,.js -v` |
| Recursive fuzz | `ffuf -w WORDLIST -ic -v -u http://IP:PORT/FUZZ -e .html -recursion` |
| Limit recursion | add `-recursion-depth 2 -rate 500` |
| GET value fuzz | `wenum -w WORDLIST --hc 404 -u "http://IP:PORT/page.php?x=FUZZ"` |
| POST value fuzz | `ffuf -u http://IP:PORT/page.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w WORDLIST -mc 200 -v` |
| vhost fuzz | `gobuster vhost -u http://HOST:PORT -w WORDLIST --append-domain` |
| Subdomain fuzz | `gobuster dns -d DOMAIN -w WORDLIST` (**⚠ Verify**: newer versions use `--do`/`--domain`) |
| Header-only check | `curl -I URL` |
| Manual POST | `curl -d "y=VALUE" URL` |
| API endpoint fuzz | `python3 api_fuzzer.py http://IP:PORT` |
| Add vhost to hosts | `echo "IP name.htb" \| sudo tee -a /etc/hosts` |

### 5.3 Common Mistakes to Avoid
- No filtering, or wrong filtering.
- Wrong wordlist path or wrong HTTP method/content type.
- Missing `--append-domain` or hosts-file entry for vhosts.
- Gobuster `-d` confusion in newer versions.
- Unthrottled recursive scans.
- Reporting unvalidated hits.
- Touching sensitive file contents unnecessarily.

### 5.4 Revision Questions

1. **What is the difference between fuzzing and brute-forcing?**
   Fuzzing sends unexpected or malformed input broadly to see how the app reacts. Brute-forcing systematically tries many possibilities for one specific value.
2. **What does `FUZZ` do in ffuf?**
   It marks where each wordlist entry is inserted into the URL, header or data.
3. **What does a 301 usually suggest during directory fuzzing?**
   A redirect, often to the directory with a trailing slash, so a directory exists.
4. **Which ffuf flag enables recursion, and which limits its depth?**
   `-recursion` enables it, `-recursion-depth` limits it.
5. **Which flag adds file extensions in ffuf?**
   `-e`.
6. **How do you send POST data in ffuf?**
   `-X POST`, `-H "Content-Type: ..."`, and `-d "param=FUZZ"`.
7. **Why use `curl -I` when validating a finding?**
   It shows headers (type, size) without downloading file contents, which is less intrusive.
8. **What does `--append-domain` do in Gobuster vhost mode?**
   It appends the base domain to each word so the `Host` header is a full hostname.
9. **How do GraphQL and SOAP endpoints differ from REST in structure?**
   GraphQL and SOAP usually expose a single endpoint, while REST uses many resource URLs.
10. **What are the three primary API fuzzing types?**
    Parameter fuzzing, data format fuzzing and sequence fuzzing.

### 5.5 Two-Minute Final Summary

Fuzzing automates sending many unexpected inputs to a web app and analysing responses to find hidden content and flaws. The core loop is the same everywhere: pick a wordlist, mark the injection point with `FUZZ`, send, filter the noise, then validate by hand.

Use **ffuf** for directories, files (`-e`), recursion (`-recursion`, with depth and rate limits) and POST bodies (`-d`). Use **wenum** for GET parameter values. Use **Gobuster** for vhosts (`--append-domain`) and DNS subdomains. **FeroxBuster** is a fast recursive content discovery tool.

Filters decide whether you see signal or noise. Match (`-mc`, `--sc`, `-s`) or hide (`-fc`, `--hc`, `-C`) by status, and use size, words, lines, regex or time as needed.

APIs need their endpoints identified first: REST via docs and traffic, SOAP via WSDL, GraphQL via introspection. Then fuzz parameters, data formats and request sequences. Undocumented endpoints (found by comparing fuzz results with the docs) are a key finding.

Always validate with minimal-impact checks like `curl -I`, keep PoCs harmless, stay within scope, and throttle your scans.

---

## 6. Skills Assessment: Approach Only

The module ends with a skills assessment that uses `common.txt` for all fuzzing. These notes contain no answers. Use the workflow in §4: enumerate, discover directories/files, check parameters and vhosts, filter, validate each step, and follow what you find to the end.
