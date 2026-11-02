# Exercise 2: Web / Reverse-Proxy Access Log

## Scenario

A reverse proxy called **`edgeproxy`** fronts your web application. It writes its own **key=value** access-log format, so Wazuh's built-in web decoders do not recognise it. There is also **no syslog header**: each line starts with an ISO-8601 timestamp, so you cannot rely on `program_name`. You must decode it with a **prematch**.

## Log format

```
2026-11-02T09:31:07Z edgeproxy src=198.51.100.12 method=GET uri=/products/42 status=200 bytes=5120 ua="Mozilla/5.0"
```

Sample logs are in [`sample-logs.txt`](sample-logs.txt) and [`forcedbrowse-logs.txt`](forcedbrowse-logs.txt).

---

## Task 2.1: Create the decoder

Create `/var/ossec/etc/decoders/edgeproxy_decoder.xml` that extracts:

| Field | Example |
|-------|---------|
| `srcip` | `203.0.113.77` |
| `http_method` | `GET` |
| `request_path` | `/index.php` |
| `status_code` | `200` |
| `bytes_sent` | `312` |
| `user_agent` | `sqlmap/1.7.2#stable` |

**Hints**

- The parent decoder needs a `<prematch>` (for example, a line that starts with a timestamp followed by `edgeproxy src=`).
- Capture the user agent with a pattern that stops at the closing quote, such as `"([^"]*)"`.
- Use `type="pcre2"` on your regex.

## Task 2.2: Create the rules

| Rule ID | Level | Fires when |
|---------|-------|------------|
| `100300` | 0 | Any event decoded by your `edgeproxy` decoder (parent rule) |
| `100301` | 7 | `user_agent` contains a known scanner: `sqlmap`, `nikto`, `nmap` or `masscan` (case-insensitive) |
| `100302` | 6 | `request_path` touches a sensitive location: `/admin`, `wp-login`, `/.env` or `/.git` |
| `100303` | 4 | `status_code` is `404` |
| `100304` | 10 | **8 or more** `404` responses to the same source IP within **60 seconds** (forced browsing / content discovery) |

**Hints**

- For case-insensitive alternation, use `<field name="user_agent" type="pcre2">(?i)sqlmap|nikto|nmap|masscan</field>`.
- `100304` builds on `100303` using `<if_matched_sid>` and `<same_source_ip />`.
- Test each sample line so that only **one** detection rule applies to it.

## Task 2.3: Test with `wazuh-logtest`

Paste each line from `sample-logs.txt`. For `100304`, stay in one logtest session and paste the lines from `forcedbrowse-logs.txt`.

## Expected outcome

| Sample log | Expected rule | Level |
|------------|---------------|-------|
| Normal `GET /products/42` | `100300` (no alert) | 0 |
| `sqlmap` user agent | `100301` | 7 |
| `GET /.env` | `100302` | 6 |
| Single `404` for `/backup.zip` | `100303` | 4 |
| Repeated `404`s from `203.0.113.99` | `100304` | 10 |

Phase 2 for the sqlmap line should look similar to:

```
**Phase 2: Completed decoding.
	name: 'edgeproxy'
	bytes_sent: '312'
	http_method: 'GET'
	request_path: '/index.php'
	srcip: '203.0.113.77'
	status_code: '200'
	user_agent: 'sqlmap/1.7.2#stable'
```

## Deliverables

- `edgeproxy_decoder.xml`
- your rules for `100300`-`100304`
- screenshots of all five outcomes in `docs/screenshots/`

## Self-check

- [ ] The benign request produces **no alert**
- [ ] The user-agent value is captured **without** the surrounding quotes
- [ ] Each detection line fires exactly the rule you intended
- [ ] The frequency rule needs repeated events and does not fire on a single `404`
