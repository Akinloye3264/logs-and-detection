# Exercise 1: Syslog Authentication Log

## Scenario

Your company runs a bastion host (`bastion01`) with an in-house authentication daemon called **`gatekeeper`**. It writes to syslog. Administrators are only supposed to log in through the trusted jump host **`10.20.30.40`**. Your job is to teach Wazuh to understand these logs and alert on suspicious logins.

## Log format

```
Nov 02 09:14:21 bastion01 gatekeeper[2217]: Accepted password for user jane from 10.20.30.40 port 51822 method=password
Nov 02 09:16:45 bastion01 gatekeeper[2231]: Failed password for user admin from 203.0.113.45 port 51822 method=password
```

Sample logs are in [`sample-logs.txt`](sample-logs.txt) and [`bruteforce-logs.txt`](bruteforce-logs.txt).

---

## Task 1.1: Create the decoder

Create `/var/ossec/etc/decoders/gatekeeper_decoder.xml` that extracts:

| Field | Example |
|-------|---------|
| `program_name` (pre-decoding) | `gatekeeper` |
| `login_result` | `Accepted` / `Failed` |
| `auth_type` | `password` |
| `dstuser` | `jane` |
| `srcip` | `10.20.30.40` |
| `srcport` | `51822` |
| `auth_method` | `password` |

**Hints**

- Use a parent decoder keyed on `<program_name>`, then a child decoder with a `pcre2` regex.
- The PID in `gatekeeper[2217]` is handled by pre-decoding. You do not match it.
- The number of capture groups must equal the number of names in `<order>`.

## Task 1.2: Create the rules

Add these rules to `/var/ossec/etc/rules/local_rules.xml` (or a new file in `/var/ossec/etc/rules/`):

| Rule ID | Level | Fires when |
|---------|-------|------------|
| `100200` | 0 | Any event decoded by your `gatekeeper` decoder (parent rule) |
| `100201` | 3 | A **successful** login comes from the trusted jump host `10.20.30.40` |
| `100202` | 8 | A **successful** login comes from **any other** IP |
| `100203` | 5 | A **failed** login |
| `100204` | 10 | **5 or more failed logins** from the same source IP within **120 seconds** (brute force) |

**Hints**

- Child rules use `<if_sid>100200</if_sid>`.
- Match a decoded field with `<field name="login_result">^Accepted$</field>`.
- The `<srcip>` option supports negation with `!`.
- For the brute-force rule, look at `frequency`, `timeframe`, `<if_matched_sid>` and `<same_source_ip />`.

## Task 1.3: Test with `wazuh-logtest`

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste each line from `sample-logs.txt`. For the brute-force rule, stay in **one** logtest session and paste the lines from `bruteforce-logs.txt` one after another.

## Expected outcome

| Sample log | Expected rule | Level |
|------------|---------------|-------|
| Accepted from `10.20.30.40` | `100201` | 3 |
| Accepted from `198.51.100.7` | `100202` | 8 |
| Failed from `203.0.113.45` (single event) | `100203` | 5 |
| Repeated failures from `203.0.113.45` in one session | `100204` | 10 |

Your Phase 2 output should look similar to:

```
**Phase 2: Completed decoding.
	name: 'gatekeeper'
	auth_method: 'password'
	auth_type: 'password'
	dstuser: 'jane'
	login_result: 'Accepted'
	srcip: '10.20.30.40'
	srcport: '51822'
```

And Phase 3 for the first log:

```
**Phase 3: Completed filtering (rules).
	id: '100201'
	level: '3'
	description: 'gatekeeper: successful login from the trusted jump host.'
```

(Descriptions and field ordering depend on your own file. Rule IDs and levels must match.)

## Deliverables

- `gatekeeper_decoder.xml`
- your rules for `100200`-`100204`
- screenshots of all four outcomes in `docs/screenshots/`

## Self-check

- [ ] Phase 1 shows `program_name: 'gatekeeper'`
- [ ] Phase 2 shows all six fields populated
- [ ] The trusted and untrusted logins trigger **different** rules
- [ ] The brute-force rule fires only after repeated failures, not on the first one
