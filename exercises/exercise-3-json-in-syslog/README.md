# Exercise 3: JSON Audit Log Inside Syslog

## Scenario

**`vaultsync`** is an internal secrets-management service. It writes structured **JSON** audit events, but the logs reach Wazuh **wrapped in a syslog header**. Wazuh has a JSON decoder plugin, but you must tell it where the JSON begins. Security wants alerts when humans touch production secrets, when access is denied, and especially when someone turns **auditing off**.

## Log format

```
Nov 02 10:05:37 vault01 vaultsync: {"event":"secret.read","actor":{"name":"mike","type":"user"},"source_ip":"198.51.100.31","resource":"prod/db/password","outcome":"success"}
```

Sample logs are in [`sample-logs.txt`](sample-logs.txt).

---

## Task 3.1: Create the decoder

Create `/var/ossec/etc/decoders/vaultsync_decoder.xml` using **two decoders**:

1. A parent decoder keyed on `program_name` = `vaultsync`.
2. A child decoder that applies the **JSON decoder plugin** to the part of the log **after** the syslog header.

After decoding, Wazuh should expose these fields:

| Field | Example |
|-------|---------|
| `event` | `secret.read` |
| `actor.name` | `mike` |
| `actor.type` | `user` |
| `source_ip` | `198.51.100.31` |
| `resource` | `prod/db/password` |
| `outcome` | `success` |

**Hints**

- Look at `<plugin_decoder>JSON_Decoder</plugin_decoder>`.
- Use `offset="after_parent"` on both the `<prematch>` and the `<plugin_decoder>`, and match the opening `{`.
- Nested JSON keys are flattened with a dot: `actor.name`, `actor.type`.

## Task 3.2: Create the rules

| Rule ID | Level | Fires when |
|---------|-------|------------|
| `100400` | 0 | Any event decoded by your `vaultsync` decoder (parent rule) |
| `100401` | 8 | `event` is `secret.read`, `actor.type` is `user`, `resource` starts with `prod/`, **and** `outcome` is `success` |
| `100402` | 10 | `event` is `secret.read` **and** `outcome` is `denied` |
| `100403` | 12 | `event` is `audit.disable` **or** `policy.delete` |

**Hints**

- Several `<field>` tags inside one rule are combined with **AND**.
- For OR logic on one field, use a PCRE2 alternation: `<field name="event" type="pcre2">^(audit\.disable|policy\.delete)$</field>`.
- Match nested fields as `<field name="actor.type">^user$</field>`.

## Task 3.3: Test with `wazuh-logtest`

Paste each line from `sample-logs.txt`.

## Expected outcome

| Sample log | Expected rule | Level |
|------------|---------------|-------|
| Service account reads `prod/db/password` | `100400` (no alert) | 0 |
| User `mike` reads `prod/db/password` | `100401` | 8 |
| User `intern01` denied on `prod/api/key` | `100402` | 10 |
| `audit.disable` by `root-admin` | `100403` | 12 |

Phase 2 for the second log should look similar to:

```
**Phase 2: Completed decoding.
	name: 'vaultsync'
	data.actor.name: 'mike'
	data.actor.type: 'user'
	data.event: 'secret.read'
	data.outcome: 'success'
	data.resource: 'prod/db/password'
	data.source_ip: '198.51.100.31'
```

(JSON fields are shown under `data.` in the output and in the dashboard.)

## Deliverables

- `vaultsync_decoder.xml`
- your rules for `100400`-`100403`
- screenshots of all four outcomes in `docs/screenshots/`

## Self-check

- [ ] Phase 2 lists nested fields such as `actor.type`
- [ ] The service-account read does **not** alert, but the human read does
- [ ] A denied read triggers `100402` and **not** `100401`
- [ ] `audit.disable` produces the highest-level alert of the lab
