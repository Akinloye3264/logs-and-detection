# Solutions

Try the exercises first. This folder explains *why* each solution works.

These are the files consumed by [`scripts/deploy-solutions.sh`](../scripts/deploy-solutions.sh).
The script installs the decoder XML files in `/var/ossec/etc/decoders/`, the
rule XML files in `/var/ossec/etc/rules/`, and runs
`wazuh-analysisd -t`. Restart `wazuh-manager` after a successful validation.

## Exercise 1: `gatekeeper`

- The **parent decoder** matches on the pre-decoded `program_name`. The `[2217]` PID is stripped during pre-decoding, which is why the decoder does not mention it.
- The **child decoder** uses PCRE2 with six capture groups mapped one-to-one to `<order>`.
- `login_result` is a custom dynamic field, matched in rules with `<field name="login_result">`.
- `<srcip negate="yes">10.20.30.40</srcip>` matches any source IP **except** the trusted host.
- `100204` is a **correlation rule**: `if_matched_sid` watches for `100203`, `frequency`/`timeframe` set the threshold, and `<same_srcip />` groups events per attacker.

## Exercise 2: `edgeproxy`

- There is no syslog header, so the parent decoder uses a **prematch** on the raw line instead of `program_name`.
- The user agent regex `"([^"]*)"` captures everything up to the closing quote.
- `request_path` and `status_code` are custom field names. Using custom names avoids confusion with static decoder fields such as `url` and `id`.
- `100304` reuses the frequency pattern from Exercise 1 on the `404` rule and groups events with `<same_srcip />`.

## Exercise 3: `vaultsync`

- The parent decoder keys on `program_name`.
- The child decoder uses `offset="after_parent"` so the JSON plugin starts parsing at the `{`, after the syslog header.
- Nested objects are flattened with dots (`actor.type`), and fields appear under `data.` in logtest and the dashboard.
- Multiple `<field>` tags in one rule are an **AND**. The OR in `100403` is a PCRE2 alternation.
- `100401` requires `outcome = success`, so a denied read is claimed only by `100402`.

## Notes

- Rule IDs are split into blocks (`1002xx`, `1003xx`, `1004xx`) so all three exercises can run on one manager without clashing.
- Frequency rules depend on how many events `wazuh-logtest` has seen **in the current session**. If a frequency rule does not fire, stay in one session and keep pasting the events.
- `scripts/run-logtests.sh` runs each input file in one session, so it is suitable for replaying the frequency samples. Use interactive `wazuh-logtest` when capturing screenshots.
- Validate with `wazuh-analysisd -t` and `wazuh-logtest` on your lab VM. Wazuh syntax and output can vary slightly by 4.x release.
