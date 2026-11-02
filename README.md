# Logs and Detection (Wazuh Decoder & Rule Lab): From Raw Log to Alert

A hands-on lab on the Wazuh analysis engine. You take three different kinds of raw logs, write **custom decoders** to extract fields from them, then write **custom rules** that turn those fields into alerts.

| # | Log type | Skill practised |
|---|----------|-----------------|
| 1 | Syslog authentication log (custom daemon) | Program-name decoders, PCRE2 field extraction, IP-based rules, frequency (brute-force) rules |
| 2 | Web / reverse-proxy access log (no syslog header) | Prematch decoders, dynamic fields, scanner and forced-browsing detection |
| 3 | JSON audit log wrapped in syslog | JSON decoding, nested field matching, multi-condition rules |

---

## How the Wazuh analysis engine works

Every log sent to the Wazuh server goes through three stages:

1. **Pre-decoding**: static header fields are pulled out (timestamp, hostname, `program_name`).
2. **Decoding**: decoders extract the dynamic fields (user, source IP, port, and so on).
3. **Rule matching**: rules check whether the decoded event is security-relevant. If a rule matches at or above the alert threshold, an alert appears on the Wazuh dashboard.

```
raw log -> [pre-decoding] -> [decoding] -> [rules] -> alert
            timestamp        srcip          level
            hostname         dstuser        description
            program_name     custom fields  groups
```

---

## Prerequisites

- A working **Wazuh manager (4.x)** you can reach as `root` or via `sudo`. A lab VM or the Wazuh OVA is fine. **Do not use production.**
- Basic comfort with a terminal and a text editor (`nano`, `vim`).
- Basic regular-expression knowledge. Decoders here use **PCRE2**.

---

## Repository layout

```
wazuh-decoder-rule-lab/
├── README.md
├── exercises/
│   ├── exercise-1-syslog-auth/       # directions + sample logs
│   ├── exercise-2-web-access/
│   └── exercise-3-json-in-syslog/
├── solutions/
│   ├── README.md                     # explanation of each solution
│   ├── decoders/                     # one decoder file per exercise
│   └── rules/                        # one rules file per exercise
├── scripts/
│   ├── deploy-solutions.sh           # copies solution files into /var/ossec
│   └── run-logtests.sh               # replays all sample logs through wazuh-logtest
└── docs/screenshots/                 # put YOUR evidence screenshots here
```

---

## How to use this lab

1. Clone the repo onto your Wazuh manager (or copy it there):
   ```bash
   git clone <your-repo-url>
   cd wazuh-decoder-rule-lab
   ```
2. Work through the exercises **in order**. Each has its own `README.md` with the scenario, tasks and expected outcome.
3. Write your own decoders in `/var/ossec/etc/decoders/` and your rules in `/var/ossec/etc/rules/local_rules.xml` (or your own file in that directory).
4. Validate with `wazuh-logtest` and save screenshots into `docs/screenshots/`.
5. **Only then** compare against `solutions/`.

### Handy commands

```bash
# Interactive decoder/rule tester
sudo /var/ossec/bin/wazuh-logtest

# Validate configuration, decoders and rules before restarting
sudo /var/ossec/bin/wazuh-analysisd -t

# Apply changes to the live manager
sudo systemctl restart wazuh-manager
```

Paste a log at the `Type one log per line` prompt. Each phase of the output shows what the engine did:

- **Phase 1**: pre-decoding (timestamp, hostname, `program_name`)
- **Phase 2**: decoding (your extracted fields)
- **Phase 3**: filtering (the rule that fired, its level and description)

---

## Common pitfalls

- **Curly quotes in XML.** If you copy from a document, `“ ”` will silently break your decoder. Use straight quotes `"` only.
- **Rule ID collisions.** Custom rule IDs must be in the `100000-120000` range and unique. Each exercise here uses its own block (`1002xx`, `1003xx`, `1004xx`).
- **Alert threshold.** Only rules at or above `log_alert_level` (default `3`) generate alerts. Level `0` rules are building blocks.
- **Always run `wazuh-analysisd -t`** before restarting. A syntax error can stop the analysis engine.
- **File ownership.** Custom files should be readable by the Wazuh group. The deploy script handles this.

---

## Deliverables (if you are submitting this lab)

For each exercise:

- your decoder XML file
- your rules XML file
- screenshots of `wazuh-logtest` output for **every** sample log, saved in `docs/screenshots/`, named like `ex1-rule-100202.png`

---

## Exercises

- [Exercise 1: Syslog authentication log](exercises/exercise-1-syslog-auth/README.md)
- [Exercise 2: Web access log](exercises/exercise-2-web-access/README.md)
- [Exercise 3: JSON audit log inside syslog](exercises/exercise-3-json-in-syslog/README.md)

---

*Created by MENSEC. All log samples use documentation-reserved IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and fictional hosts and users.*
