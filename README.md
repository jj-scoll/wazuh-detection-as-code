# wazuh-detection-as-code

Sigma detection rules for **Wazuh 5.0**, with each rule tested two ways. A
local evaluator checks it in milliseconds, and a real Wazuh engine running in
CI checks it again.

Wazuh 5.0 replaced the XML ruleset with Sigma rules evaluated by the indexer's
Security Analytics engine. That engine does not follow the Sigma spec in
several important ways (see [Wazuh 5.0 semantics](#wazuh-50-semantics)). A
rule that looks right can therefore never fire. This repo encodes those
differences as tests, so a broken rule fails CI instead of going quiet in
production.

> Pinned to `wazuh/wazuh-indexer:5.0.0-rc2`, the latest 5.0 build at the time
> of writing. Bump `WAZUH_INDEXER_IMAGE` in `scripts/indexer-up.sh` at GA, and
> let the parity job report what changed.

## Rules

| Rule | ATT&CK | Level |
|---|---|---|
| [CloudTrail logging stopped or trail deleted](rules/aws/cloudtrail_logging_disabled.yml) | T1562.008 | high |
| [GuardDuty detector deleted or member monitoring stopped](rules/aws/guardduty_disabled.yml) | T1562.001 | high |
| [Cron job file written outside package management](rules/linux/cron_job_written.yml) | T1053.003 | medium |
| [Remote script downloaded and piped straight into a shell](rules/linux/download_piped_to_shell.yml) | T1105, T1059.004 | medium |
| [Local user account created interactively](rules/linux/local_account_created.yml) | T1136.001 | medium |
| [Reverse shell through bash /dev/tcp redirection](rules/linux/reverse_shell_dev_tcp.yml) | T1059.004, T1095 | high |
| [setuid or setgid bit set with chmod](rules/linux/setuid_bit_set.yml) | T1548.001 | high |
| [Shell history cleared or disabled](rules/linux/shell_history_tampering.yml) | T1070.003 | medium |
| [SSH authorized_keys file modified](rules/linux/ssh_authorized_keys_modified.yml) | T1098.004 | medium |
| [PowerShell launched with an encoded command](rules/windows/powershell_encoded_command.yml) | T1059.001, T1027.010 | medium |
| [Windows event log cleared](rules/windows/security_log_cleared.yml) | T1070.001 | high |

Rules match on already-normalized events in the
[Wazuh Common Schema](https://github.com/wazuh/wazuh-indexer-plugins) (WCS),
which is ECS-based. For example, CloudTrail rules read `event.provider` and
`event.action` rather than raw `eventSource` and `eventName`. Mapping raw logs
into WCS is the job of decoders, and it is out of scope here.

## How it works

```
rules/**/<name>.yml          Sigma rule (as Wazuh 5.0 accepts it)
rules/**/<name>.tests.yml    match / no_match events for that rule
        │
        ├── cargo test ─────────────────── offline, every push
        │     • rule parses; unsupported Sigma features rejected, not guessed
        │     • every field exists in WCS (Wazuh rejects rules otherwise)
        │     • every fixture event only uses WCS fields
        │     • match cases fire, no_match cases don't (local evaluator)
        │     • rule converts to a Wazuh Content Manager resource
        │
        └── cargo test --test wazuh_parity -- --ignored ── CI, real engine
              • start wazuh-indexer 5.0 (engine embedded), load all rules
              • send every fixture event through Content Manager logtest
              • for every event: set of rules Wazuh fires == set fired locally
```

The parity check compares whole sets, not just "this event fires this rule".
It also catches a rule that fires on another rule's fixtures, and any drift
between the local evaluator and the engine. Content Manager's
`logtest/detection` uses the same compiler and percolator as a deployed
detector.

`wazuh-dac build` writes each rule as the JSON resource that Content Manager's
`POST /rules` expects, adding the `metadata` block, the `mitre` block derived
from `attack.*` tags, and `logsource.product` routing to your integration. CI
publishes the result as an artifact.

## Wazuh 5.0 semantics

Each item below was observed on the rc2 engine and is pinned by a test in
[`tests/evaluate.rs`](tests/evaluate.rs). Sigma spec behaviour is given for
contrast.

| | Sigma spec | Wazuh 5.0 rc2 |
|---|---|---|
| String equality, `contains`, `startswith`, `endswith` | case-insensitive | **case-sensitive** |
| `re` | anchored per backend | unanchored search; `^`/`$` work only as first/last character |
| `re\|i`, `re\|m`, `re\|s` | flags | rule rejected: "Unknown modifier i" |
| Backslash in `re` (`\s`, `\d`, `\+`) | escape | never matches; `q\|r` matches plain "r" |
| `/` in `re` (also `[/]`, `\/`) | literal | never matches |
| `@`, `&`, `#`, `<n-m>` in `re` | literal | Lucene operators (`a@b` matches "axb") |
| Array-valued fields | — | match if any element matches |
| Rule title | free | must be unique per space |
| Fields | any | must exist in WCS, or the rule is rejected |

The practical regex dialect is:

- Use character classes in place of escapes: `[+]`, `[ ]`, `[0-9]`, `[|]`.
- Spell out case variants, e.g. `[eE][nN][cC]`.
- Match a path separator with a negated class such as `[^ a-zA-Z0-9]`.

The rule loader rejects anything outside that subset, and its error message
says what to use instead:

```
unsupported: `process.command_line|re`: regex `[|][ ]*sh\s`: backslash is a literal in Wazuh; use a character class like [+] or [ ]
```

## Adding a rule

1. Write `rules/<platform>/<name>.yml`. It must have `id`, `status`, `level`,
   `description`, `author`, `date`, `falsepositives` and at least one
   `attack.tNNNN` tag. Use fields from [`schema/wcs-fields.txt`](schema/wcs-fields.txt).
2. Write `rules/<platform>/<name>.tests.yml`:
   ```yaml
   match:
     - description: what an attacker does
       event: {process: {name: chmod, args: [u+s, /tmp/sh]}}
   no_match:
     - description: the closest legitimate thing
       event: {process: {name: chmod, args: [755, /tmp/sh]}}
   ```
3. `cargo test` for the fast loop.
4. `scripts/indexer-up.sh`, then
   `set -a; . .wazuh/env; set +a; cargo test --test wazuh_parity -- --ignored`
   to confirm against the engine. The indexer needs Docker and about 2.5 GB of
   RAM (2.44 GiB measured with `docker stats` after a parity run, 1 GB heap),
   and is ready in under a minute (35-51 s measured).

## Layout

| Path | |
|---|---|
| `src/sigma.rs` | Sigma parser: selections, modifiers, condition grammar, Wazuh regex dialect check |
| `src/evaluate.rs` | local evaluator implementing Wazuh's (not the spec's) semantics |
| `src/convert.rs` | Sigma → Wazuh Content Manager rule resource |
| `src/schema.rs` | WCS field lookup |
| `src/wazuh.rs` | Content Manager API client (integrations, rules, promote, logtest) |
| `scripts/indexer-up.sh` | throwaway TLS-on indexer with per-run random credentials |
| `scripts/update-wcs-fields.sh` | regenerate the WCS field list for a Wazuh tag |

## Provenance

All rules and fixtures were written for this repository. No rules were copied
from SigmaHQ or any other ruleset. `schema/wcs-fields.txt` holds only the
field names and types from `wcs/stateless/events/main/docs/fields.csv` in
[wazuh/wazuh-indexer-plugins](https://github.com/wazuh/wazuh-indexer-plugins)
at `v5.0.0-rc2` (AGPL-3.0). Its header records the source file's sha256.

## License

[MIT](LICENSE). The vendored WCS field list keeps its upstream AGPL-3.0 notice above.
