# Adding or changing a rule

1. **Write the rule** in `rules/windows/<tactic>/<prefix>_<what_it_detects>.yml`.
   - The folder is one of the rule's ATT&CK tactics (ATT&CK v20 names: `stealth`,
     `defense_impairment`, ...). The prefix follows the logsource: `proc_creation_`,
     `proc_access_`, `registry_set_`, `win_security_`, ... `dac lint` enforces both.
   - Tag at least one technique and its tactic: `attack.credential-access`, `attack.t1003.001`.
   - The description explains *why* the logic catches the behaviour, and `falsepositives`
     says what a responder should rule out.
   - Prefer `contains` / `endswith` lists over `|re`. If you need a regex, avoid `^`, `$`,
     `\s`, `\d`, `\b` and lookarounds, and wrap it in `.*` so it means the same thing in
     Splunk, Sentinel and Elastic.

2. **Write unit cases** in `tests/rule_cases/<same file name>.yml`: at least one event that must
   match and one that must not. Good cases are the evasion variant you want to keep catching
   (renamed binary, `/` vs `-` flags, 4688 instead of Sysmon) and the benign look-alike you
   tuned out.

3. **Prove it on real data.** Find a dataset that contains the behaviour (OTRF Security-Datasets
   is a good start), add it to `datasets/manifest.yml` with its pinned URL and SHA-256, and list
   your rule under `expect`. A rule can merge as `status: experimental` without a dataset;
   `test` and `stable` need one.

4. **Run the pipeline:**

   ```bash
   dac lint && pytest && dac replay && dac convert
   ```

   If replay reports an *unexpected hit*, look at it: if it is the attack, add the rule to that
   dataset's `expect`; if it is noise, fix the rule. `known_fp` exists for the rare case where
   noise has to be accepted temporarily, and it needs a reason.

5. **Commit the regenerated `queries/`.** Reviewers read the SPL/KQL diff, not just the YAML.
   If a SIEM can't express the rule, add it to `config/conversion.yml` with the reason.

## Updating ATT&CK

```bash
dac attack-sync --version 21.0 --ref <attack-stix-data commit> --sha256 <bundle hash>
git rm attack/enterprise-attack-20.0.json
dac lint   # shows every rule whose tags were revoked, deprecated or moved
```
