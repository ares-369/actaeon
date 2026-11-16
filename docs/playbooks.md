# Playbooks

A playbook tells the analyst model what a good analyst checks for one kind of alert. The model still
decides which tools to call; the playbook is guidance in its prompt, not a script.

Built in (`actaeon/soc/playbooks/`): credential attacks, script execution, network beacons,
persistence, malware detections, privilege escalation, web attacks, data exfiltration.

```yaml
title: Brute force and password spraying
match:
  keywords: ["failed sign", "spray"]   # in the alert title, rule name, description or command line
  attack: ["T1110*"]                    # ATT&CK techniques on the alerts (globs)
  rules: ["R-100*"]                     # rule ids (globs)
steps:
  - Count failures from the source and how many accounts it tried.
  - Check for a successful sign-in after the failures.
```

At most two playbooks are used per case: the best matches (rule matches count most, then
techniques, then keywords). The case shows which ones were used.

Add your own folder; a file with the same name as a built-in one replaces it:

```yaml
soc:
  playbook_dirs: ["/etc/actaeon/playbooks"]
```

A playbook without a title, steps or any match rule stops the config from loading, with the file
named.
