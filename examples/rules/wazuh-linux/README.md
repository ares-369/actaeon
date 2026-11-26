# Wazuh on Linux: example rules

Sigma rules written for Wazuh's own field names (`syscheck.path`, `syscheck.event`, `full_log`), for the rule
library (`actaeon rules import examples/rules/wazuh-linux`). Mark the ones you want as ready to use them as alert
triage signals and in investigations. They were written from the unseen-attack triage test of 2026-11-17 and
checked on a separate held-out set (docs/benchmarks.md); review and test them on your own data first.
