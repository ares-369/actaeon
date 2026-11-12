# Responsible Use and Disclaimer

Actaeon is a defensive threat-hunting tool. I built it to help analysts
investigate hypotheses against telemetry they are authorized to query. Please
read this before using it.

## Use it only on data you are authorized to query

Only connect Actaeon to log sources, endpoints, identity providers, and threat
intelligence feeds that **you own** or have **explicit authorization** to access.
Be mindful of privacy and data-retention rules when sending log excerpts or
indicators to external model providers (use `privacy` masking and read-only
service accounts).

## You are responsible for how you use it

Actaeon is provided **"as is", without warranty of any kind**. Under sections 7
and 8 of the [Apache-2.0 license](LICENSE), the author is not liable for any
damages arising from its use.

By using, copying, modifying, or distributing Actaeon, you agree that:

- **You alone are responsible** for your actions with Actaeon, for verifying
  model verdicts against raw evidence before acting, and for following all laws
  and organizational policies that apply to you.
- **The author does not condone, and is not responsible or liable for, any
  misuse of Actaeon** or for missed detections, false positives, or decisions
  made from AI-generated verdicts.
- **The author is not responsible for modified versions, forks, or
  redistributions** made by anyone else — including versions that remove,
  weaken, or bypass Actaeon's read-only policy, privacy masking, or
  authentication controls.

## Safety features are aids, not guarantees

Actaeon ships with read-only connector policies, query validation, privacy
masking, and authentication options. They help prevent mistakes, but they are
not a guarantee that nothing can go wrong, and they are not a substitute for
read-only credentials on each data source or human review of verdicts.

## Reporting problems

If you find a security issue in Actaeon itself, please report it privately — see
[`SECURITY.md`](SECURITY.md).
