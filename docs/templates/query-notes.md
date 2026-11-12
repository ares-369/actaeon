# Query notes for <connector name>

<!-- Copy this file, fill it in for your log platform, and point the connector at it with
     query_notes_file. Keep it short: the model reads it before every query. -->

## Language
- Name of the query language and a one-line description.
- How a basic filter looks: field = value, wildcards, case sensitivity.
- How to combine conditions (and / or / not) and group them.

## Time
- How to bound a search by time (and whether the tool's time arguments already do this).

## Important fields
- Process starts: <field for event type> = <value>, <image / command line / parent fields>
- Network connections: <destination IP / port / domain fields>
- Sign-ins: <user / source IP / outcome fields>
- DNS, file writes, registry, email ... as your data has them

## Counting and stacking
- How to count by a field, find the rarest values, group by host or user.

## Pitfalls
- Things that make queries slow or wrong (unbounded wildcards, case, field names
  that differ between data sources ...).

## Examples
- Goal: PowerShell started by an Office app
  Query: <your query>
- Goal: one source failing to sign in to many accounts
  Query: <your query>
