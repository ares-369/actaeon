# Query notes: incident log database (SQLite)

These describe the data source, the way a team would document its own SIEM tables for Actaeon.
They contain no answers.

## How the tables connect
- `SecurityIncident`: one row per incident. `AlertIds` is a JSON list of `SecurityAlert.SystemAlertId`.
- `SecurityAlert`: one row per alert: `SystemAlertId`, `AlertName`, `Description`, `StartTime`,
  `CompromisedEntity`, `Tactics`, `Techniques`. `Entities` is a JSON array of every entity in the alert
  (hosts, accounts, processes with ProcessId and CommandLine, files with hashes, IPs, URLs, mailboxes).
- `AlertEvidence`: the same entities as flat columns, one row per entity per alert. Easier to query than
  the JSON: `AlertId`, `Title`, `EntityType`, `EvidenceRole`, `DeviceName`, `AccountName`, `AccountSid`,
  `AccountUpn`, `FileName`, `FolderPath`, `SHA1`, `SHA256`, `ProcessCommandLine`, `RemoteIP`, `RemoteUrl`,
  `LocalIP`, `EmailSubject`, `NetworkMessageId`, `RegistryKey`, `AdditionalFields` (JSON).
- `AlertInfo`: `AlertId`, `Title`, `Category`, `Severity`, `AttackTechniques` for the same alerts.

## Raw event tables (what happened, not only what alerted)
- `DeviceProcessEvents`: `Timestamp`, `DeviceName`, `AccountName`, `FileName`, `FolderPath`, `ProcessId`,
  `ProcessCommandLine`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `InitiatingProcessId`, `SHA256`
- `DeviceNetworkEvents`: `Timestamp`, `DeviceName`, `LocalIP`, `RemoteIP`, `RemotePort`, `RemoteUrl`, `InitiatingProcessFileName`
- `DeviceFileEvents`: `Timestamp`, `DeviceName`, `ActionType`, `FileName`, `FolderPath`, `SHA256`, `InitiatingProcessFileName`
- `DeviceLogonEvents`: `Timestamp`, `DeviceName`, `AccountName`, `LogonType`, `ActionType`, `RemoteIP`
- `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents`: domain sign-ins and directory activity
- `SigninLogs`, `AADNonInteractiveUserSignInLogs`: cloud sign-ins: `UserPrincipalName`, `IPAddress`, `AppDisplayName`, `ResultType`, `Location`
- `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`: `SenderFromAddress`, `RecipientEmailAddress`, `Subject`, `NetworkMessageId`
- `CloudAppEvents`, `AuditLogs`, `OfficeActivity`-style tables: cloud app and admin actions
- `DeviceInfo`, `DeviceNetworkInfo`: device names, IPs, OS

## Working method that fits these questions
1. Start from what the question gives you (a host, file, process ID, account, IP or time). Find the alert(s)
   that contain it: `SELECT AlertId, Title FROM AlertEvidence WHERE DeviceName LIKE '%host%'` or
   `SELECT SystemAlertId, AlertName FROM SecurityAlert WHERE Entities LIKE '%value%'`.
2. Follow the chain: list all evidence rows for those alerts, then for other alerts in the same incident
   (`SecurityIncident.AlertIds`). The answer is usually an entity that appears in a related alert.
3. Only go to the raw event tables when the alerts do not hold the answer, and filter them tightly
   (device, account and a time window around the alert).

## SQL tips
- Values are TEXT. Timestamps are ISO strings, so compare them as strings: `Timestamp >= '2024-06-26 14:00'`.
- Use `LIKE '%value%'` for case-insensitive contains; JSON columns can be searched the same way, or with
  `json_extract(Entities, '$[0].Name')` and `json_each(Entities)`.
- Results are capped: aggregate first (`SELECT DeviceName, COUNT(*) ... GROUP BY 1`), then fetch the rows you need.
- Answer with the exact value asked for (one account, one IP, one hash), not a list of candidates.
