"""Names for ATT&CK techniques Actaeon refers to itself (starters, prompts, docs).

Not the full matrix: other IDs are shown without a name. Check IDs against the
current ATT&CK release before relying on them.
"""

NAMES = {
    "T1003": "OS Credential Dumping", "T1003.001": "LSASS Memory",
    "T1021": "Remote Services", "T1021.002": "SMB/Windows Admin Shares",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1053": "Scheduled Task/Job", "T1053.005": "Scheduled Task",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell",
    "T1070": "Indicator Removal", "T1070.001": "Clear Windows Event Logs",
    "T1071": "Application Layer Protocol", "T1071.001": "Web Protocols", "T1071.004": "DNS",
    "T1078": "Valid Accounts", "T1098": "Account Manipulation", "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force", "T1110.003": "Password Spraying", "T1136": "Create Account",
    "T1204": "User Execution", "T1204.002": "Malicious File",
    "T1218": "System Binary Proxy Execution", "T1218.005": "Mshta", "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32", "T1486": "Data Encrypted for Impact",
    "T1547": "Boot or Logon Autostart Execution", "T1547.001": "Registry Run Keys / Startup Folder",
    "T1562": "Impair Defenses", "T1562.001": "Disable or Modify Tools",
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment", "T1566.002": "Spearphishing Link",
    "T1567": "Exfiltration Over Web Service", "T1567.002": "Exfiltration to Cloud Storage",
    "T1569": "System Services", "T1569.002": "Service Execution",
}


def name(tid: str) -> str:
    return NAMES.get(tid) or NAMES.get(tid.split(".")[0], "")
