"""Curated ATT&CK technique reference used for detection coverage analysis.

This is intentionally scoped to the credential-access / lateral-movement
neighborhood the rules/ knowledge base targets (OS Credential Dumping, Kerberos
ticket abuse, alternate authentication material) rather than a full mirror of
the ATT&CK Enterprise matrix - it exists to answer "which of the techniques we
care about have a rule, and which don't yet" for the coverage:// resource.
"""

ATTACK_REFERENCE: dict[str, dict[str, str]] = {
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "credential-access"},
    "T1003.002": {"name": "OS Credential Dumping: Security Account Manager", "tactic": "credential-access"},
    "T1003.003": {"name": "OS Credential Dumping: NTDS", "tactic": "credential-access"},
    "T1003.004": {"name": "OS Credential Dumping: LSA Secrets", "tactic": "credential-access"},
    "T1003.006": {"name": "OS Credential Dumping: DCSync", "tactic": "credential-access"},
    "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares", "tactic": "lateral-movement"},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "credential-access"},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "credential-access"},
    "T1187": {"name": "Forced Authentication", "tactic": "credential-access"},
    "T1550.002": {"name": "Use Alternate Authentication Material: Pass the Hash", "tactic": "lateral-movement"},
    "T1550.003": {"name": "Use Alternate Authentication Material: Pass the Ticket", "tactic": "lateral-movement"},
    "T1552.001": {"name": "Unsecured Credentials: Credentials In Files", "tactic": "credential-access"},
    "T1558.001": {"name": "Steal or Forge Kerberos Tickets: Golden Ticket", "tactic": "credential-access"},
    "T1558.003": {"name": "Steal or Forge Kerberos Tickets: Kerberoasting", "tactic": "credential-access"},
    "T1558.004": {"name": "Steal or Forge Kerberos Tickets: AS-REP Roasting", "tactic": "credential-access"},
    "T1569.002": {"name": "System Services: Service Execution", "tactic": "execution"},
}
