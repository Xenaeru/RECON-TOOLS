from exploitmap import exploits_for

RISK = {
    "sqli": {
        "severity": "critical", "cvss": 9.8,
        "risk": "SQL injection: attacker can read, modify, or delete database "
                "contents and potentially achieve command execution via stacked "
                "queries or file-write primitives. Full confidentiality, "
                "integrity, and availability impact.",
    },
    "xss": {
        "severity": "high", "cvss": 7.4,
        "risk": "Reflected cross-site scripting: attacker injects script into "
                "victim's session, steals cookies or tokens, or performs actions "
                "as the victim. Requires user interaction; impact scoped to the "
                "victim's session and the app's origin.",
    },
    "idor": {
        "severity": "high", "cvss": 7.5,
        "risk": "Insecure direct object reference: sequential or guessable "
                "identifiers expose other users' records. Unauthorized read of "
                "confidential data; write access depends on the endpoint.",
    },
    "header": {
        "severity": "low", "cvss": 3.7,
        "risk": "Missing HTTP security header: reduces browser-side defense "
                "against clickjacking or content injection. No direct compromise; "
                "defense-in-depth gap.",
    },
    "dirbust": {
        "severity": "low", "cvss": 3.1,
        "risk": "Discoverable path: endpoint exposed in the directory index. "
                "Risk depends on what the path serves; admin panels, backups, "
                "or config files raise severity.",
    },
    "engine": {
        "severity": "info", "cvss": 0.0,
        "risk": "Scan engine telemetry. Not a vulnerability.",
    },
}

def annotate(f):
    m = RISK.get(f.kind)
    if m:
        if f.severity in ("info", ""):
            f.severity = m["severity"]
        if not f.risk:
            f.risk = m["risk"]
        if f.cvss is None:
            f.cvss = m["cvss"]
    if not f.exploits:
        f.exploits = exploits_for(f.kind)
