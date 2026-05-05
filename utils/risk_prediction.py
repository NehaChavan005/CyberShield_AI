from __future__ import annotations


RISKY_PORT_WEIGHTS = {
    21: 10,
    22: 8,
    23: 18,
    25: 6,
    53: 6,
    80: 10,
    110: 4,
    143: 4,
    161: 10,
    443: 8,
    445: 18,
    587: 4,
    993: 4,
    995: 4,
    1433: 16,
    1521: 16,
    3306: 16,
    3389: 18,
    5432: 16,
    5900: 16,
    6379: 20,
    8080: 10,
    8443: 8,
    9200: 20,
    27017: 20,
}

SEVERITY_SCORES = {"critical": 100, "high": 75, "medium": 45, "low": 20, "info": 10}

ATTACK_VECTOR_RULES = [
    {
        "id": "rdp_brute_force",
        "title": "RDP brute force",
        "ports": {3389},
        "findings": {"RDP remotely exposed"},
        "base_score": 88,
        "reason": "RDP exposure can enable credential attacks and remote takeover attempts.",
    },
    {
        "id": "smb_lateral_movement",
        "title": "SMB lateral movement",
        "ports": {445},
        "findings": {"SMB exposed"},
        "base_score": 90,
        "reason": "Open SMB expands lateral movement and ransomware propagation paths.",
    },
    {
        "id": "database_exposure",
        "title": "Database exposure",
        "ports": {1433, 1521, 3306, 5432, 6379, 9200, 27017},
        "findings": {
            "MSSQL service exposed",
            "Oracle service exposed",
            "MySQL service exposed",
            "PostgreSQL service exposed",
            "Redis service exposed",
            "Elasticsearch service exposed",
            "MongoDB service exposed",
        },
        "base_score": 84,
        "reason": "Exposed data services increase the chance of credential abuse and direct data compromise.",
    },
    {
        "id": "web_app_exploitation",
        "title": "Web application exploitation",
        "ports": {80, 443, 8080, 8443},
        "findings": {"Web service without TLS"},
        "base_score": 70,
        "reason": "Public web services are common entry points for injection, XSS, and auth bypass attacks.",
    },
    {
        "id": "ssh_brute_force",
        "title": "SSH brute force",
        "ports": {22},
        "findings": set(),
        "base_score": 58,
        "reason": "SSH exposure increases the likelihood of password spraying and brute force attempts.",
    },
    {
        "id": "telnet_credential_theft",
        "title": "Telnet credential theft",
        "ports": {23},
        "findings": {"Telnet exposed"},
        "base_score": 96,
        "reason": "Telnet transmits credentials in cleartext and is highly exploitable.",
    },
    {
        "id": "ftp_credential_theft",
        "title": "FTP credential theft",
        "ports": {21},
        "findings": {"FTP exposed"},
        "base_score": 74,
        "reason": "FTP services often expose weak authentication and unencrypted data transfers.",
    },
    {
        "id": "snmp_reconnaissance",
        "title": "SNMP reconnaissance",
        "ports": {161},
        "findings": {"SNMP exposed"},
        "base_score": 54,
        "reason": "SNMP exposure can leak network/device intelligence useful for follow-on attacks.",
    },
]


def _clamp(value: int, lower: int = 0, upper: int = 100) -> int:
    return max(lower, min(upper, int(value)))


def _severity_score(findings: list[dict]) -> int:
    if not findings:
        return 5

    weighted = []
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        weighted.append(SEVERITY_SCORES.get(severity, 10))

    highest = max(weighted, default=0)
    average = sum(weighted) / len(weighted)
    return _clamp(round(highest * 0.6 + average * 0.4))


def _exposure_score(open_ports: list[dict]) -> int:
    if not open_ports:
        return 0

    ports = {int(item.get("port", 0) or 0) for item in open_ports}
    service_surface = sum(RISKY_PORT_WEIGHTS.get(port, 4) for port in ports)
    breadth_bonus = len(ports) * 3
    return _clamp(round(service_surface * 0.7 + breadth_bonus))


def _vector_finding_titles(findings: list[dict]) -> set[str]:
    return {str(item.get("title", "")) for item in findings}


def _predict_attack_vectors(open_ports: list[dict], findings: list[dict]) -> list[dict]:
    ports = {int(item.get("port", 0) or 0) for item in open_ports}
    finding_titles = _vector_finding_titles(findings)
    predicted = []

    for rule in ATTACK_VECTOR_RULES:
        matching_ports = sorted(rule["ports"].intersection(ports))
        matching_findings = sorted(rule["findings"].intersection(finding_titles))
        if not matching_ports and not matching_findings:
            continue

        likelihood = rule["base_score"]
        likelihood += min(len(matching_ports) * 4, 8)
        likelihood += min(len(matching_findings) * 6, 12)
        predicted.append(
            {
                "id": rule["id"],
                "title": rule["title"],
                "likelihood": _clamp(likelihood),
                "reason": rule["reason"],
                "related_ports": matching_ports,
                "related_findings": matching_findings,
            }
        )

    predicted.sort(key=lambda item: item["likelihood"], reverse=True)
    return predicted[:5]


def _exposure_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def predict_scan_risk(open_ports: list[dict], findings: list[dict], overall_risk: str | None = None) -> dict:
    severity_score = _severity_score(findings)
    exposure_score = _exposure_score(open_ports)
    vectors = _predict_attack_vectors(open_ports, findings)
    exploit_likelihood = _clamp(
        round(
            severity_score * 0.45
            + exposure_score * 0.35
            + (vectors[0]["likelihood"] if vectors else 0) * 0.20
        )
    )

    risk_score = _clamp(round(severity_score * 0.4 + exposure_score * 0.35 + exploit_likelihood * 0.25))
    exposure_level = _exposure_level(exposure_score)
    risk_label = str(overall_risk or _exposure_level(risk_score)).upper()

    return {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "exposure_score": exposure_score,
        "exposure_level": exposure_level,
        "exploit_likelihood": exploit_likelihood,
        "severity_score": severity_score,
        "likely_attack_vectors": vectors,
        "summary": (
            f"Exposure score {exposure_score}/100, exploit likelihood {exploit_likelihood}/100, "
            f"overall predicted risk {risk_score}/100."
        ),
    }
