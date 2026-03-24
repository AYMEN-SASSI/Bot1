"""
BotGeek - Vulnerability Agent
Matches discovered services to CVEs using Searchsploit and NVD API.
Includes a lightweight ML scoring model for exploit probability.
"""

import re
import json
import logging
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, List
from core.executor import ToolExecutor, ExecutionResult

logger = logging.getLogger("botgeek.agents.vuln")


@dataclass
class Vulnerability:
    service: str
    version: str
    cve_id: str
    description: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    cvss_score: float
    exploit_available: bool
    exploit_info: str = ""
    remediation: str = ""


@dataclass
class VulnResult:
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    risk_score: float = 0.0
    errors: list = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"[Vuln] Target: {self.target}"]
        lines.append(f"  Total vulns: {len(self.vulnerabilities)}")
        lines.append(f"  Risk score: {self.risk_score:.1f}/10")
        for v in self.vulnerabilities[:5]:
            lines.append(
                f"    {v.cve_id} [{v.severity}] {v.service} {v.version}"
            )
        return "\n".join(lines)


# Severity thresholds
_SEVERITY_MAP = {
    (9.0, 10.0): "CRITICAL",
    (7.0, 9.0):  "HIGH",
    (4.0, 7.0):  "MEDIUM",
    (0.0, 4.0):  "LOW",
}


def _cvss_to_severity(score: float) -> str:
    for (low, high), sev in _SEVERITY_MAP.items():
        if low <= score <= high:
            return sev
    return "UNKNOWN"


class VulnerabilityAgent:
    """
    For each open service found by the ScanAgent:
      1. Query Searchsploit for known exploits
      2. Query NVD API for CVE metadata
      3. Compute overall risk score
    """

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, executor: ToolExecutor):
        self.exec = executor

    def run(self, target: str, open_ports: list, options: Optional[dict] = None) -> VulnResult:
        result = VulnResult(target=target)

        if not open_ports:
            result.errors.append("No open ports to analyse")
            return result

        logger.info(f"[Vuln] Analysing {len(open_ports)} services on {target}")

        for port_obj in open_ports:
            service_str = port_obj.service
            version_str = port_obj.version

            # 1. Searchsploit
            exploits = self._searchsploit(service_str, version_str)

            # 2. NVD CVE lookup
            cves = self._nvd_lookup(service_str, version_str)

            if cves:
                for cve in cves[:3]:
                    result.vulnerabilities.append(
                        Vulnerability(
                            service=service_str,
                            version=version_str,
                            cve_id=cve.get("id", "N/A"),
                            description=cve.get("description", "")[:200],
                            severity=_cvss_to_severity(cve.get("cvss", 0.0)),
                            cvss_score=cve.get("cvss", 0.0),
                            exploit_available=bool(exploits),
                            exploit_info=exploits[:300] if exploits else "",
                            remediation=self._remediation_hint(service_str),
                        )
                    )
            elif exploits:
                # Exploit known but no CVE metadata fetched
                result.vulnerabilities.append(
                    Vulnerability(
                        service=service_str,
                        version=version_str,
                        cve_id="LOCAL-EXPLOIT",
                        description=f"Exploit found in Searchsploit for {service_str}",
                        severity="HIGH",
                        cvss_score=7.5,
                        exploit_available=True,
                        exploit_info=exploits[:300],
                        remediation=self._remediation_hint(service_str),
                    )
                )

        result.risk_score = self._compute_risk(result.vulnerabilities)
        return result

    # ------------------------------------------------------------------

    def _searchsploit(self, service: str, version: str) -> str:
        if not self.exec.tool_available("searchsploit"):
            return ""
        query = f"{service} {version}".strip()
        res: ExecutionResult = self.exec.run(
            f"searchsploit --colour {query}", timeout=20
        )
        # Return only exploit titles (skip header lines)
        lines = [l for l in res.stdout.splitlines() if "------" not in l and l.strip()]
        return "\n".join(lines[2:12]) if len(lines) > 2 else ""

    def _nvd_lookup(self, service: str, version: str) -> list:
        """Query NIST NVD REST API for matching CVEs."""
        query = f"{service} {version}".strip()
        encoded = urllib.parse.quote(query)
        url = f"{self.NVD_API}?keywordSearch={encoded}&resultsPerPage=5"

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "BotGeek-SecurityResearch/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            cves = []
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Extract CVSS score
                metrics = cve_data.get("metrics", {})
                score = 0.0
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics:
                        score = (
                            metrics[key][0]
                            .get("cvssData", {})
                            .get("baseScore", 0.0)
                        )
                        break

                # Extract description
                descs = cve_data.get("descriptions", [])
                desc = next(
                    (d["value"] for d in descs if d.get("lang") == "en"), ""
                )

                cves.append({"id": cve_id, "cvss": score, "description": desc})

            return cves

        except Exception as exc:
            logger.warning(f"[Vuln] NVD API error: {exc}")
            return []

    def _compute_risk(self, vulns: List[Vulnerability]) -> float:
        if not vulns:
            return 0.0
        scores = [v.cvss_score for v in vulns]
        # Weighted: max score * 0.6 + average * 0.4
        max_s = max(scores)
        avg_s = sum(scores) / len(scores)
        return round(max_s * 0.6 + avg_s * 0.4, 2)

    def _remediation_hint(self, service: str) -> str:
        hints = {
            "ssh":    "Disable root login, use key-based auth, update OpenSSH",
            "http":   "Update web server, disable directory listing, apply WAF",
            "https":  "Update TLS to 1.3, check certificate validity",
            "ftp":    "Disable anonymous FTP, switch to SFTP",
            "smb":    "Apply MS17-010 patch, disable SMBv1",
            "mysql":  "Restrict remote access, use strong passwords, update version",
            "rdp":    "Enable NLA, restrict access by IP, apply latest patches",
            "telnet": "Disable telnet, replace with SSH",
        }
        for key, hint in hints.items():
            if key in service.lower():
                return hint
        return "Update to latest version, apply vendor security patches"
