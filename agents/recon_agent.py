"""
BotGeek - Recon Agent
Handles passive and active reconnaissance using Parrot OS tools.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from core.executor import ToolExecutor, ExecutionResult

logger = logging.getLogger("botgeek.agents.recon")


@dataclass
class ReconResult:
    target: str
    whois: str = ""
    subdomains: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    dns_records: str = ""
    errors: list = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"[Recon] Target: {self.target}"]
        if self.whois:
            lines.append(f"  WHOIS: {len(self.whois)} chars")
        if self.subdomains:
            lines.append(f"  Subdomains found: {len(self.subdomains)}")
        if self.emails:
            lines.append(f"  Emails found: {len(self.emails)}")
        if self.dns_records:
            lines.append("  DNS: collected")
        return "\n".join(lines)


class ReconAgent:
    """
    Performs passive and active reconnaissance on a target.
    Uses: whois, dig, theHarvester, amass (when available).
    """

    def __init__(self, executor: ToolExecutor):
        self.exec = executor

    def run(self, target: str, options: Optional[dict] = None) -> ReconResult:
        options = options or {}
        result = ReconResult(target=target)

        logger.info(f"[Recon] Starting recon on {target}")

        result.whois = self._whois(target)
        result.dns_records = self._dns(target)

        if self.exec.tool_available("theHarvester"):
            result.emails, result.subdomains = self._harvester(target)
        else:
            logger.warning("[Recon] theHarvester not found — skipping email/subdomain harvest")

        return result

    # ------------------------------------------------------------------

    def _whois(self, target: str) -> str:
        res: ExecutionResult = self.exec.run(f"whois {target}", timeout=30)
        if res.success:
            return res.stdout[:1500]
        result_err = res.stderr[:200] if res.stderr else "whois failed"
        logger.warning(f"[Recon] whois error: {result_err}")
        return ""

    def _dns(self, target: str) -> str:
        res: ExecutionResult = self.exec.run(f"dig {target} ANY +short", timeout=15)
        if res.success:
            return res.stdout[:800]
        return ""

    def _harvester(self, target: str) -> tuple[list, list]:
        cmd = f"theHarvester -d {target} -b all -l 100"
        res: ExecutionResult = self.exec.run(cmd, timeout=60)
        if not res.success:
            return [], []

        import re
        emails     = re.findall(r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}", res.stdout)
        subdomains = re.findall(
            r"\b(?:[a-zA-Z0-9\-]+\.){2,}[a-zA-Z]{2,}\b", res.stdout
        )
        return list(set(emails)), list(set(subdomains))
