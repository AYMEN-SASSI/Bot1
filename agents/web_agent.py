"""
BotGeek - Web Agent
Web application scanning using Nikto and Gobuster.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from core.executor import ToolExecutor, ExecutionResult

logger = logging.getLogger("botgeek.agents.web")


@dataclass
class WebFinding:
    url: str
    finding_type: str   # "header", "directory", "vulnerability", "info"
    description: str
    severity: str       # HIGH / MEDIUM / LOW / INFO


@dataclass
class WebResult:
    target: str
    findings: list = field(default_factory=list)
    directories: list = field(default_factory=list)
    headers_issues: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"[Web] Target: {self.target}"]
        lines.append(f"  Findings: {len(self.findings)}")
        lines.append(f"  Directories: {len(self.directories)}")
        return "\n".join(lines)


class WebAgent:
    """
    Runs Nikto for vulnerability scanning and Gobuster for directory discovery.
    """

    def __init__(self, executor: ToolExecutor):
        self.exec = executor

    def run(self, target: str, options: Optional[dict] = None) -> WebResult:
        options = options or {}
        result = WebResult(target=target)

        url = target if target.startswith("http") else f"http://{target}"

        if self.exec.tool_available("nikto"):
            self._nikto(url, result)
        else:
            result.errors.append("nikto not found")

        if self.exec.tool_available("gobuster"):
            wordlist = options.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            self._gobuster(url, wordlist, result)
        else:
            result.errors.append("gobuster not found")

        return result

    # ------------------------------------------------------------------

    def _nikto(self, url: str, result: WebResult) -> None:
        cmd = f"nikto -h {url} -maxtime 60 -nointeractive"
        logger.info(f"[Web] Running: {cmd}")
        res: ExecutionResult = self.exec.run(cmd, timeout=90)

        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("-"):
                continue
            if "+" in line:
                severity = "HIGH" if any(
                    k in line.lower() for k in ["xss", "sql", "traversal", "inject"]
                ) else "MEDIUM" if any(
                    k in line.lower() for k in ["missing", "outdated", "version"]
                ) else "INFO"
                result.findings.append(
                    WebFinding(
                        url=url,
                        finding_type="vulnerability",
                        description=line[:300],
                        severity=severity,
                    )
                )

    def _gobuster(self, url: str, wordlist: str, result: WebResult) -> None:
        cmd = (
            f"gobuster dir -u {url} -w {wordlist} "
            f"-t 20 -q --no-error -o /tmp/gobuster_out.txt"
        )
        logger.info(f"[Web] Running: {cmd}")
        res: ExecutionResult = self.exec.run(cmd, timeout=120)

        dirs = re.findall(r"(/[^\s]+)\s+\(Status:\s*(\d+)\)", res.stdout)
        for path, status in dirs:
            result.directories.append(
                WebFinding(
                    url=f"{url}{path}",
                    finding_type="directory",
                    description=f"HTTP {status}",
                    severity="INFO" if status == "200" else "LOW",
                )
            )
