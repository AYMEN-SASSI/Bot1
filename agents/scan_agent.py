"""
BotGeek - Scan Agent
Network port and service scanning using Nmap (and optionally Masscan).
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from core.executor import ToolExecutor, ExecutionResult

logger = logging.getLogger("botgeek.agents.scan")


@dataclass
class OpenPort:
    port: int
    protocol: str
    state: str
    service: str
    version: str


@dataclass
class ScanResult:
    target: str
    raw_nmap: str = ""
    open_ports: list = field(default_factory=list)
    os_guess: str = ""
    duration: float = 0.0
    errors: list = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"[Scan] Target: {self.target}"]
        lines.append(f"  Open ports: {len(self.open_ports)}")
        for p in self.open_ports:
            lines.append(f"    {p.port}/{p.protocol}  {p.service}  {p.version}")
        if self.os_guess:
            lines.append(f"  OS guess: {self.os_guess}")
        return "\n".join(lines)


class ScanAgent:
    """
    Runs Nmap scans with configurable intensity.
    Parses results into structured OpenPort objects.
    """

    def __init__(self, executor: ToolExecutor):
        self.exec = executor

    def run(self, target: str, options: Optional[dict] = None) -> ScanResult:
        options = options or {}
        result = ScanResult(target=target)

        if not self.exec.tool_available("nmap"):
            result.errors.append("nmap not found")
            logger.error("[Scan] nmap not installed")
            return result

        cmd = self._build_nmap_cmd(target, options)
        logger.info(f"[Scan] {cmd}")

        res: ExecutionResult = self.exec.run(cmd, timeout=300)
        result.duration = res.duration
        result.raw_nmap = res.stdout

        if not res.success:
            result.errors.append(res.stderr[:300])
            return result

        result.open_ports = self._parse_ports(res.stdout)
        result.os_guess   = self._parse_os(res.stdout)
        return result

    # ------------------------------------------------------------------

    def _build_nmap_cmd(self, target: str, opts: dict) -> str:
        flags = ["-sC", "-sV"]

        if opts.get("aggressive"):
            flags += ["-T4", "-A"]
        elif opts.get("stealth"):
            flags += ["-T2", "-sS"]
        else:
            flags += ["-T3", "-O"]

        if "ports" in opts:
            flags.append(f"-p {opts['ports']}")
        else:
            flags.append("--top-ports 1000")

        if opts.get("output_format") == "xml":
            flags.append("-oX scan_output.xml")

        return f"nmap {' '.join(flags)} {target}"

    def _parse_ports(self, nmap_output: str) -> list:
        pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)\s*(.*)"
        )
        ports = []
        for m in pattern.finditer(nmap_output):
            ports.append(
                OpenPort(
                    port=int(m.group(1)),
                    protocol=m.group(2),
                    state=m.group(3),
                    service=m.group(4),
                    version=m.group(5).strip()[:80],
                )
            )
        return ports

    def _parse_os(self, nmap_output: str) -> str:
        m = re.search(r"OS details?:\s*(.+)", nmap_output)
        if m:
            return m.group(1).strip()
        m = re.search(r"Aggressive OS guesses?:\s*(.+)", nmap_output)
        if m:
            return m.group(1).split(",")[0].strip()
        return ""
