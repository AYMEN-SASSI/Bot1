"""
BotGeek - WiFi Agent
Wireless reconnaissance using the Aircrack-ng suite (Parrot OS).
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from core.executor import ToolExecutor, ExecutionResult

logger = logging.getLogger("botgeek.agents.wifi")


@dataclass
class AccessPoint:
    bssid: str
    channel: str
    encryption: str
    essid: str
    signal: str
    clients: list = field(default_factory=list)


@dataclass
class WifiResult:
    interface: str
    access_points: list = field(default_factory=list)
    monitor_interface: str = ""
    errors: list = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"[WiFi] Interface: {self.interface}"]
        lines.append(f"  Access points found: {len(self.access_points)}")
        for ap in self.access_points[:5]:
            lines.append(
                f"    SSID: {ap.essid:20s}  BSSID: {ap.bssid}  "
                f"CH: {ap.channel}  ENC: {ap.encryption}"
            )
        return "\n".join(lines)


class WifiAgent:
    """
    Puts interface into monitor mode, scans for nearby APs,
    then restores managed mode.
    """

    def __init__(self, executor: ToolExecutor):
        self.exec = executor

    def run(self, interface: str = "wlan0", options: Optional[dict] = None) -> WifiResult:
        options = options or {}
        result = WifiResult(interface=interface)

        for tool in ("airmon-ng", "airodump-ng"):
            if not self.exec.tool_available(tool):
                result.errors.append(f"{tool} not found")
                logger.error(f"[WiFi] {tool} missing")
                return result

        # Enable monitor mode
        mon_iface = self._enable_monitor(interface, result)
        if not mon_iface:
            return result

        result.monitor_interface = mon_iface

        # Capture APs
        self._airodump(mon_iface, result)

        # Restore managed mode
        self._disable_monitor(interface)

        return result

    # ------------------------------------------------------------------

    def _enable_monitor(self, iface: str, result: WifiResult) -> str:
        logger.info(f"[WiFi] Enabling monitor mode on {iface}")
        res: ExecutionResult = self.exec.run(
            f"airmon-ng start {iface}", timeout=20
        )
        m = re.search(r"monitor mode (enabled|vif enabled) on (\w+)", res.stdout, re.I)
        if m:
            return m.group(2)
        # Fallback: assume wlan0mon
        if "monitor mode" in res.stdout.lower():
            return f"{iface}mon"
        result.errors.append(f"Could not enable monitor mode: {res.stderr[:200]}")
        return ""

    def _airodump(self, mon_iface: str, result: WifiResult) -> None:
        out_prefix = "/tmp/botgeek_wifi"
        cmd = (
            f"timeout 15 airodump-ng {mon_iface} "
            f"--output-format csv --write {out_prefix} -a"
        )
        logger.info(f"[WiFi] Scanning: {cmd}")
        self.exec.run(cmd, timeout=20)

        # Parse CSV
        try:
            with open(f"{out_prefix}-01.csv", "r", errors="replace") as f:
                content = f.read()
            result.access_points = self._parse_csv(content)
        except FileNotFoundError:
            result.errors.append("airodump CSV output not found")

    def _parse_csv(self, content: str) -> list:
        aps = []
        in_ap_section = True
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("Station MAC"):
                in_ap_section = False
                continue
            if in_ap_section and "," in line:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 14 and parts[0] != "BSSID":
                    try:
                        aps.append(
                            AccessPoint(
                                bssid=parts[0],
                                channel=parts[3],
                                encryption=parts[5],
                                essid=parts[13],
                                signal=parts[8],
                            )
                        )
                    except IndexError:
                        pass
        return aps

    def _disable_monitor(self, iface: str) -> None:
        logger.info(f"[WiFi] Restoring managed mode on {iface}")
        self.exec.run(f"airmon-ng stop {iface}mon", timeout=15)
