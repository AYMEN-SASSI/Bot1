"""
BotGeek - Main Orchestrator
Coordinates all agents through the NLP command interpreter.
"""

import sys
import logging
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).parent))

from core.executor    import ToolExecutor
from core.interpreter import CommandInterpreter, Intent, ParsedCommand
from agents.recon_agent  import ReconAgent
from agents.scan_agent   import ScanAgent
from agents.vuln_agent   import VulnerabilityAgent
from agents.web_agent    import WebAgent
from agents.wifi_agent   import WifiAgent
from agents.report_agent import ReportAgent, AuditData
from models.vuln_scorer  import VulnScoringModel, build_features_from_port

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("botgeek.orchestrator")

BANNER = r"""
  ██████╗  ██████╗ ████████╗ ██████╗ ███████╗███████╗██╗  ██╗
  ██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝ ██╔════╝██╔════╝██║ ██╔╝
  ██████╔╝██║   ██║   ██║   ██║  ███╗█████╗  █████╗  █████╔╝
  ██╔══██╗██║   ██║   ██║   ██║   ██║██╔══╝  ██╔══╝  ██╔═██╗
  ██████╔╝╚██████╔╝   ██║   ╚██████╔╝███████╗███████╗██║  ██╗
  ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝
  AI-Powered Security Orchestration Platform
  ─────────────────────────────────────────
  Type your command in natural language.
  Examples:
    analyse 192.168.1.10
    scan ports on 10.0.0.5
    wifi scan on wlan0
    check web vulnerabilities on 192.168.1.20
    help
    exit
"""

HELP_TEXT = """
Available Commands (Natural Language):

  RECON         gather info on <target>
  SCAN          scan <target> / scan ports on <ip>
  VULN          check vulnerabilities on <target>
  WEB           web scan <url>
  WIFI          wifi scan [on wlan0]
  FULL AUDIT    analyse <target> / full audit <target>
  REPORT        generate report
  HELP          show this help
  EXIT          quit BotGeek
"""


class BotGeek:
    """Central orchestrator — takes parsed commands, dispatches to agents."""

    def __init__(self):
        self.executor    = ToolExecutor()
        self.interpreter = CommandInterpreter()
        self.recon_agent = ReconAgent(self.executor)
        self.scan_agent  = ScanAgent(self.executor)
        self.vuln_agent  = VulnerabilityAgent(self.executor)
        self.web_agent   = WebAgent(self.executor)
        self.wifi_agent  = WifiAgent(self.executor)
        self.report_agent = ReportAgent()
        self.ml_model    = VulnScoringModel()

        # Session storage
        self._last_audit: dict = {}

    # ------------------------------------------------------------------

    def handle(self, user_input: str) -> None:
        cmd: ParsedCommand = self.interpreter.parse(user_input)

        print(f"\n  🤖  {cmd.explanation}\n")

        if cmd.intent == Intent.HELP or cmd.intent == Intent.UNKNOWN:
            print(HELP_TEXT)
            return

        if cmd.intent == Intent.REPORT:
            self._generate_report()
            return

        if cmd.intent == Intent.WIFI:
            iface = cmd.options.get("interface", "wlan0")
            result = self.wifi_agent.run(iface, cmd.options)
            print(result.summary())
            return

        if cmd.intent == Intent.WEB:
            target = cmd.target
            if not target:
                print("  ⚠  Please specify a target URL or IP.")
                return
            result = self.web_agent.run(target, cmd.options)
            print(result.summary())
            self._last_audit["web"] = result
            return

        target = cmd.target
        if not target:
            print("  ⚠  No target found in command. Please include an IP or domain.")
            return

        if cmd.intent == Intent.RECON:
            self._run_recon(target, cmd.options)

        elif cmd.intent == Intent.SCAN:
            self._run_scan(target, cmd.options)

        elif cmd.intent in (Intent.VULN, Intent.EXPLOIT):
            self._run_vuln(target, cmd.options)

        elif cmd.intent == Intent.FULL_AUDIT:
            self._run_full_audit(target, cmd.options)

    # ------------------------------------------------------------------  Workflows

    def _run_recon(self, target: str, opts: dict) -> None:
        result = self.recon_agent.run(target, opts)
        print(result.summary())
        self._last_audit.update({"target": target, "recon": result})

    def _run_scan(self, target: str, opts: dict) -> None:
        result = self.scan_agent.run(target, opts)
        print(result.summary())
        self._last_audit.update({"target": target, "scan": result})

    def _run_vuln(self, target: str, opts: dict) -> None:
        scan = self._last_audit.get("scan") or self.scan_agent.run(target, opts)
        result = self.vuln_agent.run(target, scan.open_ports, opts)
        print(result.summary())

        # ML scoring
        scores = []
        for p in scan.open_ports:
            feat = build_features_from_port(p, result)
            scores.append(self.ml_model.predict(feat))

        if scores:
            print("\n  [ML] Exploit Probability Predictions:")
            for s in scores:
                bar = "█" * int(s.exploit_probability * 20)
                print(
                    f"    {s.service:15s} [{bar:<20s}] "
                    f"{int(s.exploit_probability*100):3d}%  {s.risk_tier}"
                )

        self._last_audit.update(
            {"target": target, "scan": scan, "vuln": result, "ml_scores": scores}
        )

    def _run_full_audit(self, target: str, opts: dict) -> None:
        print("  ─" * 35)
        print(f"  Starting full audit on: {target}")
        print("  ─" * 35)

        print("\n  [1/4] RECON")
        recon = self.recon_agent.run(target, opts)
        print(recon.summary())

        print("\n  [2/4] SCAN")
        scan = self.scan_agent.run(target, opts)
        print(scan.summary())

        print("\n  [3/4] VULNERABILITY ANALYSIS")
        vuln = self.vuln_agent.run(target, scan.open_ports, opts)
        print(vuln.summary())

        # ML predictions
        scores = []
        for p in scan.open_ports:
            feat = build_features_from_port(p, vuln)
            scores.append(self.ml_model.predict(feat))

        if scores:
            print("\n  [ML] Exploit Probability:")
            for s in scores:
                bar = "█" * int(s.exploit_probability * 20)
                print(
                    f"    {s.service:15s} [{bar:<20s}] "
                    f"{int(s.exploit_probability*100):3d}%  {s.risk_tier}"
                )

        self._last_audit = {
            "target": target,
            "recon": recon,
            "scan": scan,
            "vuln": vuln,
            "ml_scores": scores,
        }

        print("\n  [4/4] GENERATING REPORT")
        self._generate_report()

    def _generate_report(self) -> None:
        if not self._last_audit:
            print("  ⚠  No audit data — run a scan first.")
            return

        data = AuditData(
            target=self._last_audit.get("target", "unknown"),
            recon=self._last_audit.get("recon"),
            scan=self._last_audit.get("scan"),
            vuln=self._last_audit.get("vuln"),
            web=self._last_audit.get("web"),
            wifi=self._last_audit.get("wifi"),
            ml_scores=self._last_audit.get("ml_scores"),
        )
        paths = self.report_agent.generate(data)
        print(f"\n  ✔  Report saved:")
        print(f"     TXT  → {paths['txt']}")
        print(f"     HTML → {paths['html']}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print(BANNER)
    bot = BotGeek()

    while True:
        try:
            user_input = input("BotGeek > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Goodbye.")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit", "q"):
            print("  Goodbye.")
            break

        bot.handle(user_input)


if __name__ == "__main__":
    main()
