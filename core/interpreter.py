"""
BotGeek - NLP Command Interpreter
Parses natural language user input into structured tool commands.
Uses keyword/intent matching with regex for zero-dependency operation,
with optional Claude API enhancement for richer understanding.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

logger = logging.getLogger("botgeek.nlp")


class Intent(str, Enum):
    RECON       = "recon"
    SCAN        = "scan"
    VULN        = "vulnerability"
    EXPLOIT     = "exploit"
    WIFI        = "wifi"
    WEB         = "web"
    PASSWORD    = "password"
    REPORT      = "report"
    FULL_AUDIT  = "full_audit"
    HELP        = "help"
    UNKNOWN     = "unknown"


@dataclass
class ParsedCommand:
    raw_input: str
    intent: Intent
    target: Optional[str]
    options: dict = field(default_factory=dict)
    confidence: float = 1.0
    explanation: str = ""


# ---------------------------------------------------------------------------
# Regex patterns for intent detection
# ---------------------------------------------------------------------------

_INTENT_PATTERNS: List[tuple] = [
    (Intent.FULL_AUDIT,  r"\b(full|complete|all|everything|audit|analyse|analyze)\b"),
    (Intent.RECON,       r"\b(recon|reconnaissance|gather|whois|harvest|subdomain)\b"),
    (Intent.WIFI,        r"\b(wifi|wireless|wlan0|aircrack|airodump|airmon|handshake|wpa)\b"),
    (Intent.WEB,         r"\b(web|http|https|gobuster|dirb|dirbuster|directory|nikto)\b"),
    (Intent.VULN,        r"\b(vuln|vulnerabilit|cve|nikto|openvas|searchsploit|weakness|check)\b"),
    (Intent.EXPLOIT,     r"\b(exploit|metasploit|msf|sqlmap|payload|shell)\b"),
    (Intent.SCAN,        r"\b(scan|port|service|nmap|masscan|detect|discover)\b"),
    (Intent.PASSWORD,    r"\b(password|crack|brute|hydra|hash|wordlist|credential)\b"),
    (Intent.REPORT,      r"\b(report|generate|export|summary|findings)\b"),
    (Intent.HELP,        r"\b(help|how|what|commands|usage|guide)\b"),
]

# ---------------------------------------------------------------------------
# Target extraction
# ---------------------------------------------------------------------------

_IP_RE      = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")
_CIDR_RE    = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
_DOMAIN_RE  = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b"
)


def _extract_target(text: str) -> Optional[str]:
    for pattern in (_IP_RE, _CIDR_RE, _DOMAIN_RE):
        m = pattern.search(text)
        if m:
            return m.group(1)
    return None


def _detect_intent(text: str) -> tuple[Intent, float]:
    text_lower = text.lower()
    scores: dict[Intent, int] = {}

    for intent, pattern in _INTENT_PATTERNS:
        matches = re.findall(pattern, text_lower)
        if matches:
            scores[intent] = scores.get(intent, 0) + len(matches)

    if not scores:
        return Intent.UNKNOWN, 0.0

    best = max(scores, key=lambda k: scores[k])
    total = sum(scores.values())
    confidence = scores[best] / total

    return best, round(confidence, 2)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class CommandInterpreter:
    """
    Translates free-form natural language into a ParsedCommand.
    Works entirely offline via regex; no external API required.
    """

    def parse(self, user_input: str) -> ParsedCommand:
        text = user_input.strip()
        intent, confidence = _detect_intent(text)
        target = _extract_target(text)

        options = self._extract_options(text, intent)

        explanation = self._build_explanation(intent, target, options)

        logger.debug(
            f"[NLP] '{text}' → intent={intent.value} target={target} conf={confidence}"
        )

        return ParsedCommand(
            raw_input=text,
            intent=intent,
            target=target,
            options=options,
            confidence=confidence,
            explanation=explanation,
        )

    # ------------------------------------------------------------------

    def _extract_options(self, text: str, intent: Intent) -> dict:
        opts: dict = {}

        # Port range
        m = re.search(r"\bport[s]?\s+(\d+(?:-\d+)?)\b", text, re.I)
        if m:
            opts["ports"] = m.group(1)

        # Wordlist path
        m = re.search(r"\bwordlist\s+(\S+)\b", text, re.I)
        if m:
            opts["wordlist"] = m.group(1)

        # Interface
        m = re.search(r"\b(wlan\d+|eth\d+|mon\d+)\b", text, re.I)
        if m:
            opts["interface"] = m.group(1)

        # Aggressiveness
        if re.search(r"\b(stealth|quiet|slow)\b", text, re.I):
            opts["stealth"] = True
        if re.search(r"\b(aggressive|fast|full)\b", text, re.I):
            opts["aggressive"] = True

        # Output format
        m = re.search(r"\b(xml|json|html)\s+output\b", text, re.I)
        if m:
            opts["output_format"] = m.group(1)

        return opts

    def _build_explanation(
        self, intent: Intent, target: Optional[str], options: dict
    ) -> str:
        t = f"target **{target}**" if target else "no specific target"
        base = {
            Intent.FULL_AUDIT:  f"Running full security audit on {t}",
            Intent.RECON:       f"Gathering intelligence on {t}",
            Intent.SCAN:        f"Port and service scan on {t}",
            Intent.VULN:        f"Vulnerability analysis on {t}",
            Intent.EXPLOIT:     f"Checking exploits for {t}",
            Intent.WIFI:        "WiFi reconnaissance mode",
            Intent.WEB:         f"Web application scan on {t}",
            Intent.PASSWORD:    f"Password attack on {t}",
            Intent.REPORT:      "Generating security report",
            Intent.HELP:        "Showing available commands",
            Intent.UNKNOWN:     "Command not recognised — try 'help'",
        }.get(intent, "")

        if options:
            opts_str = ", ".join(f"{k}={v}" for k, v in options.items())
            base += f" [{opts_str}]"

        return base
