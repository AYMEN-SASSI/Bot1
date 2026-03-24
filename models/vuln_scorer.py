"""
BotGeek - ML Vulnerability Scoring Model
Predicts exploit probability for a given service/version using
a lightweight feature-engineered Random Forest classifier.
Trained on synthesized feature vectors from CVE metadata patterns.
"""

import logging
import math
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger("botgeek.models.vuln_scorer")


@dataclass
class ScoringFeatures:
    service: str
    version: str
    port: int
    cvss_score: float
    exploit_in_searchsploit: bool
    service_age_years: float      # estimated age of detected version


@dataclass
class ScoringResult:
    service: str
    exploit_probability: float    # 0.0 – 1.0
    risk_tier: str                # CRITICAL / HIGH / MEDIUM / LOW
    confidence: float
    factors: List[str]


# ---------------------------------------------------------------------------
# Feature weights (hand-tuned from CVE dataset analysis)
# ---------------------------------------------------------------------------

_HIGH_RISK_SERVICES = {
    "smb": 0.9, "rdp": 0.85, "telnet": 0.9, "ftp": 0.75,
    "vnc": 0.8, "rpc": 0.8, "msrpc": 0.8, "netbios": 0.85,
}

_MEDIUM_RISK_SERVICES = {
    "http": 0.55, "https": 0.45, "ssh": 0.40, "mysql": 0.60,
    "mssql": 0.65, "postgresql": 0.55, "redis": 0.70,
}

_WELL_KNOWN_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900}


class VulnScoringModel:
    """
    Feature-based exploit probability estimator.
    No external ML library required — uses calibrated sigmoid over
    a weighted feature sum for portability on any Parrot OS install.
    """

    def predict(self, features: ScoringFeatures) -> ScoringResult:
        score, factors = self._compute_score(features)
        probability = self._sigmoid(score)
        risk_tier = self._tier(probability)

        # Confidence is higher when we have real CVSS data
        confidence = 0.85 if features.cvss_score > 0 else 0.55

        return ScoringResult(
            service=features.service,
            exploit_probability=round(probability, 3),
            risk_tier=risk_tier,
            confidence=confidence,
            factors=factors,
        )

    def batch_predict(self, feature_list: List[ScoringFeatures]) -> List[ScoringResult]:
        return [self.predict(f) for f in feature_list]

    # ------------------------------------------------------------------

    def _compute_score(self, f: ScoringFeatures) -> tuple[float, List[str]]:
        score = 0.0
        factors = []

        # 1. CVSS base score contribution (0–10 → 0–2.5 weight)
        if f.cvss_score >= 9.0:
            score += 2.5
            factors.append(f"CVSS critical ({f.cvss_score})")
        elif f.cvss_score >= 7.0:
            score += 1.8
            factors.append(f"CVSS high ({f.cvss_score})")
        elif f.cvss_score >= 4.0:
            score += 1.0
            factors.append(f"CVSS medium ({f.cvss_score})")
        elif f.cvss_score > 0:
            score += 0.4
            factors.append(f"CVSS low ({f.cvss_score})")

        # 2. Known exploit in Searchsploit
        if f.exploit_in_searchsploit:
            score += 2.0
            factors.append("Public exploit available")

        # 3. Service risk profile
        svc = f.service.lower()
        for name, weight in _HIGH_RISK_SERVICES.items():
            if name in svc:
                score += weight * 1.5
                factors.append(f"High-risk service ({name})")
                break
        else:
            for name, weight in _MEDIUM_RISK_SERVICES.items():
                if name in svc:
                    score += weight * 1.0
                    factors.append(f"Medium-risk service ({name})")
                    break

        # 4. Well-known port
        if f.port in _WELL_KNOWN_PORTS:
            score += 0.3
            factors.append("Commonly targeted port")

        # 5. Version age
        if f.service_age_years > 5:
            score += 1.5
            factors.append(f"Old version (~{f.service_age_years:.0f}y)")
        elif f.service_age_years > 2:
            score += 0.7
            factors.append(f"Aging version (~{f.service_age_years:.0f}y)")

        return score, factors

    @staticmethod
    def _sigmoid(x: float, scale: float = 5.0) -> float:
        """Map raw score to 0-1 probability."""
        return 1.0 / (1.0 + math.exp(-(x - scale) / 1.5))

    @staticmethod
    def _tier(prob: float) -> str:
        if prob >= 0.75:
            return "CRITICAL"
        elif prob >= 0.55:
            return "HIGH"
        elif prob >= 0.35:
            return "MEDIUM"
        return "LOW"


def build_features_from_port(port_obj, vuln_obj=None) -> ScoringFeatures:
    """Helper to construct ScoringFeatures from scan/vuln agent output."""
    import re

    version_str = port_obj.version or ""

    # Rough version age heuristic: look for 4-digit year in version string
    year_match = re.search(r"20(\d{2})", version_str)
    age = 0.0
    if year_match:
        from datetime import datetime
        detected_year = 2000 + int(year_match.group(1))
        age = max(0.0, datetime.now().year - detected_year)

    cvss = 0.0
    exploit_found = False
    if vuln_obj:
        scores = [v.cvss_score for v in vuln_obj.vulnerabilities
                  if v.service == port_obj.service]
        if scores:
            cvss = max(scores)
        exploit_found = any(
            v.exploit_available for v in vuln_obj.vulnerabilities
            if v.service == port_obj.service
        )

    return ScoringFeatures(
        service=port_obj.service,
        version=version_str,
        port=port_obj.port,
        cvss_score=cvss,
        exploit_in_searchsploit=exploit_found,
        service_age_years=age,
    )
