"""Security Telemetry & Incident Audit Trail"""

import time
from typing import Dict, Any, List


class SecurityAuditor:
    def __init__(self):
        self.total_scans = 0
        self.injections_blocked = 0
        self.pii_redacted_count = 0
        self.budget_violations = 0
        self.latency_sum_ms = 0.0
        self.recent_incidents: List[Dict[str, Any]] = []

    def record_scan(
        self,
        risk_score: float,
        is_blocked: bool,
        has_pii: bool,
        redactions: int,
        budget_exceeded: bool,
        latency_ms: float,
        prompt_snippet: str
    ):
        self.total_scans += 1
        self.latency_sum_ms += latency_ms

        if is_blocked:
            self.injections_blocked += 1
        if has_pii:
            self.pii_redacted_count += redactions
        if budget_exceeded:
            self.budget_violations += 1

        if is_blocked or has_pii or budget_exceeded:
            incident = {
                "timestamp": time.time(),
                "risk_score": risk_score,
                "blocked": is_blocked,
                "has_pii": has_pii,
                "redactions": redactions,
                "budget_exceeded": budget_exceeded,
                "latency_ms": round(latency_ms, 2),
                "snippet": prompt_snippet[:100] + "..." if len(prompt_snippet) > 100 else prompt_snippet
            }
            self.recent_incidents.insert(0, incident)
            if len(self.recent_incidents) > 50:
                self.recent_incidents.pop()

    def get_metrics(self) -> Dict[str, Any]:
        avg_latency = (
            round(self.latency_sum_ms / self.total_scans, 2)
            if self.total_scans > 0 else 0.0
        )
        return {
            "total_prompts_scanned": self.total_scans,
            "injections_blocked": self.injections_blocked,
            "total_pii_entities_redacted": self.pii_redacted_count,
            "token_budget_violations": self.budget_violations,
            "avg_inspection_latency_ms": avg_latency,
            "active_protection_rules": [
                "Prompt Injection (OWASP LLM01)",
                "Sensitive Data Exposure (OWASP LLM06)",
                "Denial-of-Wallet / DoS (OWASP LLM04)"
            ],
            "recent_incidents_count": len(self.recent_incidents)
        }


security_auditor = SecurityAuditor()
