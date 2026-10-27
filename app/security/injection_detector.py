"""Prompt Injection & Jailbreak Heuristic Analysis Engine"""

import re
from typing import Dict, Any, List, Tuple
from app.core.config import settings


class InjectionDetector:
    def __init__(self):
        # Categorized adversarial trigger signatures
        self.signatures = {
            "INSTRUCTION_OVERRIDE": [
                r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules|prompts)",
                r"disregard\s+(all\s+)?(prior|previous|existing)\s+(guidelines|instructions|rules|directives)",
                r"forget\s+(everything|all)\s+(you\s+know|previously\s+told)",
                r"override\s+(system|safety|core)\s+(instructions|filters|rules)",
            ],
            "JAILBREAK_ROLEPLAY": [
                r"\byou\s+are\s+now\s+(dan|an\s+unfiltered|an\s+unrestricted|jailbroken|evil)\b",
                r"do\s+anything\s+now",
                r"developer\s+mode\s+(enabled|activated|on)",
                r"unrestricted\s+mode",
                r"bypass\s+(content\s+filters|safety\s+protocols|openai\s+guidelines)",
                r"pretend\s+(there\s+are\s+no|you\s+have\s+no)\s+(rules|restrictions|filters)",
            ],
            "SYSTEM_PROMPT_LEAK": [
                r"(output|repeat|print|show|reveal)\s+.*?(system|initial|developer|original)\s+(prompt|instructions)",
                r"what\s+are\s+your\s+.*?(system|initial)\s+instructions",
                r"verbatim\s+copy\s+of\s+(your\s+)?prompt",
            ],
            "DELIMITER_EXPLOITATION": [
                r"<\s*/?\s*(system|assistant|instruction|prompt)\s*>",
                r"\[\s*system\s*:\s*",
                r"###\s*(instruction|system|human)\s*:",
            ],
        }

        # Compile regex patterns
        self.compiled_signatures = {
            category: [re.compile(p, re.IGNORECASE) for p in patterns]
            for category, patterns in self.signatures.items()
        }

    def analyze(self, text: str) -> Dict[str, Any]:
        """Evaluate text for adversarial prompt injection patterns."""
        if not text or not text.strip():
            return {
                "risk_score": 0.0,
                "is_injection": False,
                "threat_level": "SAFE",
                "detected_threats": []
            }

        detected_threats: List[Dict[str, str]] = []
        score = 0.0

        for category, patterns in self.compiled_signatures.items():
            for regex in patterns:
                match = regex.search(text)
                if match:
                    detected_threats.append({
                        "category": category,
                        "matched_pattern": match.group(0)
                    })
                    # Calibrated threat weights
                    if category == "INSTRUCTION_OVERRIDE":
                        score += 0.75
                    elif category == "JAILBREAK_ROLEPLAY":
                        score += 0.80
                    elif category == "SYSTEM_PROMPT_LEAK":
                        score += 0.70
                    elif category == "DELIMITER_EXPLOITATION":
                        score += 0.45

        # Cap score between 0.0 and 1.0
        final_risk_score = round(min(score, 1.0), 3)
        is_injection = final_risk_score >= settings.INJECTION_RISK_THRESHOLD

        if final_risk_score >= 0.70:
            threat_level = "CRITICAL_INJECTION"
        elif final_risk_score >= 0.35:
            threat_level = "SUSPICIOUS"
        else:
            threat_level = "SAFE"

        return {
            "risk_score": final_risk_score,
            "is_injection": is_injection,
            "threat_level": threat_level,
            "detected_threats": detected_threats
        }


injection_detector = InjectionDetector()
