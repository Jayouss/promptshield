"""Token Budget & Denial-of-Wallet (DoS) Mitigation Engine"""

from typing import Dict, Any
from app.core.config import settings


class TokenBudgetGuard:
    def __init__(self, max_tokens: int = settings.MAX_TOKEN_BUDGET_PER_REQUEST):
        self.max_tokens = max_tokens

    def estimate_tokens(self, text: str) -> int:
        """Fast subword-approximated token counter (approx 3.8 - 4.0 chars per token in English)."""
        if not text:
            return 0
        words = text.split()
        char_count = len(text)
        # Hybrid formula: blend character count and word count
        estimated = int((char_count / 4.0) * 0.7 + (len(words) * 1.3) * 0.3)
        return max(1, estimated)

    def check_budget(self, text: str) -> Dict[str, Any]:
        """Verify if prompt complies with token quota limits."""
        tokens = self.estimate_tokens(text)
        is_exceeded = tokens > self.max_tokens

        return {
            "estimated_tokens": tokens,
            "max_allowed_tokens": self.max_tokens,
            "within_budget": not is_exceeded,
            "status": "APPROVED" if not is_exceeded else "TOKEN_BUDGET_EXCEEDED"
        }


token_guard = TokenBudgetGuard()
