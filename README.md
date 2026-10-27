<div align="center">

# 🛡️ PromptShield
### High-Performance LLM Security Gateway & Prompt Injection Firewall

[![CI Pipeline](https://github.com/Jayouss/promptshield/actions/workflows/ci.yml/badge.svg)](https://github.com/Jayouss/promptshield/actions)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![OWASP Top 10 for LLM](https://img.shields.io/badge/OWASP-LLM_Top_10_Compliant-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Latency](https://img.shields.io/badge/Latency-%3C0.1ms-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<p align="center">
  A blazing-fast, sub-millisecond reverse proxy and security guardrail for LLM applications. Protects against <b>Prompt Injections</b>, <b>DAN Jailbreaks</b>, <b>Data Leakage (PII Masking)</b>, and <b>Denial-of-Wallet (DoS)</b> attacks before prompts reach OpenAI or Anthropic.
</p>

[Threat Model](#-threat-model-coverage) • [Architecture](#-system-architecture) • [Quickstart](#-quickstart) • [Attack Simulation](#-interactive-attack-simulation) • [API Reference](#-api-endpoints)

</div>

---

## 🛡️ Threat Model Coverage (OWASP LLM Top 10)

| Threat ID | Vulnerability Category | Mitigation Strategy in PromptShield | Status |
| :--- | :--- | :--- | :---: |
| **LLM01** | **Prompt Injection** | Multi-category heuristic signature matching (Overrides, Delimiters, Leaks). | ✅ Active |
| **LLM04** | **Model Denial-of-Service** | Subword token estimation and strict request budget enforcement. | ✅ Active |
| **LLM06** | **Sensitive Information Disclosure** | Real-time PII redaction (Emails, Credit Cards, Secrets, NIK/SSN, Phones). | ✅ Active |
| **LLM07** | **System Prompt Exfiltration** | Pattern traps for instruction extraction and verbatim reflection requests. | ✅ Active |

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    Client["Client / User / Application"] -->|POST /v1/chat/completions or /inspect| Shield["PromptShield Security Gateway (:8080)"]

    subgraph "PromptShield Defense Pipeline (< 0.1ms overhead)"
        Shield --> BudgetCheck{"Token Budget Check"}
        BudgetCheck -->|Exceeded| BlockDoS["Reject: 413 Token Budget Exceeded"]
        
        BudgetCheck -->|Within Budget| InjectionScanner["Injection & Jailbreak Scanner"]
        InjectionScanner -->|Risk Score >= 0.65| BlockInjection["Block: 400 Prompt Injection Detected"]
        
        InjectionScanner -->|Risk Score < 0.65| PIIRedactor["Zero-Latency PII Redactor Engine"]
        PIIRedactor -->|Mask Emails, Cards, Keys| CleanPrompt["Generate Sanitized Prompt"]
    end

    CleanPrompt --> Upstream["Upstream LLM (OpenAI / Anthropic / Local LLM)"]
    Upstream --> ReturnResponse["Return Safe AI Completion"]
    Shield --> Telemetry["Audit Logs & Security Metrics"]
```

---

## ⚡ Key Engineering Highlights

* **Sub-Millisecond Inspection Latency**: Averaging **0.05 ms** inspection overhead using pre-compiled regex automata and lightweight token counters.
* **OpenAI-Compatible Drop-In Proxy**: Switch your application's `baseURL` to `http://localhost:8080/v1` to instantly add enterprise firewall protection with zero application code changes.
* **Deterministic PII Redaction**: Automatically sanitizes Emails (`[REDACTED_EMAIL]`), Credit Cards (`[REDACTED_CREDIT_CARD]`), API Keys / JWTs (`[REDACTED_SECRET]`), Phone Numbers (`[REDACTED_PHONE]`), and National IDs (`[REDACTED_NATIONAL_ID]`).
* **Jailbreak & DAN Pattern Traps**: Detects adversarial roleplay bypasses (*"You are now DAN"*, *"developer mode enabled"*, *"disregard prior directives"*).
* **Denial-of-Wallet Mitigation**: Prevents malicious attackers from exhausting corporate LLM tokens through recursive word floods.

---

## 🚀 Quickstart

### 1. Local Setup
```bash
git clone https://github.com/Jayouss/promptshield.git
cd promptshield

pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```
* Gateway API: `http://localhost:8080`
* Interactive Swagger Docs: `http://localhost:8080/docs`

---

### 2. Docker Setup
```bash
docker compose up --build -d
```

---

## 🧪 Interactive Attack Simulation

Run the automated attack test harness to watch PromptShield block jailbreaks, mask secrets, and mitigate DoS floods live in the console:

```bash
python scripts/demo_attack_simulation.py
```

### Sample Simulation Output:
```text
===========================================================================
>> PROMPTSHIELD — LLM SECURITY GATEWAY & ATTACK SIMULATION
===========================================================================
Initializing active firewall rules: OWASP LLM01, LLM04, LLM06...

[SCENARIO]: 1. Benign Technical Query
  [DECISION]: ✅ ALLOWED (Clean prompt. No threats detected.)
  [Inspection Latency]: 0.04 ms

[SCENARIO]: 2. Accidental PII / Secret Leak
  [DECISION]: 🛡️ SANITIZED (Redacted 3 PII entities: ['EMAIL', 'CREDIT_CARD', 'API_SECRET'])
  [Sanitized Output]: "Debug this script with customer email [REDACTED_EMAIL], card [REDACTED_CREDIT_CARD], and key [REDACTED_SECRET]."
  [Inspection Latency]: 0.06 ms

[SCENARIO]: 3. Prompt Injection (Instruction Override)
  [DECISION]: 🛑 BLOCKED (Threat Level: CRITICAL_INJECTION (Risk Score: 0.75))
  [Threat Signatures Detected]: [{'category': 'INSTRUCTION_OVERRIDE', 'matched_pattern': 'Ignore all previous directives'}]
  [Inspection Latency]: 0.04 ms

[SCENARIO]: 4. Jailbreak Attack (DAN Mode)
  [DECISION]: 🛑 BLOCKED (Threat Level: CRITICAL_INJECTION (Risk Score: 1.0))
  [Threat Signatures Detected]: [{'category': 'JAILBREAK_ROLEPLAY', 'matched_pattern': 'You are now DAN'}]
  [Inspection Latency]: 0.04 ms

[SCENARIO]: 5. DoS / Token Flood Attack
  [DECISION]: 🛑 BLOCKED (Token Budget Exceeded: 5698 tokens)
  [Latency]: 0.24 ms
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/shield/inspect` | Analyze prompt: returns decision (`ALLOW`, `SANITIZE`, `BLOCK`), redacted text, and risk scores. |
| `POST` | `/v1/chat/completions` | Drop-in OpenAI API compatible proxy with inline firewall protection. |
| `GET` | `/api/v1/shield/metrics` | Security telemetry: total prompts scanned, injections blocked, PII masked. |
| `GET` | `/health` | Service health and active firewall rules. |

### cURL Examples

#### Inspect & Sanitize Prompt
```bash
curl -X POST http://localhost:8080/api/v1/shield/inspect \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Please review code for john@acme.corp using key ghp_secret1234567890abcdefghijklmnopqrst."
  }'
```

#### Drop-In OpenAI Proxy Request
```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "How do I secure an API?"}
    ]
  }'
```

---

## 🧪 Testing

```bash
# Run pytest test suite
pytest tests -v
```

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
