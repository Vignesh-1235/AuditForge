"""
Ollama Client - TURBO MODE
One single Mistral call for ALL findings at once.
Completes in seconds instead of minutes.
"""

import sys
import json as _json
import requests
from typing import List
from parsers.parser_engine import Finding
from utils.logger import get_logger

logger = get_logger("ollama_client")

OLLAMA_BASE = "http://localhost:11434"
OLLAMA_GEN  = f"{OLLAMA_BASE}/api/generate"
OLLAMA_TAGS = f"{OLLAMA_BASE}/api/tags"


class OllamaClient:
    def __init__(self, model: str = "mistral"):
        self.model = model

    def check_connection(self) -> bool:
        try:
            resp = requests.get(OLLAMA_TAGS, timeout=5)
            if resp.status_code != 200:
                return False
            available = [m["name"] for m in resp.json().get("models", [])]
            matched   = [m for m in available if self.model.split(":")[0] in m]
            if not matched:
                logger.error(f"Model '{self.model}' not found. Run: ollama pull {self.model}")
                return False
            logger.info(f"✅ Ollama running  |  model: {matched[0]}")
            return True
        except requests.exceptions.ConnectionError:
            logger.error("❌ Ollama not running. Run: ollama serve")
            return False
        except Exception as e:
            logger.error(f"Ollama check failed: {e}")
            return False

    def _query(self, prompt: str, system: str = "", max_tokens: int = 2000) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": True,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.2,
                "top_p": 0.9,
                "repeat_penalty": 1.1,
            },
        }
        try:
            full = []
            with requests.post(OLLAMA_GEN, json=payload, stream=True, timeout=300) as resp:
                if resp.status_code != 200:
                    return ""
                sys.stdout.write("  Mistral thinking")
                sys.stdout.flush()
                chars = 0
                for line in resp.iter_lines():
                    if not line:
                        continue
                    try:
                        chunk = _json.loads(line)
                    except Exception:
                        continue
                    token = chunk.get("response", "")
                    full.append(token)
                    chars += len(token)
                    if chars >= 80:
                        sys.stdout.write(".")
                        sys.stdout.flush()
                        chars = 0
                    if chunk.get("done"):
                        break
            sys.stdout.write(" done!\n\n")
            sys.stdout.flush()
            return "".join(full).strip()
        except requests.exceptions.Timeout:
            logger.warning("Mistral timed out")
            return ""
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return ""

    # ------------------------------------------------------------------ #
    #  TURBO: One single call for ALL findings
    # ------------------------------------------------------------------ #
    def analyze_findings(self, findings: List[Finding], context_note: str, org_name: str) -> List[Finding]:
        """
        TURBO MODE: One Mistral call capped at 15 unique critical/high findings.
        Everything else uses instant fallbacks. Target: 15-25 seconds total.
        """
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        medium        = [f for f in findings if f.severity == "medium"]
        low           = [f for f in findings if f.severity == "low"]

        # Deduplicate by title
        seen   = {}
        unique = []
        dupes  = []
        for f in critical_high:
            key = f.title.lower().strip()
            if key not in seen:
                seen[key] = None
                unique.append(f)
            else:
                dupes.append(f)

        # ── SPEED CAP: only send top 15 to Mistral, rest use fallbacks ──
        MAX_AI = 15
        ai_batch   = unique[:MAX_AI]
        fallback_q = unique[MAX_AI:]

        logger.info(f"TURBO MODE: {len(ai_batch)} findings → Mistral | {len(fallback_q)} fallback | {len(dupes)} cached | {len(medium)+len(low)} built-in")

        # Build compact numbered list — truncate descriptions hard
        finding_lines = []
        for i, f in enumerate(ai_batch):
            finding_lines.append(
                f"{i+1}. [{f.severity.upper()}] {f.title} | {f.host}:{f.port} | {f.description[:80]}"
            )
        findings_text = "\n".join(finding_lines)

        system_prompt = f"Cybersecurity auditor. Client: {org_name}. Return ONLY valid JSON array."

        prompt = f"""Analyze {len(ai_batch)} findings. Return JSON array only:
[{{"id":1,"analysis":"1 sentence risk.","rec":"1. Fix. 2. Fix. 3. Fix."}},...]

Findings:
{findings_text}

Return exactly {len(ai_batch)} objects. id=finding number. analysis=1 sentence. rec=3 steps."""

        response = self._query(prompt, system_prompt, max_tokens=1500)
        results  = self._parse_json_response(response, len(ai_batch))

        # Apply AI results to batch
        for i, f in enumerate(ai_batch):
            result = results.get(i + 1, {})
            f.llm_analysis   = result.get("analysis", "") or self._fallback_analysis(f, org_name)
            f.recommendation = f.recommendation or result.get("rec", "") or result.get("recommendation", "") or self._fallback_recommendation(f)
            seen[f.title.lower().strip()] = (f.llm_analysis, f.recommendation)

        # Fallback for overflow unique findings
        for f in fallback_q:
            f.llm_analysis   = self._fallback_analysis(f, org_name)
            f.recommendation = f.recommendation or self._fallback_recommendation(f)
            seen[f.title.lower().strip()] = (f.llm_analysis, f.recommendation)

        # Reuse cached for duplicates
        for f in dupes:
            cached = seen.get(f.title.lower().strip())
            if cached:
                f.llm_analysis   = cached[0]
                f.recommendation = f.recommendation or cached[1]
            else:
                f.llm_analysis   = self._fallback_analysis(f, org_name)
                f.recommendation = f.recommendation or self._fallback_recommendation(f)

        # Medium / Low: instant built-in text
        for f in medium + low:
            f.llm_analysis   = self._fallback_analysis(f, org_name)
            f.recommendation = f.recommendation or self._fallback_recommendation(f)

        logger.info(f"✅ Done! All {len(findings)} findings analyzed.\n")
        return critical_high + medium + low

    def _parse_json_response(self, response: str, expected: int) -> dict:
        """Parse Mistral's JSON response into a dict keyed by finding id."""
        if not response:
            return {}
        try:
            # Find JSON array in response
            start = response.find("[")
            end   = response.rfind("]") + 1
            if start == -1 or end == 0:
                raise ValueError("No JSON array found")
            json_str = response[start:end]
            data = _json.loads(json_str)
            return {item["id"]: item for item in data if "id" in item}
        except Exception as e:
            logger.warning(f"JSON parse failed ({e}), trying line-by-line fallback")
            return self._fallback_parse(response, expected)

    def _fallback_parse(self, response: str, expected: int) -> dict:
        """If JSON parsing fails, extract what we can."""
        results = {}
        try:
            # Try to find individual objects
            import re
            objects = re.findall(r'\{[^{}]+\}', response, re.DOTALL)
            for obj_str in objects:
                try:
                    obj = _json.loads(obj_str)
                    if "id" in obj:
                        results[obj["id"]] = obj
                except Exception:
                    continue
        except Exception:
            pass
        return results

    # ------------------------------------------------------------------ #
    #  Executive Summary — also one call
    # ------------------------------------------------------------------ #
    def generate_executive_summary(self, findings: List[Finding], context_note: str, org_name: str) -> str:
        critical_c = sum(1 for f in findings if f.severity == "critical")
        high_c     = sum(1 for f in findings if f.severity == "high")
        medium_c   = sum(1 for f in findings if f.severity == "medium")

        top      = [f for f in findings if f.severity in ("critical", "high")][:8]
        top_list = "\n".join(f"- [{f.severity.upper()}] {f.title} ({f.host})" for f in top)

        system_prompt = "CISO writing a concise board summary. Plain text only."

        prompt = (
            f"Write a 3-paragraph executive summary for {org_name}.\n"
            f"Stats: {critical_c} Critical, {high_c} High, {medium_c} Medium.\n"
            f"Top risks:\n{top_list}\n"
            f"(1) overall posture (2) top risks (3) recommended actions. Plain text, no headers."
        )

        logger.info("Generating Executive Summary...")
        summary = self._query(prompt, system_prompt, max_tokens=300)
        return summary or self._fallback_executive_summary(org_name, critical_c, high_c, medium_c, top)

    # ------------------------------------------------------------------ #
    #  Fallbacks
    # ------------------------------------------------------------------ #
    def _fallback_analysis(self, f: Finding, org_name: str) -> str:
        msg = {
            "critical": f"This critical finding on {f.host} poses an immediate exploitable risk to {org_name}. An attacker could gain full system control, leading to data theft or ransomware deployment.",
            "high":     f"This high-severity issue on {f.host} significantly expands {org_name}'s attack surface. Exploitation could enable unauthorised access or lateral movement across the network.",
            "medium":   f"This medium-severity finding on {f.host} presents a moderate risk. Address during the next maintenance window.",
            "low":      f"This informational finding on {f.host} poses minimal direct risk. Resolve during routine security reviews.",
        }
        return msg.get(f.severity, msg["medium"])

    def _fallback_recommendation(self, f: Finding) -> str:
        lookup = {
            "ftp":  "1. Disable FTP and migrate to SFTP/SCP. 2. Block port 21 at the firewall. 3. Remove anonymous and default-credential accounts.",
            "ssl":  "1. Disable TLS 1.0/1.1 and SSLv2/3. 2. Remove weak ciphers (RC4, DES, NULL, EXPORT). 3. Enforce TLS 1.2+ with AES-GCM suites.",
            "http": "1. Add missing security headers (CSP, HSTS, X-Frame-Options). 2. Deploy a WAF. 3. Disable risky HTTP methods (TRACE, PUT).",
            "snmp": "1. Disable SNMPv1/v2c. 2. Upgrade to SNMPv3 with AES encryption. 3. Change all default community strings.",
            "os":   "1. Migrate to a supported OS immediately. 2. Apply all outstanding patches. 3. Isolate with firewall rules until migration is done.",
        }
        for key, rec in lookup.items():
            if key in f.service.lower() or key in f.title.lower():
                return rec
        return "1. Apply latest vendor security patches. 2. Restrict access with firewall rules. 3. Follow vendor hardening guidelines."

    def _fallback_executive_summary(self, org_name, critical, high, medium, top) -> str:
        top_str = "; ".join(f.title for f in top[:3])
        return (
            f"This security assessment of {org_name} identified {critical + high + medium} findings — "
            f"{critical} critical, {high} high, and {medium} medium severity.\n\n"
            f"The most critical risks include: {top_str}. These present direct exploitation paths "
            f"that could result in data exfiltration or operational disruption.\n\n"
            f"Immediate priorities: resolve all critical findings within 24-72 hours, "
            f"high-severity within 30 days, medium findings in the next maintenance cycle.\n\n"
            f"Strategically, {org_name} should invest in vulnerability management, "
            f"network segmentation, and regular penetration testing."
        )
