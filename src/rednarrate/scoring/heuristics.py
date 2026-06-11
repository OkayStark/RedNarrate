"""Default CVSS 3.1 base vectors per finding_type.

These serve two purposes: the anchor given to the scoring LLM (so its job is
constrained 'adjust this default given the evidence' rather than 'score this'),
and the deterministic fallback when the LLM call fails or produces garbage.
Vectors are conservative, defensible class-level defaults — the LLM refines.
"""

from __future__ import annotations

# CVSS:3.1 vector tails (the AV.../A:.. part). Full string assembled at use.
HEURISTICS: dict[str, str] = {
    # ── injection / RCE: typically critical ──────────────────────────
    "sqli": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                 # 9.8
    "os-command-injection": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "rce": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                  # 9.8
    "xxe": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",                  # 8.6
    "ssti": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "deserialization": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    # ── auth / access ────────────────────────────────────────────────
    "default-credentials": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "auth-bypass": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "anonymous-access": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "idor": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "privilege-escalation": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    # ── XSS family ───────────────────────────────────────────────────
    "xss-reflected": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",       # 6.1
    "xss-stored": "AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",          # 5.4
    "csrf": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",               # 4.3
    "open-redirect": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
    "clickjacking": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    # ── information / config ─────────────────────────────────────────
    "info-disclosure": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",     # 5.3
    "sensitive-data-exposure": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "directory-listing": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "ssl-issue": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "ssl-weak-cipher": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "weak-crypto": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "outdated-software": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "missing-header": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "missing-security-headers": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "cors-misconfiguration": "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
    # ── traversal / file / server-side request ───────────────────────
    "lfi": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "path-traversal": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssrf": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    # ── upload / injection variants ──────────────────────────────────
    "unrestricted-file-upload": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  # 8.1 High
    # ── auth / session ───────────────────────────────────────────────
    "broken-authentication": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1 Critical
    "host-header-injection": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1 Medium
    # ── exposure ─────────────────────────────────────────────────────
    "open-port": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",          # 0.0 / Info
    "web-issue": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",          # fallback for ZAP generic
    "dos": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",                # 7.5 High
}

# Used when finding_type is unknown — a conservative low/info default.
DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def heuristic_vector(finding_type: str) -> str:
    """Return a full CVSS:3.1 vector string for a finding type."""
    tail = HEURISTICS.get(finding_type)
    if tail:
        return f"CVSS:3.1/{tail}"
    # nse-* and other unknown classes fall back to the info default.
    return DEFAULT_VECTOR
