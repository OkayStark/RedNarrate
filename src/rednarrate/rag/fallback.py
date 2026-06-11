"""Static reference context, compiled in.

Used when the Chroma store is empty (first run, or `ingest-kb` never run) so the
pipeline never fails for lack of RAG setup — it just writes slightly more generic
prose. One solid paragraph per common finding type.
"""

from __future__ import annotations

GENERIC_CONTEXT = (
    "This finding represents a security weakness that could be leveraged by an "
    "attacker to undermine the confidentiality, integrity, or availability of the "
    "affected system. Remediation should follow vendor guidance and recognized "
    "secure-configuration baselines, and be verified by re-testing."
)

STATIC_CONTEXT: dict[str, str] = {
    "sqli": (
        "SQL injection allows an attacker to interfere with the queries an "
        "application makes to its database, typically by submitting crafted input "
        "to a parameter. Impact ranges from authentication bypass and data "
        "disclosure to full database compromise. Remediation: use parameterized "
        "queries / prepared statements for all database access, apply least-"
        "privilege database accounts, and validate input server-side. References: "
        "CWE-89, OWASP A03:2021 Injection."
    ),
    "xss-reflected": (
        "Reflected cross-site scripting occurs when user-supplied data is included "
        "in a response without proper output encoding, allowing script execution in "
        "a victim's browser. Remediation: contextual output encoding, a strict "
        "Content-Security-Policy, and input validation. References: CWE-79, "
        "OWASP A03:2021."
    ),
    "xss-stored": (
        "Stored cross-site scripting persists attacker-controlled script in the "
        "application so it executes for other users. Remediation: output-encode all "
        "stored data on render, validate on input, and deploy a Content-Security-"
        "Policy. References: CWE-79, OWASP A03:2021."
    ),
    "os-command-injection": (
        "OS command injection lets an attacker execute arbitrary operating-system "
        "commands on the host running the application. Remediation: avoid calling "
        "the shell, use parameterized APIs, and strictly allow-list inputs. "
        "References: CWE-78, OWASP A03:2021."
    ),
    "rce": (
        "Remote code execution allows an attacker to run arbitrary code on the "
        "target, typically resulting in full system compromise. Remediation: patch "
        "the vulnerable component, restrict network exposure, and apply least "
        "privilege to the service account. References: CWE-94."
    ),
    "default-credentials": (
        "Default or weak credentials allow trivial unauthorized access to a service "
        "or administrative interface. Remediation: change all default credentials, "
        "enforce a strong password policy, and restrict management interfaces to "
        "trusted networks. References: CWE-1392, OWASP A07:2021."
    ),
    "info-disclosure": (
        "Information disclosure exposes sensitive technical or business data that "
        "aids an attacker. Remediation: remove verbose errors and banners, restrict "
        "access to sensitive files, and review responses for leaked data. "
        "References: CWE-200, OWASP A01:2021."
    ),
    "open-port": (
        "An open network port exposes a service to the tested network. While not a "
        "vulnerability in itself, unnecessary exposure increases attack surface. "
        "Remediation: restrict access via firewall rules, disable unused services, "
        "and ensure exposed services are patched and hardened."
    ),
    "ssl-issue": (
        "A weakness in the TLS/SSL configuration may allow interception or "
        "downgrade of encrypted traffic. Remediation: disable legacy protocols and "
        "ciphers, deploy current certificates, and enforce HSTS. References: "
        "CWE-326, OWASP A02:2021."
    ),
    "outdated-software": (
        "Outdated software contains known vulnerabilities that are publicly "
        "documented and frequently exploited. Remediation: apply vendor patches, "
        "establish a patch-management cadence, and remove unsupported components. "
        "References: CWE-1104, OWASP A06:2021."
    ),
    "csrf": (
        "Cross-site request forgery tricks an authenticated user's browser into "
        "submitting unwanted requests. Remediation: implement anti-CSRF tokens, use "
        "SameSite cookies, and verify the Origin/Referer on state-changing requests. "
        "References: CWE-352, OWASP A01:2021."
    ),
    "xxe": (
        "XML External Entity injection abuses an XML parser that resolves external "
        "entities, enabling file disclosure, SSRF, or denial of service. Remediation: "
        "disable DTD and external-entity resolution in the parser, and prefer less "
        "complex data formats. References: CWE-611, OWASP A05:2021."
    ),
    "ssrf": (
        "Server-side request forgery lets an attacker coerce the server into making "
        "requests to internal or unintended systems, often reaching cloud metadata "
        "endpoints. Remediation: allow-list outbound destinations, block link-local "
        "ranges, and validate user-supplied URLs. References: CWE-918, OWASP A10:2021."
    ),
    "idor": (
        "Insecure direct object reference exposes internal object identifiers without "
        "an authorization check, letting users access other users' data. Remediation: "
        "enforce per-object access control on every request and use unpredictable "
        "identifiers. References: CWE-639, OWASP A01:2021."
    ),
    "auth-bypass": (
        "Authentication bypass allows access to protected functionality without valid "
        "credentials. Remediation: centralize authentication checks, fail closed, and "
        "patch the underlying flaw. References: CWE-287, OWASP A07:2021."
    ),
    "anonymous-access": (
        "Anonymous access permits unauthenticated users to reach a service or its "
        "data. Remediation: require authentication, disable anonymous/guest accounts, "
        "and restrict the service to trusted networks. References: CWE-306."
    ),
    "directory-listing": (
        "Directory listing exposes the contents of a web directory, often revealing "
        "backups, source, or sensitive files. Remediation: disable automatic indexing "
        "(e.g. Options -Indexes) and remove sensitive files from web roots. "
        "References: CWE-548, OWASP A05:2021."
    ),
    "sensitive-data-exposure": (
        "Sensitive data exposure occurs when confidential information (credentials, "
        "PII, payment data) is accessible without adequate protection. Remediation: "
        "encrypt data at rest and in transit, remove exposed artifacts, and apply "
        "strict access control. References: CWE-200, OWASP A02:2021."
    ),
    "missing-security-headers": (
        "Missing HTTP security headers (HSTS, CSP, X-Content-Type-Options, etc.) "
        "weaken browser-side defenses. Remediation: set the recommended response "
        "headers at the server or gateway. References: OWASP Secure Headers Project."
    ),
    "weak-crypto": (
        "Weak or legacy cryptographic configuration (deprecated protocols, small DH "
        "parameters, weak ciphers) can allow downgrade or interception. Remediation: "
        "disable legacy protocols/ciphers and enforce modern TLS. References: CWE-326."
    ),
    "path-traversal": (
        "Path traversal lets an attacker read files outside the intended directory by "
        "manipulating path input. Remediation: canonicalize and validate paths, and "
        "use allow-lists rather than user-supplied file names. References: CWE-22."
    ),
    "lfi": (
        "Local file inclusion allows inclusion of server files via attacker-controlled "
        "paths, leading to disclosure or code execution. Remediation: avoid dynamic "
        "includes, validate against an allow-list, and disable URL inclusion. "
        "References: CWE-98."
    ),
    "cors-misconfiguration": (
        "An overly permissive CORS policy can let untrusted origins read authenticated "
        "responses. Remediation: reflect only trusted origins, avoid wildcard with "
        "credentials, and validate the Origin header. References: CWE-942."
    ),
    "unrestricted-file-upload": (
        "Unrestricted file upload allows an attacker to upload files of arbitrary "
        "type, potentially leading to remote code execution, malware hosting, or "
        "stored XSS. Remediation: validate file type server-side by magic bytes, "
        "restrict to an allow-list of safe extensions, store uploads outside the "
        "web root, and serve them via a content-delivery path that disables script "
        "execution. References: CWE-434, OWASP A04:2021."
    ),
    "ssti": (
        "Server-side template injection arises when user input is embedded directly "
        "into a template engine and evaluated, often leading to remote code execution. "
        "Remediation: never pass raw user input to template engines; use sandboxed "
        "rendering, enforce logic-less templates, and audit all dynamic template "
        "construction. References: CWE-94, OWASP A03:2021."
    ),
    "privilege-escalation": (
        "Privilege escalation allows a lower-privileged user or process to gain "
        "elevated access, often full administrative or root control. Remediation: "
        "apply least-privilege principles, patch the underlying flaw, audit sudo/SUID "
        "binaries, and enforce mandatory access controls. References: CWE-269."
    ),
    "web-issue": (
        "A general web application security weakness was identified. Remediation "
        "should follow OWASP guidelines relevant to the specific issue, apply "
        "secure coding practices, and verify the fix with re-testing."
    ),
    "dos": (
        "A denial-of-service condition allows an attacker to degrade or crash the "
        "service, affecting availability. Remediation: apply the vendor patch, "
        "implement rate limiting, and isolate the affected service. References: CWE-400."
    ),
    "deserialization": (
        "Insecure deserialization occurs when untrusted data is used to reconstruct "
        "objects, often enabling remote code execution or privilege escalation. "
        "Remediation: validate and sign serialized data, avoid native deserialization "
        "of untrusted input, and prefer safe data formats such as JSON. "
        "References: CWE-502, OWASP A08:2021."
    ),
    "open-redirect": (
        "An open redirect allows attackers to craft URLs that redirect users to "
        "arbitrary external sites, facilitating phishing and credential harvesting. "
        "Remediation: use an allow-list of trusted redirect destinations and avoid "
        "passing user-controlled data directly to redirect logic. References: CWE-601."
    ),
    "clickjacking": (
        "Clickjacking (UI redress attack) tricks users into clicking concealed elements "
        "by embedding the target page in an iframe. Remediation: set the X-Frame-Options "
        "header to DENY or SAMEORIGIN, or use the frame-ancestors CSP directive. "
        "References: CWE-1021, OWASP A05:2021."
    ),
    "ssl-weak-cipher": (
        "Weak TLS cipher suites (RC4, export-grade, NULL, anonymous DH) allow "
        "cryptographic attacks such as BEAST, POODLE, or LOGJAM. Remediation: "
        "configure only ECDHE+AES-GCM or ChaCha20-Poly1305 cipher suites and "
        "disable SSLv3/TLSv1.0/TLSv1.1. References: CWE-327."
    ),
    "missing-header": (
        "One or more recommended HTTP security response headers are absent, weakening "
        "browser-side defenses. Remediation: configure the server or WAF to emit "
        "HSTS, Content-Security-Policy, X-Content-Type-Options, and X-Frame-Options "
        "on all responses. References: OWASP Secure Headers Project."
    ),
    "broken-authentication": (
        "Broken authentication encompasses flaws in session management, credential "
        "handling, or authentication logic that allow account takeover or unauthorized "
        "access. Remediation: enforce MFA, use secure session tokens, implement "
        "account lockout, and audit all authentication flows. "
        "References: CWE-287, OWASP A07:2021."
    ),
    "host-header-injection": (
        "Host header injection occurs when the application uses the HTTP Host header "
        "in logic or links without validation, enabling password-reset poisoning, "
        "cache poisoning, or SSRF. Remediation: validate the Host header against an "
        "allow-list and avoid using it to construct URLs in emails or redirects. "
        "References: CWE-20."
    ),
}


def static_context(finding_type: str) -> str:
    return STATIC_CONTEXT.get(finding_type, GENERIC_CONTEXT)
