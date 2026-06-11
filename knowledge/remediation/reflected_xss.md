# Reflected Cross-Site Scripting — Remediation Guidance

## Description
Reflected cross-site scripting (XSS) occurs when user-supplied input is returned
in an HTTP response without adequate output encoding, allowing an attacker to
execute arbitrary script in a victim's browser in the context of the vulnerable
site. Exploitation typically requires luring the victim to a crafted link.

## Business Impact
Reflected XSS can be used to hijack sessions, perform actions as the victim,
steal data rendered in the page, or stage phishing within a trusted origin,
undermining user trust and potentially exposing authenticated functionality.

## Remediation
- Apply contextual output encoding (HTML, attribute, JavaScript, URL) at the
  point where data is written into the response.
- Deploy a strict Content-Security-Policy that disallows inline script and
  restricts script sources.
- Validate input server-side and reject unexpected content types.
- Set the HttpOnly and Secure flags on session cookies to limit theft impact.

## References
CWE-79, OWASP A03:2021 Injection, OWASP WSTG-INPV-01.
