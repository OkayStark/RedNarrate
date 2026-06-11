# SQL Injection — Remediation Guidance

## Description
SQL injection (SQLi) occurs when untrusted input is concatenated into a database
query, allowing an attacker to alter the query's logic. Depending on the backend
and the application's database privileges, impact ranges from authentication
bypass and unauthorized data disclosure to full read/write access and, in some
configurations, command execution on the database host.

## Business Impact
Successful SQL injection commonly leads to disclosure of customer records,
credentials, and other sensitive data, with consequent regulatory, contractual,
and reputational exposure. Where the database account is over-privileged, the
attacker may pivot to broader infrastructure compromise.

## Remediation
- Use parameterized queries (prepared statements) for every database call; never
  build queries by string concatenation with user input.
- Prefer a well-maintained ORM or query builder that parameterizes by default.
- Apply least privilege to the application's database account (no DDL, no access
  to unrelated schemas).
- Validate and canonicalize input server-side as defense in depth, but do not
  rely on it as the primary control.
- Disable verbose database error messages in production responses.

## References
CWE-89, OWASP A03:2021 Injection, OWASP WSTG-INPV-05.
