# Default / Weak Credentials — Remediation Guidance

## Description
A service or administrative interface accepts default, shipped, or otherwise
trivially guessable credentials. This gives an attacker direct authenticated
access without exploiting any software flaw, and is frequently the first foothold
in a broader compromise.

## Business Impact
Default credentials on an administrative interface typically grant full control
of the affected component, enabling configuration changes, data access, and
lateral movement. The likelihood of exploitation is high because such credentials
are publicly documented and routinely scanned for.

## Remediation
- Change all default credentials before deployment; enforce this in build and
  provisioning automation.
- Enforce a strong password policy and, where supported, multi-factor
  authentication for administrative access.
- Restrict management interfaces to trusted networks or a bastion host.
- Inventory devices and services for shipped default accounts and disable any
  that are unused.

## References
CWE-1392, OWASP A07:2021 Identification and Authentication Failures.
