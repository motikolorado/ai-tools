# Security policy

## Reporting a vulnerability

Do not open a public issue for a security vulnerability. Contact the repository owner privately through GitHub security advisories or the email listed on the maintainer's GitHub profile.

Include the affected version, reproduction steps, impact, and any suggested mitigation.

## Security boundaries

`endpoint_audit` performs network requests and is protected against private-address SSRF, redirects to private addresses, HTTPS downgrade redirects, response-size abuse, and request timeouts. It is an availability/discovery check, not a penetration test.

`token_risk_scan` is a conservative address and bytecode snapshot. It is not a honeypot detector, audit, investment recommendation, or guarantee of token safety.
