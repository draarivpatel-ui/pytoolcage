# Security policy

`pytoolcage` is a security boundary for AI-agent tool calls. Reports about bypasses are especially important.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting a vulnerability

Report vulnerabilities privately through GitHub at <https://github.com/draarivpatel-ui/pytoolcage/security/advisories/new>. Private vulnerability reporting is enabled for this repository. Do not open a public issue with a working exploit, a real secret, personal data or a third party's private endpoint.

Include a minimal policy and input, the expected decision, the actual decision, the affected layer, Python version and operating system. Use synthetic values only.

## Disclosure timeline

We aim to acknowledge new reports within 72 hours, complete triage within 7 days, and release a fix or mitigation within 90 days when the report is valid. Reporters will be credited after disclosure unless they ask not to be credited.

## Scope notes

The library validates inputs and outputs. It cannot make an underlying dangerous tool safe. DNS resolution and network connection pinning are intentionally outside this version's runtime boundary.
