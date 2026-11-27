# Security policy

`pytoolcage` is a security boundary for AI-agent tool calls. Reports about bypasses are especially important.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |

## Reporting

Until the project is published, open a private security report through the repository owner's preferred private channel listed on the public repository profile after launch. Do not open a public issue with a working exploit, a real secret, personal data or a third party's private endpoint.

Include a minimal policy and input, the expected decision, the actual decision, the affected layer, Python version and operating system. Use synthetic values only.

## Scope notes

The library validates inputs and outputs. It cannot make an underlying dangerous tool safe. DNS resolution and network connection pinning are intentionally outside this version's runtime boundary.
