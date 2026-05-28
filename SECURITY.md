# Security Policy

Sift is security software. Please report suspected vulnerabilities privately.

## Reporting A Vulnerability

Email security reports to:

```text
security@3rdstarindustries.com
```

Include:

- Affected component or package.
- A clear reproduction path.
- Expected impact.
- Relevant logs, configs, or proof-of-concept code.
- Whether the issue is already public.

Please do not include secrets, customer data, or private keys in the report.

## Response Expectations

This is an early-stage open-source project. We aim to acknowledge valid reports within 5 business days and will coordinate fixes and disclosure timing case by case.

## Supported Versions

Until the first stable release, security fixes target the main branch and the latest published package or container image.

## Security Boundaries

Sift is designed to enforce policy at the MCP tool boundary. It does not replace:

- Endpoint detection and response.
- Identity provider controls.
- Secrets management.
- Network segmentation.
- Sandboxing for untrusted code execution.
- Human review for high-impact operational changes.

Use Sift as one layer in a broader security program.
