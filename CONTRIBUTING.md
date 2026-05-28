# Contributing To Sift

Thanks for helping improve Sift.

## Development Setup

Requires Node.js 22 or newer.

```bash
npm install
npm run typecheck
npm test
npm --prefix sift-server run typecheck
npm --prefix sift-server test
```

## Pull Request Guidelines

- Keep changes focused.
- Add tests for security-sensitive behavior.
- Do not commit real API keys, tokens, customer data, or private network details.
- Prefer existing policy, audit, and MCP abstractions over new framework code.
- Keep docs updated when changing config or operator-facing behavior.

## Code Style

This repo uses TypeScript, Node's native test runner, and explicit configuration files. Avoid large refactors unless they are needed for the feature or fix.

## Security Changes

For auth, policy enforcement, metadata scanning, audit, or session lifecycle changes:

- Add regression tests.
- Run the Sift Server test suite.
- Consider whether the lab or quickstart smoke tests should be extended.
- Describe the security impact clearly in the pull request.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
