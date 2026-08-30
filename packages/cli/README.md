# @clockchain/handshake-cli

Offline JSON CLI helpers for the standalone Clockchain agent handshake.

Commands:

- `help`
- `contract`
- `validate-tool-input <tool-name>`
- `validate-tool-result <tool-name>`
- `prepare-signing`
- `verify-result-fixture`
- `verify-certificate-fixture`

Commands except `help` and `contract` read one JSON object from stdin and write one JSON object to stdout. Successful outputs include `verificationMode: "explicit_fixture_only"`, `clockchainTrustVerified: false`, and `externalBusinessActionPerformed: false`.

Fixture verification commands do not establish Clockchain trust. They only exercise explicitly supplied local fixture callbacks, so they are useful for conformance tests and package wiring checks, not production trust decisions.

The CLI does not sign, does not hold keys, has no network behavior, has no persistence, and does not perform business actions.
