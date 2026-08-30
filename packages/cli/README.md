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

Stdin is bounded to 1 MiB and a 5 second idle/read timeout. Oversized, malformed, or non-terminating input fails closed with the stable `SCHEMA_INVALID` error envelope and no raw parser details.

Fixture verification commands do not establish Clockchain trust. They only exercise explicitly supplied local fixture callbacks, so they are useful for conformance tests and package wiring checks, not production trust decisions.

Fixture verification commands require a `fixtureTrustAdapter` data object with only these keys: `acceptedIssuerDigests`, `clockchainNetwork`, `trustRootId`, optional `revokedHandles`, and optional `replayedNonces`. Digest arrays contain `sha256:` digests, handle arrays contain bounded opaque handles, and all fields are plain JSON data with no accessors, proxies, or extra keys.

The CLI does not sign, does not hold keys, has no network behavior, has no persistence, and does not perform business actions.
