# @clockchain/handshake-sdk

Offline SDK helpers for the standalone Clockchain agent handshake.

This package consumes `@clockchain/handshake-protocol/v3` as the protocol source of truth. It exposes contract and tool discovery metadata, strict tool input/result validation, typed signing request preparation, and certificate/continuation verification wrappers.

Verification authority stays with the caller. SDK verification APIs only delegate to caller-supplied trust, revocation, and replay callbacks. The SDK does not sign, does not hold keys, has no network behavior, has no persistence, and does not perform business actions.

CLI envelope helpers clone plain JSON data before freezing it and reject symbols, cycles, accessors, proxies, descriptor traps, and non-plain objects with `SCHEMA_INVALID`. They validate only the SDK-owned CLI wrapper envelope; protocol-domain validation remains in `@clockchain/handshake-protocol/v3`.

Use the returned signing bytes and digest with an external signer you control. Treat verification results as valid only to the extent that the callbacks you supplied actually verify Clockchain trust, revocation status, and replay safety.
