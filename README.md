# MimbleWimbleCoin wallet module

Altbase 0.1.9 runs the official MWC wallet 6.0.1 locally. It restores the Altbase BIP39 phrase through encrypted Owner API v3 and keeps keys, outputs, scan state, and signing on the user's computer. Public node reads use `https://api.altbase.io/api/v1/mwc/daemon/v2/foreign`; the backend never receives wallet recovery data.

The first restoration performs a complete recovery scan from height 1. Subsequent launches reuse the encrypted wallet and completed scan marker. An unfinished scan, stale summary, or network error is displayed as unverified/unavailable, never as a verified zero balance. MWC uses nine decimal places.

Transfers use mainnet MQS addresses. **Both wallets must be online for interactive MQS negotiation.** The official `mqs.mwc.mw` relay transports encrypted slate messages. Slatepack/file and Tor transfer flows are not exposed. Fee planning uses `estimate_only`; a transfer is finalized with `post_tx:false`, checked against the reviewed amount and fee, and posted only after explicit wallet confirmation. There is no automatic retry after an uncertain broadcast.

Windows uses the source-owned `native/private_console.c` helper because the reference wallet's password reader requires a console input handle. The helper creates a private ConPTY, receives the password on stdin, discards console output, and ends its child with a Job Object. This requires Windows 10 version 1809 or later.

Reference binaries and their Apache license are prepared by `scripts/prepare-coin-runtimes.cjs`. Profiles live under the application profile's `local-wallets/mwc` directory; do not delete them to recover from a temporary node outage.
