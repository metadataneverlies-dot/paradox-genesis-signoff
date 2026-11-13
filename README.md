# PARADOX genesis sign-off (public bundle)

Two records, each signed 3-of-3 with ed25519 keys whose public halves are inside the record.
Private keys are NOT in this bundle and never leave the signers.

- `records/1-genesis-signoff.json` : sign-off citing Bitcoin block 0 (does not claim control of the genesis key).
- `records/2-pem-anchor.json`      : SHA-256 hashes of the two genesis public-key PEMs in this folder.
- `*.ots`                          : OpenTimestamps proofs (Bitcoin-anchored once upgraded; pending proofs still carry calendar commitments).

## Verify
    node verify.js records/*.json      # expect PASS 3-of-3 for each
    ots verify records/1-genesis-signoff.json.ots   # needs `opentimestamps-client`; checks the Bitcoin anchor

Note: link tx d86bdcbc...7476 is CITED only; ownership is not proven in these records.
Do not hand-edit the JSON: the signatures cover the canonical bytes, any change fails verification.
