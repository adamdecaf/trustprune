These files are throwaway minisign test keys and signatures. They exist
only so the in-tree verifier can be checked against fixtures produced by
the official minisign tool. Do not reuse the keys for any other purpose.
The secret keys are not included.

Generated with minisign 0.12:

    minisign -G -W -p test-key.pub -s test-key.key
    minisign -G -W -p other-key.pub -s other-key.key
    minisign -S -c "TEST KEY; do not reuse" \
      -t "TEST KEY; do not reuse. timestamp:1 file:allowlist.yaml" \
      -s test-key.key -m allowlist.yaml -x allowlist.yaml.minisig
    minisign -S -l -c "TEST KEY; do not reuse" \
      -t "TEST KEY; do not reuse. timestamp:1 file:allowlist.yaml legacy" \
      -s test-key.key -m allowlist.yaml -x allowlist.yaml.legacy.minisig

`allowlist.yaml.minisig` is a hashed (`ED`) signature.
`allowlist.yaml.legacy.minisig` is a legacy unhashed (`Ed`) signature.
`other-key.pub` is a second test public key, used to check a key-id mismatch.
