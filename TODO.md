# TODO

Tasks known to be outstanding, roughly in priority order.

## Protocol support

- [ ] Add p11-kit RPC protocol v2 support: negotiate to `min(client, 2)`
      instead of clamping to 0, and recognize the v2-only call IDs. The v0
      variants of the two affected calls (C_InitToken, C_DeriveKey) are now
      implemented, which is the prerequisite for this.
      https://github.com/p11-glue/p11-kit/blob/master/p11-kit/rpc-server.c#L2566

- [ ] Implement C_InitToken2 (call 88), used once protocol v1+ is negotiated.
      Request is `uays` (space-padded 32-byte label). The codebase has
      `readZeroString` but no space-string (`s`) reader yet.

- [ ] Implement C_DeriveKey2 (call 89), used once protocol v2 is negotiated.
      Request is unchanged (`uMuaA`) but the response becomes `uPu` (error
      code, mechanism parameter update, key handle). The `P` mechanism
      parameter-update encoder doesn't exist yet on the write side.

## C_DeriveKey / ECDH

- [ ] Support the remaining CKM_ECDH1_DERIVE key derivation functions. The
      SHA-2 KDFs (CKD_SHA224/256/384/512_KDF, ANSI X9.63 construction) are
      implemented; the PKCS #11 3.0 header also bundles CKD_SHA1_KDF (0x02),
      CKD_SHA1_KDF_ASN1/CONCATENATE (X9.42), SHA3 (0x0a-0x0d), and NIST
      SP 800-56A single-step variants (CKD_*_KDF_SP800, 0x0e-0x14).
      https://github.com/p11-glue/p11-kit/blob/master/common/pkcs11.h#L609

- [ ] Exercise the CKA_VALUE_LEN resize path in `deriveECDH`. pkcs11-tool
      sets CKA_VALUE_LEN equal to the secret length, so the truncation/pad
      path (`resizeSecret`) isn't covered by the current tests.

## Test infrastructure

- [ ] Commit the `modules/nix-cache` WIP in ~/src/fleet. The flake can't
      evaluate while that directory is untracked, which blocks comin from
      deploying `p11-kit.out` (added to aluminium in 67f26ca) and the e2e
      tests from resolving the client at
      `/run/current-system/sw/lib/pkcs11/p11-kit-client.so` on NixOS.

- [ ] Bump the CI workflow (.github/workflows/test.yaml): it pins Go
      1.17.x/1.18.x, `setup-go@v2`, and `staticcheck@2022.1.1`.

- [ ] p11kit/errors_generate.go is flagged by gofmt (pre-existing; it's a
      generated file).

## Code structure

- [ ] `Slot.mechanisms()` and `Slot.mechanismInfo` are hardcoded; make them
      configurable now that the list grew with CKM_ECDH1_DERIVE.
