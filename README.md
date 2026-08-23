# PKCS #11 modules in Go without cgo

[![Go Reference](https://pkg.go.dev/badge/github.com/google/go-p11-kit/p11kit.svg)](https://pkg.go.dev/github.com/google/go-p11-kit/p11kit)

This project implements [p11-kit RPC server protocol][p11-kit-rpc], allowing Go
programs to act as a PKCS #11 module without the need for cgo. Clients load the
p11-kit-client.so shared library, then communicate over RPC to the Go server.

```
       ------------------------
       | client (e.g. Chrome) |
       ------------------------
                 |
     (PKCS #11 - shared library)
                 ↓ 
        ---------------------
        | p11-kit-client.so |
        ---------------------
                 |
        (RPC over unix socket)
                 ↓ 
---------------------------------------
| github.com/google/go-p11-kit/p11kit |
---------------------------------------
```

[p11-kit-rpc]: https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html

## Key derivation

EC private keys can derive a shared secret via `C_DeriveKey` with
`CKM_ECDH1_DERIVE`, as long as their `CKA_DERIVE` attribute is set with
`Object.SetDerive`:

```
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so --derive --mechanism ECDH1-DERIVE --slot=0x1 --label=my-key --input-file=peer-public.der --output-file=shared-secret.bin
```

The `CKD_NULL` and SHA-2 (`CKD_SHA224_KDF`, `CKD_SHA256_KDF`,
`CKD_SHA384_KDF`, `CKD_SHA512_KDF`, using the ANSI X9.63 key derivation
function) derivation functions are supported.

## Token initialization

Slots are presented as already initialized unless `Slot.Initialized` is false.
An uninitialized token can be initialized by a client via `C_InitToken`, which
sets the token's label:

```
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so --init-token --slot=0x1 --label=my-token --so-pin=12345678
Token successfully initialized
```

## Key pair generation

RSA and EC key pairs can be generated on a token via `C_GenerateKeyPair`, with
a `CKA_LABEL` template attribute identifying the new keys:

```
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so --keypairgen --key-type EC:prime256v1 --slot=0x1 --label=my-key
Key pair generated:
Private Key Object; EC
  label:      my-key
  Usage:      sign, derive
Public Key Object; EC  EC_POINT 256 bits
  label:      my-key
  Usage:      verify, derive
```

`CKM_RSA_PKCS_KEY_PAIR_GEN` (with `CKA_MODULUS_BITS`) and
`CKM_EC_KEY_PAIR_GEN` (with `CKA_EC_PARAMS`) are supported, on all of the
P-224/P-256/P-384/P-521 named curves. Keys generated with `CKA_TOKEN` set are
stored on the slot's token, so later sessions can find them by label, for
example to sign:

```
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so --sign --slot=0x1 --label=my-key -m ECDSA --input-file=digest.bin --output-file=sig.bin
```

## Demo

The example directory contains a demo server that reads keys and certificates
from disk and serves them on a unix socket. To build and start the server, run
the following commands:

```
go build -o bin/example-p11-kit-server ./example/example-p11-kit-server
./bin/example-p11-kit-server --priv example/priv.pem --pub example/pub.pem --cert example/cert.pem
```

The server will print out an environment variable to set similar to:

```
export P11_KIT_SERVER_ADDRESS=unix:path=/tmp/1056705225/p11kit.sock
```

In another shell, export the environment variable, and use p11-kit-client.so
to query the example server:

```
$ export P11_KIT_SERVER_ADDRESS=unix:path=/tmp/1056705225/p11kit.sock
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so --list-slots
Available slots:
Slot 0 (0x1): example-slot
  token label        : example
  token manufacturer : go-p11-kit
  token model        : example-server
  token flags        : token initialized
  hardware version   : 0.1
  firmware version   : 0.1
  serial num         : 12345678
  pin min/max        : 0/0
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so --list-objects
Using slot 0 with a present token (0x1)
Certificate Object; type = X.509 cert
  subject:    DN: CN=test
Private Key Object; RSA
  Usage:      decrypt, sign
  Access:     none
Public Key Object; RSA 256 bits
  Usage:      encrypt, verify
  Access:     none
```
