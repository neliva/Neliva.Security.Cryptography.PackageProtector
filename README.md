## PackageProtector (aka DataProtector)

This repository describes safe and secure data at rest protection for untrusted remote storage. The specification and reference implementation is released into the public domain. See the [UNLISENCE](UNLICENSE.md) file.

[![master](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/workflows/master/badge.svg)](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/actions?query=workflow%3Amaster)
[![Nuget](https://img.shields.io/nuget/v/Neliva.Security.Cryptography.PackageProtector?style=plastic)](https://www.nuget.org/packages/Neliva.Security.Cryptography.PackageProtector)

## Overview

PackageProtector combines SP800-108 KDF (CTR), HMAC-SHA256 and CBC-AES256 to form authenticated encryption. Data stream is split into equal size chunks (except the last one) and each chunk is signed and encrypted separately. This scheme allows random read/write of an arbitrary length stream with the guarantee that the returned data is authenticated.

Protected streams have no headers, markers or identifiers. This makes protected streams indistinguishable from true randomness. Without a key, it is impossible to determine if the protected stream was produced by PackageProtector or do traffic analysis.

## Underlying algorithms

There are many authenticated encryption algorithms such as AES-CCM, AES-GCM, or ChaCha20-Poly1305 that perform very well on modern hardware. There are shortcomings with such algorithms:
* Reuse of key and nounce in stream ciphers is catastrophic.
* The authentication tag is only 16 bytes.

Block ciphers have their own issues such as padding oracle attacks. PackageProtector uses PKCS7 padding scheme in *pad-then-mac-then-encrypt* mode to guard against padding oracle attacks. CBC mode provides a bit more safety in key/IV reuse and re-encryption of individual chunks (if required). Algorithms performance is not the primary goal of DataProtector. It was deemed nessesary to have separate algorithms and keys for MAC and ENCRYPT operations.

## Stream format

PackageProtector splits an arbitrary data stream into chunks. The chunk **content** is wrapped in a **package**. Package size is configurable and must be a multiple of 16 bytes. The minimum package **overhead** is 49 bytes.

```
|                   package, 64 bytes - (16MiB - 16 bytes)                           |
+------------------------------------------------------------------------------------+
| iv/salt     | chunk content             | PKCS7 pad       | MAC (content | pad)    |
+-------------+---------------------------+-----------------+------------------------+
| 16 bytes    | 0 - (16MiB - 65 bytes)    | 1 - 16 bytes    | 32 bytes               |
+-------------+----------------------------------------------------------------------+
              |                       encrypted (no padding)                         |
```
Package **iv/salt** is cryptographically strong random bytes generated for every package. When package is updated, new random bytes must be generated. Notice that the padding comes before the MAC. This *pad-then-mac-then-encrypt* format forces the decryption operation to verify MAC before padding, eliminating padding oracle attacks.

## Keys derivation

Given a data stream key (master key), for each package a KDF-HMAC-SHA256 in counter mode as described in SP800-108 is used to derive encryption and MAC keys. This provides a level of key indirection and recovered individual package keys cannot be used to recover other packages or the stream master key.

The KDF takes into account the following **derived key context**:
* Key purpose (encrypt or MAC)
* Package number (64 bit int)
* Package size (24 bit int)
* Package salt (16 bytes)
* Stream associated data (caller provided, 16 bytes)

The KDF context is optimized to fit into a single HMAC-SHA256 block to reduce computational overhead. The master key can be any length. However, the recommended key size is 64 bytes. PackageProtector restricts the key size to 32 - 64 bytes.
