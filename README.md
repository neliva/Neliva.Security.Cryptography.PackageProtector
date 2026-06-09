## PackageProtector

This repository describes safe and secure data at rest protection for untrusted remote storage. The specification and the reference implementation are released into the public domain. See the [UNLICENSE](UNLICENSE.md) file.

[![main](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/actions/workflows/main.yml/badge.svg)](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/actions/workflows/main.yml)
[![dotnet 10.0](https://img.shields.io/badge/dotnet-10.0-green)](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)
[![NuGet (with prereleases)](https://img.shields.io/nuget/vpre/Neliva.Security.Cryptography.PackageProtector)](https://www.nuget.org/packages/Neliva.Security.Cryptography.PackageProtector)

## Overview

PackageProtector combines SP800-108 CTR KDF, HMAC-SHA512, and AES256-CBC algorithms to form a key-committing and message/context-committing authenticated encryption design. The data stream is split into equal-size chunks (except the last one), and each chunk is signed and encrypted separately. This scheme allows random reads and writes of an arbitrary-length stream with the guarantee that the returned data is authenticated. PackageProtector is designed for secure, long-term storage.

Protected streams have no headers, markers, or identifiers. This makes protected streams indistinguishable from random data. Without a key, it is impossible to determine whether the protected stream was produced by PackageProtector or to perform traffic analysis.

### Usage
```C#
// using Neliva.Security.Cryptography;

// Use the system protector (32-byte IV, 64 KiB package size)
var protector = PackageProtector.System;

var keyBytes = new byte[32];
RandomNumberGenerator.Fill(keyBytes);

using var key = new PackageKey(keyBytes);

// Protect
await protector.ProtectAsync(srcContentStream, destProtectedStream, key /*, associatedData */);

// Unprotect
await protector.UnprotectAsync(srcProtectedStream, destContentStream, key /*, associatedData */);
```

### Algorithms

Many authenticated encryption algorithms, such as AES-GCM or ChaCha20-Poly1305, perform very well on modern hardware. These algorithms have some shortcomings:
* Reuse of key and nonce in stream ciphers is catastrophic.
* The authentication tag is only 16 bytes.
* No key commitment or message commitment.

Block ciphers have their own issues, such as padding oracle attacks. PackageProtector uses the PKCS7 padding scheme in *pad-then-mac-then-encrypt* mode to guard against padding oracle attacks. CBC mode provides additional safety for key/IV reuse and re-encryption of individual chunks (if required). Algorithm performance is not the primary goal of PackageProtector. The design intentionally uses separate algorithms and keys for MAC and encryption operations.

## Stream format

PackageProtector splits an arbitrary data stream into chunks. The chunk **content** is wrapped in a **package**. The package size is configurable and must be a multiple of 16 bytes. PackageProtector allows 0, 16, or 32-byte KDF IVs. The maximum content size per package depends on the KDF IV size.

For a 16-byte KDF IV, the package layout is the following:
```
|                             package, 64 bytes - 1GiB                              |
+-----------------------------------------------------------------------------------+
| KDF IV      | MAC(content || pad)    | chunk content            | PKCS7 pad       |
+-------------+------------------------+--------------------------+-----------------+
| 16 bytes    | 32 bytes               | 0 - (1GiB - 49 bytes)    | 1 - 16 bytes    |
+-------------+---------------------------------------------------------------------+
|             |                       encrypted (no padding)                        |
```
The KDF **IV** consists of cryptographically strong random bytes generated for every package. When a package is updated, new random bytes must be generated. The MAC placed before the chunk content also acts as a synthetic IV for CBC mode. When the KDF IV size is zero, the content is encrypted deterministically.

All packages, including the last one that may be incomplete, have the same format. *End of stream* is represented by an incomplete or empty package. An incomplete package has more than one padding byte. An empty package has zero-length *content*.

*Package size* is used to control the amount of data held in memory during protection and unprotection of a single package. The default recommended size is 64 KiB, but it can be changed based on application requirements.

## Stream keys

Given a **package key** for a data stream, PackageProtector uses KDF-HMAC-SHA512 in counter mode (SP800-108) to derive MAC and ENC keys for each package. This provides a level of key indirection. Recovered per-package keys cannot be used to recover other packages or the stream's package key.

The KDF uses the following **derived key context**:
* Key purpose (encrypt or sign)
* **Package number** (64-bit int, starts at 0 and increases sequentially)
* **Package size** (32-bit uint, same value for all stream packages)
* Maximum package padding size
* KDF IV (0/16/32 bytes, randomly generated for each package)
* Stream **associated data** (0 - 80 bytes, user-provided)

```
  32 - 64 bytes                        64 bytes
+----------------+     +-------+     +----------+     +--------------+     +-------+
| package key    |---->|       |---->| MAC key  |---->| HMAC-SHA512  |---->|       |
+----------------+     | ----- |     +----------+     +--------------+     |       |
                       |  KDF  |                                           | PKG N |
+----------------+     | ----- |     +----------+     +--------------+     |       |
| key context N  |---->|       |---->| ENC key  |---->| AES256-CBC   |---->|       |
+----------------+     +-------+     +----------+     +--------------+     +-------+
  102 bytes                            32 bytes
```

The KDF context is optimized to fit into a single HMAC-SHA512 block to reduce computational overhead. PackageProtector restricts the package key size to 32-64 bytes to provide adequate security. **The recommended key size is 64 bytes.**

Data streams can include optional *associated data* context (up to 80 bytes) that is used by the KDF. The same value must be provided when unprotecting the stream. There is no overhead for using *associated data*, but the combined size of the KDF IV and the associated data cannot be larger than 80 bytes.

## Stream security
Provided that the package key and *associated data* combination is unique for every data stream, PackageProtector guarantees detection of:
* Package reordering
* Stream truncation
* Extra data after *end of stream* marker
* Package substitution from a different stream

## Stream limits
Every package is protected independently by keys derived from the stream's package key and the package key context. PackageProtector uses *int64* for package numbers. Given the maximum 9223372036854775807 *package number*, the default 64 KiB *package size*, and a 16-byte KDF IV, the amount of data that can be protected is:
* *64 KiB - 49 bytes* of content per package
* *~511 ZiB* of content per package key and *associated data* combination
