## PackageProtector (aka DataProtector)

This repository describes safe and secure data at rest protection for untrusted remote storage. The specification and reference implementation are released into the public domain. See the [UNLICENSE](UNLICENSE.md) file.

[![master](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/workflows/master/badge.svg)](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/actions?query=workflow%3Amaster)
[![netstandard 2.1](https://img.shields.io/badge/netstandard-2.1-green)](https://docs.microsoft.com/en-us/dotnet/standard/net-standard)
[![Nuget (with prereleases)](https://img.shields.io/nuget/vpre/Neliva.Security.Cryptography.PackageProtector)](https://www.nuget.org/packages/Neliva.Security.Cryptography.PackageProtector)

## Overview

PackageProtector combines SP800-108 KDF (CTR), HMAC-SHA256 and AES256-CBC to form authenticated encryption. The data stream is split into equal size chunks (except the last one) and each chunk is signed and encrypted separately. This scheme allows random read/write of an arbitrary length stream with the guarantee that the returned data is authenticated. PackageProtector is designed for secure, long term storage.

Protected streams have no headers, markers or identifiers. This makes protected streams indistinguishable from true randomness. Without a key, it is impossible to determine if the protected stream was produced by PackageProtector or do traffic analysis.

### Usage
```C#
// using Neliva.Security.Cryptography;

var key = new byte[32];
RandomNumberGenerator.Fill(key);

// Use default values for package size and associated data
await srcContentStream.ProtectAsync(destProtectedStream, key);
```

### Algorithms

There are many authenticated encryption algorithms such as AES-GCM or ChaCha20-Poly1305 that perform very well on modern hardware. There are shortcomings with such algorithms:
* Reuse of key and nonce in stream ciphers is catastrophic.
* The authentication tag is only 16 bytes.

Block ciphers have their own issues such as padding oracle attacks. PackageProtector uses PKCS7 padding scheme in *pad-then-mac-then-encrypt* mode to guard against padding oracle attacks. CBC mode provides a bit more safety in key/IV reuse and re-encryption of individual chunks (if required). Algorithms performance is not the primary goal of PackageProtector. It was deemed necessary to have separate algorithms and keys for MAC and ENCRYPT operations.

## Stream format

PackageProtector splits an arbitrary data stream into chunks. The chunk **content** is wrapped in a **package**. Package size is configurable and must be a multiple of 16 bytes. The minimum package **overhead is 49 bytes**.

```
|                   package, 64 bytes - (16MiB - 16 bytes)                            |
+-------------------------------------------------------------------------------------+
| KDF IV      | MAC (content || pad)    | chunk content             | PKCS7 pad       |
+-------------+-------------------------+---------------------------+-----------------+
| 16 bytes    | 32 bytes                | 0 - (16MiB - 65 bytes)    | 1 - 16 bytes    |
+-------------+-----------------------------------------------------------------------+
              |                       encrypted (no padding)                          |
```
The KDF **IV** is cryptographically strong random bytes generated for every package. When package is updated, new random bytes must be generated. The MAC placed before chunk content, in addition, acts as synthetic IV for CBC mode.

All packages, including the last one that may be incomplete, have the same format. *End of stream* is represented by an incomplete or empty package. An incomplete package has more than one padding byte. An empty package has zero length *content* and produces a 64 byte *package*.

*Package size* is used to control the amount of data held in memory during protection and unprotection of a single package. The default recommended size is 64 KiB but can be changed based on the application requirements.

## Stream keys

Given a data stream key (**master key**), for each package a KDF-HMAC-SHA256 in Counter Mode ([described in SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)) is used to derive MAC and ENC keys. This provides a level of key indirection. Recovered individual package keys cannot be used to recover other packages or the stream master key.

The KDF takes into account the following **derived key context**:
* Key purpose (encrypt or sign)
* **Package number** (64 bit int, starts from 0 and sequentially increases)
* **Package size** (24 bit uint, same value for all stream packages)
* KDF IV (16 bytes, randomly generated for each package)
* Stream **associated data** (0 - 16 bytes, user provided)

```
  32 - 64 bytes                        32 bytes
+----------------+     +-------+     +----------+     +--------------+     +-------+
| master key     |---->|       |---->| MAC key  |---->| HMAC-SHA256  |---->|       |
+----------------+     | ----- |     +----------+     +--------------+     |       |
                       |  KDF  |                                           | PKG N |
+----------------+     | ----- |     +----------+     +--------------+     |       |
| key context N  |---->|       |---->| ENC key  |---->| AES256-CBC   |---->|       |
+----------------+     +-------+     +----------+     +--------------+     +-------+
  55 bytes                             32 bytes
```

The KDF context is optimized to fit into a single HMAC-SHA256 block to reduce computational overhead. PackageProtector restricts the master key size to 32 - 64 bytes to provide adequate security. **The recommended key size is 64 bytes**. 

Data streams can have optional *associated data* context (up to 16 bytes) that is used by the KDF. The same value must be provided to unprotect the stream. There is no overhead in using *associated data*.

## Stream security
Provided that the stream key and *associated data* combination is unique for every data stream, PackageProtector guarantees to detect:
* Package reordering
* Stream truncation
* Extra data after *end of stream* marker
* Package substitution from a different stream

## Stream limits
Every package is protected independently by the keys derived from the data stream key and package key context. PackageProtector uses *int64* for package numbers. Given the max 9223372036854775807 *package number* and the default 64 KiB *package size*, the amount of data that can be protected is:
* *64 KiB - 49 bytes* of content per package
* *~511 ZiB* of content per stream key and *associated data* combination
