## PackageProtector (aka DataProtector)

This repository provides safe and secure data at rest protection for untrusted remote storage. The specification and reference implementation is released into the public domain. See the [UNLISENCE](UNLICENSE.md) file.

[![master](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/workflows/master/badge.svg)](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/actions?query=workflow%3Amaster)
[![Nuget](https://img.shields.io/nuget/v/Neliva.Security.Cryptography.PackageProtector?style=plastic)](https://www.nuget.org/packages/Neliva.Security.Cryptography.PackageProtector)

## Overview

PackageProtector combines SP800-108 KDF (CTR), HMAC-SHA256 and CBC-AES256 to form authenticated encryption. Data stream is split into equal size chunks (except the last one) and each chunk is signed and encrypted separately. This scheme allows random read/write of an arbitrary length stream with the guarantee that the returned data is authenticated.

Protected streams have no headers, markers, or identifiers. This makes protected streams indistinguishable from true randomness. Without a key, it is impossible to determine if the protected stream was produced by PackageProtector or do traffic analysis.

## Underlying algorithms

There are many authenticated encryption algorithms such as AES-CCM, AES-GCM, or ChaCha20-Poly1305 that perform very well on modern hardware. There are shortcomings with such algorithms:
* Reuse of key and nounce in stream ciphers is catastrophic.
* The authentication tag is only 16 bytes.

Block ciphers have their own issues such as padding oracle attacks. CBC mode provides a bit more safety in key/IV reuse and re-encryption of individual chunks (if required). Algorithms performance is not the primary goal of DataProtector. It was deemed nessesary to have separate algorithms and keys for MAC and ENCRYPT operations. PackageProtector uses PKCS7 padding scheme in *pad-then-mac-then-encrypt* mode to guard against padding oracle attacks.

## 
