## PackageProtector (aka DataProtector)

This repository provides safe and secure data protection at rest specification for untrusted remote storage.

[![master](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/workflows/master/badge.svg)](https://github.com/neliva/Neliva.Security.Cryptography.PackageProtector/actions?query=workflow%3Amaster)
[![Nuget](https://img.shields.io/nuget/v/Neliva.Security.Cryptography.PackageProtector?style=plastic)](https://www.nuget.org/packages/Neliva.Security.Cryptography.PackageProtector)

## Overview

DataProtector combines SP800-108 KDF (CTR), HMAC-SHA256, and CBC-AES256 to form authenticated encryption. Data stream is split into chunks and each chunk is signed and encrypted individually.
