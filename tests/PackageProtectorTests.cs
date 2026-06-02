// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Xunit;
using Xunit.Sdk;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    public class PackageProtectorTests
    {
        private const int BlockSize = 16;
        private const int HashSize = 32;

        private const int MinPackageSize = BlockSize + BlockSize + HashSize;
        private const int MaxPackageSize = (16 * 1024 * 1024) - BlockSize;

        [Fact]
        public void ProtectOverlapFail()
        {
            using var protector = new PackageProtector(packageSize: 64);

            var buf = new byte[protector.MaxPackageSize * 2];

            var content = new ArraySegment<byte>(buf, 1, protector.MaxContentSize);

            var package = new ArraySegment<byte>(buf, protector.MaxContentSize, protector.MaxPackageSize);

            var key = new byte[32];

            var ex = Assert.Throws<InvalidOperationException>(() => protector.Protect(content, package, key, 0, null));
            Assert.Equal("The 'package' must not overlap in memory with the 'content'.", ex.Message);
        }

        [Fact]
        public void ProtectNoOverlapPass()
        {
            using var protector = new PackageProtector(packageSize: 64);

            var buf = new byte[protector.MaxPackageSize * 2];

            var content = new ArraySegment<byte>(buf, protector.MaxPackageSize, protector.MaxContentSize);

            var package = new ArraySegment<byte>(buf);

            var key = new byte[32];

            Assert.Equal(protector.MaxPackageSize, protector.Protect(content, package, key, 0, null));
        }

        [Fact]
        public void UnprotectOverlapFail()
        {
            using var protector = new PackageProtector(packageSize: 64);

            var buf = new byte[protector.MaxPackageSize * 2];

            var package = new ArraySegment<byte>(buf, protector.MaxContentSize, protector.MaxPackageSize);

            var content = new ArraySegment<byte>(buf, 1, protector.MaxPackageSize);

            var key = new byte[32];

            var ex = Assert.Throws<InvalidOperationException>(() => protector.Unprotect(package, content, key, 0, null));
            Assert.Equal("The 'content' must not overlap in memory with the 'package'.", ex.Message);
        }

        [Fact]
        public void UnprotectNoOverlapPass()
        {
            using var protector = new PackageProtector(packageSize: 64);

            var buf = new byte[protector.MaxPackageSize * 2];

            var package = new ArraySegment<byte>(buf, protector.MaxPackageSize, protector.MaxPackageSize);

            var content = new ArraySegment<byte>(buf);

            var key = new byte[32];

            protector.Protect(content.Slice(0, protector.MaxContentSize), package, key, 0, null);

            Assert.Equal(protector.MaxContentSize, protector.Unprotect(package, content, key, 0, null));
        }

        [Fact]
        public void PackageProtectorUseAfterDisposeFail()
        {
            using var protector = new PackageProtector(packageSize: 64);

            protector.Dispose();

            var content = new byte[protector.MaxContentSize];
            var package = new byte[protector.MaxPackageSize];

            var package2 = new byte[protector.MaxPackageSize];

            var key = new byte[32];

            var ex = Assert.Throws<ObjectDisposedException>(() => protector.Protect(content, package, key, 0, null));
            Assert.Equal(typeof(PackageProtector).FullName, ex.ObjectName);

            ex = Assert.Throws<ObjectDisposedException>(() => protector.Unprotect(package, package2, key, 0, null));
            Assert.Equal(typeof(PackageProtector).FullName, ex.ObjectName);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(15)]
        [InlineData(17)]
        [InlineData(31)]
        [InlineData(33)]
        [InlineData(48)]
        public void NewPackageProtectorInvalidIvSizeFail(int ivSize)
        {
            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new PackageProtector(ivSize: ivSize));

            Assert.Equal(nameof(ivSize), ex.ParamName);
            Assert.Equal("IV size must be 0, 16, or 32 bytes. (Parameter 'ivSize')", ex.Message);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void NewPackageProtectorValidIvSizePass(int ivSize)
        {
            using var p = new PackageProtector(ivSize: ivSize);
        }

        [Theory]
        // Zero IV
        [InlineData(0, 0)]
        [InlineData(0, 15)]
        [InlineData(0, 16)]
        [InlineData(0, 17)]
        [InlineData(0, 32)]
        [InlineData(0, 47)]
        [InlineData(0, 49)]
        [InlineData(0, 63)]
        [InlineData(0, 65)]
        [InlineData(0, 120)]
        [InlineData(0, MaxPackageSize + 1)]
        // 16 bytes IV
        [InlineData(16, 0)]
        [InlineData(16, 15)]
        [InlineData(16, 16)]
        [InlineData(16, 17)]
        [InlineData(16, 32)]
        [InlineData(16, 47)]
        [InlineData(16, 49)]
        [InlineData(16, 63)]
        [InlineData(16, 65)]
        [InlineData(16, 120)]
        [InlineData(16, MaxPackageSize + 1)]
        // 32 bytes IV
        [InlineData(32, 0)]
        [InlineData(32, 15)]
        [InlineData(32, 16)]
        [InlineData(32, 17)]
        [InlineData(32, 32)]
        [InlineData(32, 47)]
        [InlineData(32, 49)]
        [InlineData(32, 63)]
        [InlineData(32, 65)]
        [InlineData(32, 120)]
        [InlineData(32, MaxPackageSize + 1)]
        public void NewPackageProtectorInvalidPackageSizeFail(int ivSize, int packageSize)
        {
            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new PackageProtector(ivSize: ivSize, packageSize: packageSize));

            Assert.Equal(nameof(packageSize), ex.ParamName);
            Assert.Equal("Package size must be a multiple of 16 bytes, at least (ivSize + 48), and no greater than 16777200 bytes. (Parameter 'packageSize')", ex.Message);
        }

        [Theory]
        // Zero IV
        [InlineData(0, 48)]
        [InlineData(0, 64)]
        [InlineData(0, 64 * 1024)]
        [InlineData(0, MaxPackageSize - BlockSize)]
        // 16 bytes IV
        [InlineData(16, 64)]
        [InlineData(16, 80)]
        [InlineData(16, 64 * 1024)]
        [InlineData(16, MaxPackageSize - BlockSize)]
        // 32 bytes IV
        [InlineData(32, 80)]
        [InlineData(32, 96)]
        [InlineData(32, 64 * 1024)]
        [InlineData(32, MaxPackageSize - BlockSize)]
        public void NewPackageProtectorValidPackageSizePass(int ivSize, int packageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            int overhead = ivSize + HashSize + 1;

            int maxContentSize = packageSize - overhead;

            Assert.Equal(packageSize, p.MaxPackageSize);
            Assert.Equal(maxContentSize, p.MaxContentSize);

            Assert.Equal(overhead, p.MaxPackageSize - p.MaxContentSize);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(31)]
        [InlineData(65)]
        [InlineData(128)]
        public void ProtectInvalidKeySizeFail(int keySize)
        {
            using var p = new PackageProtector(packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[keySize], 0, null));
            Assert.Equal("key", ex.ParamName);
            Assert.Equal("Key length must be between 32 and 64 bytes. (Parameter 'key')", ex.Message);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(31)]
        [InlineData(65)]
        [InlineData(128)]
        public void UnprotectInvalidKeySizeFail(int keySize)
        {
            using var p = new PackageProtector(packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Unprotect(package, package, new byte[keySize], 0, null));
            Assert.Equal("key", ex.ParamName);
            Assert.Equal("Key length must be between 32 and 64 bytes. (Parameter 'key')", ex.Message);
        }

        [Fact]
        public void ProtectNullKeyFail()
        {
            using var p = new PackageProtector(packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Protect(content, package, null, 0, null));
            Assert.Equal("key", ex.ParamName);
        }

        [Fact]
        public void UnprotectNullKeyFail()
        {
            using var p = new PackageProtector(packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentNullException>(() => p.Unprotect(package, package, null, 0, null));
            Assert.Equal("key", ex.ParamName);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void ProtectRngActionCallbackPass(int ivSize)
        {
            byte[] rngVal = Array.Empty<byte>();

            RngFillAction rng = (Span<byte> data) =>
            {
                if (data.Length == 0 || rngVal.Length != 0)
                {
                    throw new XunitException("Callback is not operating properly.");
                }

                rngVal = new byte[data.Length].Fill((byte)data.Length);

                rngVal.AsSpan().CopyTo(data);
            };

            using var protector = new PackageProtector(ivSize: ivSize, packageSize: 128, rngFill: rng);

            var content = new byte[1].Fill(100);
            var package = new byte[protector.MaxPackageSize];

            protector.Protect(content, package, new byte[32].Fill(32), 0, null);

            Assert.Equal(ivSize, rngVal.Length);

            var pkgIV = new ArraySegment<byte>(package, 0, ivSize).ToArray();

            Assert.Equal(rngVal, pkgIV);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        public void ProtectClearOutputOnFailurePass(int ivSize)
        {
            const string exStr = "CRNG FAILED";
            byte[] rngVal = Array.Empty<byte>();

            RngFillAction rng = (Span<byte> data) =>
            {
                if (data.Length == 0 || rngVal.Length != 0)
                {
                    throw new XunitException("Callback is not operating properly.");
                }

                rngVal = new byte[data.Length].Fill((byte)data.Length);

                rngVal.AsSpan().CopyTo(data);

                throw new Exception(exStr);
            };

            using var protector = new PackageProtector(ivSize: ivSize, packageSize: 80, rngFill: rng);

            var content = new byte[1].Fill(100);
            var package = new byte[protector.MaxPackageSize];

            var ex = Assert.Throws<Exception>(() => protector.Protect(content, package, new byte[32].Fill(32), 0, null));
            Assert.Equal(exStr, ex.Message);

            Assert.Equal(ivSize, rngVal.Length);

            var pkgIV = new ArraySegment<byte>(package, 0, ivSize);

            Assert.True(pkgIV.IsAllZeros(), "Destination not cleared on Protect() failure.");

            Assert.NotEqual(rngVal, pkgIV.ToArray());
        }

        [Fact]
        public void ProtectInvalidPackageNumberFail()
        {
            using var p = new PackageProtector(packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[32], -1, null));
            Assert.Equal("packageNumber", ex.ParamName);
            Assert.Equal("Package number must not be negative. (Parameter 'packageNumber')", ex.Message);
        }

        [Fact]
        public void UnprotectInvalidPackageNumberFail()
        {
            using var p = new PackageProtector(packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Unprotect(package, package, new byte[32], -1, null));
            Assert.Equal("packageNumber", ex.ParamName);
            Assert.Equal("Package number must not be negative. (Parameter 'packageNumber')", ex.Message);
        }

        [Theory]
        [InlineData(0, 33)]
        [InlineData(16, 17)]
        [InlineData(32, 1)]
        public void ProtectInvalidAssociatedDataFail(int ivSize, int associatedDataSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[32], long.MaxValue, new byte[associatedDataSize]));
            Assert.Equal("associatedData", ex.ParamName);
            Assert.Equal("Associated data length is too large. (Parameter 'associatedData')", ex.Message);
        }

        [Theory]
        [InlineData(0, 33)]
        [InlineData(16, 17)]
        [InlineData(32, 1)]
        public void UnprotectInvalidAssociatedDataSizeFail(int ivSize, int associatedDataSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Unprotect(package, package, new byte[32], long.MaxValue, new byte[associatedDataSize]));
            Assert.Equal("associatedData", ex.ParamName);
            Assert.Equal("Associated data length is too large. (Parameter 'associatedData')", ex.Message);
        }

        [Theory]
        [InlineData(0, 48)]
        [InlineData(16, 64)]
        [InlineData(32, 80)]
        public void ProtectInvalidPackageSizeFail(int ivSize, int packageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize - 1];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[32], long.MaxValue, null));
            Assert.Equal("package", ex.ParamName);
            Assert.Equal("Insufficient space for package output. (Parameter 'package')", ex.Message);
        }

        [Theory]
        [InlineData(0, 48)]
        [InlineData(16, 64)]
        [InlineData(32, 80)]
        public void ProtectInvalidContentSizeFail(int ivSize, int packageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var content = new byte[p.MaxContentSize + 1];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[32], long.MaxValue, null));
            Assert.Equal("content", ex.ParamName);
            Assert.Equal("Content length is too large. (Parameter 'content')", ex.Message);
        }

        [Theory]
        [InlineData(0, 48)]
        [InlineData(16, 64)]
        [InlineData(32, 80)]
        public void UnprotectInvalidContentSizeFail(int ivSize, int packageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var package = new byte[p.MaxPackageSize];

            var content = new byte[p.MaxContentSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Unprotect(package, content, new byte[32], long.MaxValue, null));
            Assert.Equal("content", ex.ParamName);
            Assert.Equal("Insufficient space for content output. (Parameter 'content')", ex.Message);
        }

        [Theory]
        [InlineData(0, 48, 47)]
        [InlineData(0, 48, 49)]
        [InlineData(16, 64, 63)]
        [InlineData(16, 64, 65)]
        [InlineData(32, 80, 79)]
        [InlineData(32, 80, 81)]
        public void UnprotectInvalidPackageSizeFail(int ivSize, int packageSize, int invalidPackageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var package = new byte[invalidPackageSize];

            var content = new byte[p.MaxContentSize + 1];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Unprotect(package, content, new byte[32], 0, null));
            Assert.Equal("package", ex.ParamName);
            Assert.Equal("Package length is invalid or not aligned to the required boundary. (Parameter 'package')", ex.Message);
        }

        [Theory]
        [InlineData(0, 48 + 16, 48 + 16 - 1)]
        [InlineData(0, 48 + 16, 48 + 16 + 1)]
        [InlineData(16, 64 + 16, 64 + 16 - 1)]
        [InlineData(16, 64 + 16, 64 + 16 + 1)]
        [InlineData(32, 80 + 16, 80 + 16 - 1)]
        [InlineData(32, 80 + 16, 80 + 16 + 1)]
        public void UnprotectInvalidPackageSize2Fail(int ivSize, int packageSize, int invalidPackageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var package = new byte[invalidPackageSize];

            var content = new byte[p.MaxContentSize + 1];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Unprotect(package, content, new byte[32], 0, null));
            Assert.Equal("package", ex.ParamName);
            Assert.Equal("Package length is invalid or not aligned to the required boundary. (Parameter 'package')", ex.Message);
        }

        [Fact]
        public void ProtectNullOrDefaultContentPass()
        {
            using var p = new PackageProtector(packageSize: 128);

            p.Protect(null, new byte[128], new byte[32], 0, new byte[1]);
            p.Protect(default, new byte[128], new byte[32], 0, new byte[1]);
            p.Protect(ArraySegment<byte>.Empty, new byte[128], new byte[32], 0, new byte[1]);
        }

        [Fact]
        public void ProtectNullOrDefaultAssociatedDataPass()
        {
            using var p = new PackageProtector(packageSize: 128);

            p.Protect(new byte[1], new byte[128], new byte[32], 0, null);
            p.Protect(new byte[1], new byte[128], new byte[33], 0, default);
            p.Protect(new byte[1], new byte[128], new byte[64], 0, ArraySegment<byte>.Empty);
        }

        [Fact]
        public void UnprotectNullOrDefaultAssociatedDataPass()
        {
            using var protector = new PackageProtector(packageSize: 64);

            var p = new byte[64];
            var c = new byte[64];
            protector.Protect(default, p, new byte[32], 0, default);

            protector.Unprotect(p, c, new byte[32], 0, null);
            protector.Unprotect(p, c, new byte[32], 0, default);
            protector.Unprotect(p, c, new byte[32], 0, ArraySegment<byte>.Empty);
        }

        [Theory]
        [InlineData(0, 48, 0)]
        [InlineData(0, 48 + BlockSize, 0)]
        [InlineData(0, MaxPackageSize, 0)]
        [InlineData(0, 48, 16)]
        [InlineData(0, 48 + BlockSize, 16)]
        [InlineData(0, MaxPackageSize, 16)]
        [InlineData(0, 48, 32)]
        [InlineData(0, 48 + BlockSize, 32)]
        [InlineData(0, MaxPackageSize, 32)]
        //
        [InlineData(16, 64, 0)]
        [InlineData(16, 64 + BlockSize, 0)]
        [InlineData(16, MaxPackageSize, 0)]
        [InlineData(16, 64, 16)]
        [InlineData(16, 64 + BlockSize, 16)]
        [InlineData(16, MaxPackageSize, 16)]
        //
        [InlineData(32, 80, 0)]
        [InlineData(32, 80 + BlockSize, 0)]
        [InlineData(32, MaxPackageSize, 0)]
        public void RoundTripFullPackagePass(int ivSize, int packageSize, int associatedDataSize)
        {
            var key = new byte[64].Fill(4);
            var associatedData = new byte[associatedDataSize].Fill((byte)associatedDataSize);

            using (var protector = new PackageProtector(ivSize, packageSize))
            {
                var content = new ArraySegment<byte>(new byte[protector.MaxContentSize].Fill(7));

                var package = new ArraySegment<byte>(new byte[packageSize]);

                var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

                Assert.Equal(packageSize, bytesProtected);

                var unprotectedContent = new ArraySegment<byte>(new byte[packageSize]);

                var bytesUnprotected = protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData);

                Assert.Equal(content.Count, bytesUnprotected);

                Assert.Equal(content.Array, unprotectedContent.Slice(0, bytesUnprotected).ToArray());
            }
        }

        [Fact]
        public void RoundTripEmptyPackagePass()
        {
            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(4);

            foreach (var packageSize in new int[] { MinPackageSize, MinPackageSize + BlockSize, MaxPackageSize })
            {
                using (var protector = new PackageProtector(packageSize: packageSize))
                {
                    var content = ArraySegment<byte>.Empty;

                    var package = new ArraySegment<byte>(new byte[MinPackageSize]);

                    var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

                    Assert.Equal(MinPackageSize, bytesProtected);

                    var unprotectedContent = new ArraySegment<byte>(new byte[packageSize]);

                    var bytesUnprotected = protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData);

                    Assert.Equal(content.Count, bytesUnprotected);

                    Assert.Equal(content.Array, unprotectedContent.Slice(0, bytesUnprotected).ToArray());
                }
            }
        }

        [Fact]
        public void RoundTripVariousContentSizePass()
        {
            var key = new byte[32].Fill(4);
            var associatedData = new byte[1].Fill(4);

            const int PackageSize = MinPackageSize + BlockSize;

            byte[] contentBuffer = new byte[PackageSize].Fill(33);
            byte[] packageBuffer = new byte[PackageSize];
            byte[] unprotectedContentBuffer = new byte[PackageSize];

            using var protector = new PackageProtector(packageSize: PackageSize);

            for (int contentSize = protector.MaxContentSize; contentSize >= 0; contentSize--)
            {
                var content = new ArraySegment<byte>(contentBuffer, 0, contentSize);
                var package = new ArraySegment<byte>(packageBuffer);

                var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

                var unprotectedContent = new ArraySegment<byte>(unprotectedContentBuffer);

                var bytesUnprotected = protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData);

                Assert.Equal(content.Count, bytesUnprotected);

                Assert.Equal(content.Slice(0, contentSize).ToArray(), unprotectedContent.Slice(0, bytesUnprotected).ToArray());

                Array.Clear(packageBuffer, 0, packageBuffer.Length);
                Array.Clear(unprotectedContentBuffer, 0, unprotectedContentBuffer.Length);
            }
        }

        [Fact]
        public void DeriveKeysProduceDifferentKeysPass()
        {
            var masterKey = new byte[32].Fill(31);
            var kdfIV = new byte[16].Fill(91);
            var associatedData = new byte[16].Fill(201);

            var encKey = new byte[32];
            var sigKey = new byte[32];

            using (var hmac = new HMACSHA256(masterKey))
            {
                PackageProtector.DeriveKeys(hmac, 42, 4096, kdfIV, associatedData, encKey, sigKey);
            }

            Assert.NotEqual(masterKey, sigKey);
            Assert.NotEqual(masterKey, encKey);

            Assert.NotEqual(encKey, sigKey);
        }

        [Fact]
        public void DeriveKeysAllowVariableIVSizePass()
        {
            var masterKey = new byte[32].Fill(31);

            var iv1 = (Span<byte>)new byte[32];
            var iv2 = (Span<byte>)new byte[iv1.Length];

            for (int i = 0; i < iv1.Length; i++)
            {
                iv1[i] = (byte)(i + 1);
                iv2[i] = (byte)(i + 101);
            }

            var encKey = new byte[32];
            var sigKey = new byte[32];

            using (var hmac = new HMACSHA256(masterKey))
            {
                for (int i = 0; i < iv1.Length; i++)
                {
                    var s1 = iv1.Slice(0, i);
                    var s2 = iv2.Slice(i);

                    PackageProtector.DeriveKeys(hmac, 42, 4096, s1, s2, encKey, sigKey);

                    Assert.NotEqual(masterKey, sigKey);
                    Assert.NotEqual(masterKey, encKey);

                    Assert.NotEqual(encKey, sigKey);
                }
            }
        }

        [Fact]
        public void DeriveKeysBadIVSizeFail()
        {
            var masterKey = new byte[32].Fill(31);

            var encKey = new byte[32];
            var sigKey = new byte[32];

            using (var hmac = new HMACSHA256(masterKey))
            {
                Assert.Throws<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[33], new byte[0], encKey, sigKey));
                Assert.Throws<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[0], new byte[33], encKey, sigKey));

                Assert.Throws<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[32], new byte[1], encKey, sigKey));
                Assert.Throws<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[1], new byte[32], encKey, sigKey));

                Assert.Throws<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[17], new byte[16], encKey, sigKey));
                Assert.Throws<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[16], new byte[17], encKey, sigKey));
            }
        }

        [Fact]
        public void DeriveKeysValidKeyContextPass()
        {
            var masterKey = new byte[32].Fill(31);
            var kdfIV = new byte[16].Fill(91);
            var associatedData = new byte[16].Fill(201);

            var encKey = new byte[32];
            var sigKey = new byte[32];

            var argsList = new List<Tuple<long, int, byte[]>> {
                new Tuple<long, int, byte[]>(0, MinPackageSize, associatedData),
                new Tuple<long, int, byte[]>(long.MaxValue, MinPackageSize, associatedData),
                new Tuple<long, int, byte[]>(0, MaxPackageSize, associatedData),
                new Tuple<long, int, byte[]>(long.MaxValue, MaxPackageSize, associatedData),
                new Tuple<long, int, byte[]>(long.MaxValue, MaxPackageSize, Array.Empty<byte>()),
                new Tuple<long, int, byte[]>(0, MinPackageSize, Array.Empty<byte>()),
            };

            foreach (var a in argsList)
            {
                using (var hmac = new HMACSHA256(masterKey))
                {
                    PackageProtector.DeriveKeys(hmac, a.Item1, a.Item2, kdfIV, a.Item3, encKey, sigKey);
                }

                var expectedEncKey = DeriveKey32(masterKey, true, a.Item1, a.Item2, kdfIV, a.Item3);
                var expectedSigKey = DeriveKey32(masterKey, false, a.Item1, a.Item2, kdfIV, a.Item3);

                Assert.Equal(expectedEncKey, encKey);
                Assert.Equal(expectedSigKey, sigKey);
            }
        }

        [Fact]
        public void UnprotectWrongKeyFail()
        {
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize - 8].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            key[31] ^= 1;

            Assert.Throws<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        [Fact]
        public void UnprotectWrongPackageNumberFail()
        {
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize - 7].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            Assert.Throws<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 6, associatedData));

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        [Fact]
        public void UnprotectWrongPackageSizeFail()
        {
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize - 5].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            using var protector1 = new PackageProtector(packageSize: MinPackageSize + BlockSize);

            Assert.Throws<BadPackageException>(() => protector1.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        [Fact]
        public void UnprotectWrongAssociatedDataFail()
        {
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(4);

            var associatedData = new ArraySegment<byte>(new byte[13].Fill(7));

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize - 3].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            Assert.Throws<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData.Slice(1)));

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");

            associatedData[0] ^= 1;
            Assert.Throws<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        [Fact]
        public void UnprotectCorruptedPackageFail()
        {
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            foreach (var i in new int[] { 0, 15, 16, 31, 32, 47, 48, 63 })
            {
                package[i] ^= 1;

                Assert.Throws<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));

                Assert.True(unprotectedContent.IsAllZeros(), $"Destination not cleared on Unprotect() failure for byte index '{i}'.");

                package[i] ^= 1;
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void UnprotectTamperEveryByteAndBitMultiBlockFail(int ivSize)
        {
            // Exhaustive tamper detection: flipping any single bit at any byte
            // position of a multi block package must be rejected and must clear the
            // output. Covers the IV region, the MAC region, and the encrypted body.
            const int PackageSize = 128; // Multiple AES blocks beyond the minimum.

            using var protector = new PackageProtector(ivSize: ivSize, packageSize: PackageSize);

            var key = new byte[32].Fill(4);

            // MaxAssociatedDataSize == 32 - ivSize, so use a size valid for all ivSizes.
            var associatedData = new byte[32 - ivSize].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize].Fill(9));

            var package = new ArraySegment<byte>(new byte[PackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[PackageSize]);

            for (int i = 0; i < bytesProtected; i++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    package[i] ^= (byte)(1 << bit);

                    Assert.Throws<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));

                    Assert.True(unprotectedContent.IsAllZeros(), $"Destination not cleared on Unprotect() failure for byte index '{i}', bit '{bit}'.");

                    package[i] ^= (byte)(1 << bit);
                }
            }
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        public void UnprotectTamperedIvFail(int ivSize)
        {
            // The KDF binds the derived keys to the IV bytes. Flipping any bit of
            // any IV byte must cause a MAC failure and clear the output.
            const int PackageSize = 128;

            using var protector = new PackageProtector(ivSize: ivSize, packageSize: PackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[32 - ivSize].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize].Fill(9));

            var package = new ArraySegment<byte>(new byte[PackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[PackageSize]);

            for (int i = 0; i < ivSize; i++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    package[i] ^= (byte)(1 << bit);

                    Assert.Throws<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));

                    Assert.True(unprotectedContent.IsAllZeros(), $"Destination not cleared on Unprotect() failure for IV byte index '{i}', bit '{bit}'.");

                    package[i] ^= (byte)(1 << bit);
                }
            }
        }

        [Theory]
        [InlineData(0L)]
        [InlineData(1L)]
        [InlineData(long.MaxValue)]
        [InlineData(long.MaxValue - 1L)]
        [InlineData(0x0102030405060708L)]
        public void RoundTripPackageNumberBoundaryPass(long packageNumber)
        {
            // The package number is serialized as 8 big endian bytes into the KDF
            // input. Round-tripping boundary and high values confirms the full range
            // survives protection and unprotection.
            const int PackageSize = 128;

            using var protector = new PackageProtector(ivSize: 16, packageSize: PackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[16].Fill(7);

            var content = new byte[protector.MaxContentSize - 5].Fill(9);

            var package = new byte[PackageSize];

            var bytesProtected = protector.Protect(content, package, key, packageNumber, associatedData);

            var unprotectedContent = new byte[PackageSize];

            var bytesUnprotected = protector.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), unprotectedContent, key, packageNumber, associatedData);

            Assert.Equal(content.Length, bytesUnprotected);
            Assert.Equal(content, new ArraySegment<byte>(unprotectedContent, 0, bytesUnprotected).ToArray());
        }

        [Theory]
        [InlineData(0L, 1L)]
        [InlineData(1L, 0L)]
        [InlineData(0L, long.MaxValue)]
        [InlineData(long.MaxValue, 0L)]
        public void UnprotectWrongPackageNumberBoundaryFail(long protectNumber, long unprotectNumber)
        {
            // A package produced with one package number must not be decryptable with
            // a different package number, including boundary values.
            const int PackageSize = 128;

            using var protector = new PackageProtector(ivSize: 16, packageSize: PackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[16].Fill(7);

            var content = new byte[protector.MaxContentSize].Fill(9);

            var package = new byte[PackageSize];

            var bytesProtected = protector.Protect(content, package, key, protectNumber, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[PackageSize]);

            Assert.Throws<BadPackageException>(() => protector.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), unprotectedContent, key, unprotectNumber, associatedData));

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        [Fact]
        public void UnprotectGoodMacBadPadFail()
        {
            byte[] ZeroIV = new byte[BlockSize];

            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(93);
            var associatedData = new byte[13].Fill(56);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize].Fill(231));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            protector.Protect(content, package, key, 5, associatedData);

            var encKey = DeriveKey32(key, true, 5, MinPackageSize, package.Slice(0, BlockSize), associatedData);
            var sigKey = DeriveKey32(key, false, 5, MinPackageSize, package.Slice(0, BlockSize), associatedData);

            using (var aes = Aes.Create())
            {
                aes.Padding = PaddingMode.None;
                aes.Mode = CipherMode.CBC;

                using (var dec = aes.CreateDecryptor(encKey, ZeroIV))
                {
                    dec.TransformBlock(package.Array, BlockSize, MinPackageSize - BlockSize, package.Array, BlockSize);
                }

                Assert.Equal(content.Array, package.Slice(BlockSize + HashSize, content.Count).ToArray());

                using (var hmac = new HMACSHA256(sigKey))
                {
                    var hash = hmac.ComputeHash(package.Array, BlockSize + HashSize, MinPackageSize - BlockSize - HashSize);

                    Assert.Equal(hash, package.Slice(BlockSize, HashSize).ToArray());

                    package[MinPackageSize - 1] = 2;

                    if (!hmac.TryComputeHash(package.Slice(BlockSize + HashSize, MinPackageSize - BlockSize - HashSize), package.Slice(BlockSize, HashSize), out _))
                    {
                        throw new CryptographicUnexpectedOperationException();
                    }
                }

                using (var enc = aes.CreateEncryptor(encKey, ZeroIV))
                {
                    enc.TransformBlock(package.Array, BlockSize, MinPackageSize - BlockSize, package.Array, BlockSize);
                }
            }

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            Assert.Throws<BadPackageException>(() => protector.Unprotect(package, unprotectedContent, key, 5, associatedData));

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        private static byte[] DeriveKey32(byte[] masterKey, bool encrypt, long packageNumber, int packageSize, ReadOnlySpan<byte> kdfIV, ReadOnlySpan<byte> associatedData)
        {
            byte purpose = encrypt ? (byte)0xff : (byte)0x00;

            Span<byte> label = stackalloc byte[3] { purpose, (byte)kdfIV.Length, (byte)associatedData.Length };

            Span<byte> context = stackalloc byte[sizeof(ulong) + 16 + 16 + 3];
            context.Clear();

            using (var hmac = new HMACSHA256(masterKey))
            {
                var derivedKey = new byte[hmac.HashSize / 8];

                BinaryPrimitives.WriteUInt64BigEndian(context.Slice(0, sizeof(ulong)), (ulong)packageNumber);

                kdfIV.CopyTo(context.Slice(sizeof(ulong), kdfIV.Length));

                associatedData.CopyTo(context.Slice(sizeof(ulong) + kdfIV.Length, associatedData.Length));

                context[context.Length - 3] = (byte)(packageSize >> 16);
                context[context.Length - 2] = (byte)(packageSize >> 8);
                context[context.Length - 1] = (byte)packageSize;

                hmac.DeriveKey(derivedKey, label, context);

                return derivedKey;
            }
        }

        [Fact]
        public void DotNETArraySegmentAssumptionsPass()
        {
            Assert.Null(((ArraySegment<byte>)null).Array);
            Assert.Equal(0, ((ArraySegment<byte>)null).Count);
            Assert.Equal(0, ((ArraySegment<byte>)null).Offset);

            Assert.Null(default(ArraySegment<byte>).Array);
            Assert.Equal(0, default(ArraySegment<byte>).Count);
            Assert.Equal(0, default(ArraySegment<byte>).Offset);

            Assert.NotNull(ArraySegment<byte>.Empty.Array);
            Assert.Equal(0, ArraySegment<byte>.Empty.Count);
            Assert.Equal(0, ArraySegment<byte>.Empty.Offset);

            Assert.Empty(ArraySegment<byte>.Empty.Array);
        }

        [Fact]
        public void DoubleDisposeNoThrow()
        {
            var p = new PackageProtector(packageSize: 64);
            p.Dispose();
            p.Dispose();
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        public void ProtectRandomIvProducesDifferentCiphertextPass(int ivSize)
        {
            // Semantic security: same plaintext + key + packageNumber + associatedData
            // must yield distinct ciphertexts when a random IV is used.
            using var protector = new PackageProtector(ivSize: ivSize, packageSize: 128);

            var key = new byte[32].Fill(11);
            var content = new byte[protector.MaxContentSize].Fill(42);

            var pkg1 = new byte[protector.MaxPackageSize];
            var pkg2 = new byte[protector.MaxPackageSize];

            protector.Protect(content, pkg1, key, 7, null);
            protector.Protect(content, pkg2, key, 7, null);

            Assert.NotEqual(pkg1, pkg2);

            // Difference must include both the random IV prefix and the encrypted body.
            Assert.NotEqual(
                new ArraySegment<byte>(pkg1, 0, ivSize).ToArray(),
                new ArraySegment<byte>(pkg2, 0, ivSize).ToArray());

            Assert.NotEqual(
                new ArraySegment<byte>(pkg1, ivSize, pkg1.Length - ivSize).ToArray(),
                new ArraySegment<byte>(pkg2, ivSize, pkg2.Length - ivSize).ToArray());
        }

        [Fact]
        public void ProtectZeroIvProducesDeterministicCiphertextPass()
        {
            // With ivSize=0 the construction is deterministic by design.
            // Identical inputs must yield byte-identical output (no hidden randomness).
            using var protector = new PackageProtector(ivSize: 0, packageSize: 128);

            var key = new byte[32].Fill(11);
            var associatedData = new byte[16].Fill(33);
            var content = new byte[protector.MaxContentSize].Fill(42);

            var pkg1 = new byte[protector.MaxPackageSize];
            var pkg2 = new byte[protector.MaxPackageSize];

            protector.Protect(content, pkg1, key, 7, associatedData);
            protector.Protect(content, pkg2, key, 7, associatedData);

            Assert.Equal(pkg1, pkg2);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void RoundTripAcrossSeparateInstancesPass(int ivSize)
        {
            // Protector instances must carry no hidden per-instance state:
            // a package produced by one instance must be decryptable by another
            // instance constructed with the same parameters.
            var key = new byte[64].Fill(17);

            // MaxAssociatedDataSize == 32 - ivSize, so use a size valid for all ivSizes.
            var associatedData = ArraySegment<byte>.Empty;

            using var pA = new PackageProtector(ivSize: ivSize, packageSize: 256);
            using var pB = new PackageProtector(ivSize: ivSize, packageSize: 256);

            var content = new byte[pA.MaxContentSize - 13].Fill(99);

            var package = new byte[pA.MaxPackageSize];

            int bytesProtected = pA.Protect(content, package, key, 12345, associatedData);

            var output = new byte[pB.MaxPackageSize];

            int bytesUnprotected = pB.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), output, key, 12345, associatedData);

            Assert.Equal(content.Length, bytesUnprotected);
            Assert.Equal(content, new ArraySegment<byte>(output, 0, bytesUnprotected).ToArray());
        }

        [Theory]
        [InlineData(0, 16)]
        [InlineData(0, 32)]
        [InlineData(16, 0)]
        [InlineData(16, 32)]
        [InlineData(32, 0)]
        [InlineData(32, 16)]
        public void UnprotectWithMismatchedIvSizeFail(int protectIvSize, int unprotectIvSize)
        {
            // The KDF binds the encryption/signing keys to the configured ivSize
            // (its length is part of the derivation input). A package produced with
            // one ivSize must NOT be decryptable by a protector configured with a
            // different ivSize, even when the package length happens to be acceptable
            // to both.
            const int PackageSize = 128;

            var key = new byte[32].Fill(5);

            using var pProtect = new PackageProtector(ivSize: protectIvSize, packageSize: PackageSize);
            using var pUnprotect = new PackageProtector(ivSize: unprotectIvSize, packageSize: PackageSize);

            var content = new byte[pProtect.MaxContentSize].Fill(7);

            var package = new byte[PackageSize];

            int bytesProtected = pProtect.Protect(content, package, key, 0, null);
            Assert.Equal(PackageSize, bytesProtected);

            var output = new byte[PackageSize];

            Assert.Throws<BadPackageException>(
                () => pUnprotect.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), output, key, 0, null));

            Assert.True(((ArraySegment<byte>)output).IsAllZeros(),
                "Destination not cleared after cross-ivSize unprotect failure.");
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void RoundTripFullAssociatedDataRangePass(int ivSize)
        {
            // The associatedData length is bound into the KDF (its byte value and the
            // bytes themselves). Exhaustively round-trip every valid associatedData
            // size from 0 to MaxAssociatedDataSize (== 32 - ivSize) for each ivSize.
            const int PackageSize = 128;

            var key = new byte[32].Fill(4);

            int maxAssociatedDataSize = 32 - ivSize;

            using var protector = new PackageProtector(ivSize: ivSize, packageSize: PackageSize);

            var content = new byte[protector.MaxContentSize - 1].Fill(9);

            var package = new byte[PackageSize];
            var unprotectedContent = new byte[PackageSize];

            for (int aadSize = 0; aadSize <= maxAssociatedDataSize; aadSize++)
            {
                var associatedData = new byte[aadSize].Fill((byte)(aadSize + 1));

                Array.Clear(package);
                Array.Clear(unprotectedContent);

                int bytesProtected = protector.Protect(content, package, key, 3, associatedData);

                int bytesUnprotected = protector.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), unprotectedContent, key, 3, associatedData);

                Assert.Equal(content.Length, bytesUnprotected);
                Assert.Equal(content, new ArraySegment<byte>(unprotectedContent, 0, bytesUnprotected).ToArray());
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void RoundTripFullKeySizeRangePass(int ivSize)
        {
            // The valid key length is 32..64 bytes. Exhaustively round-trip every
            // size in that range to confirm all are accepted and produce a valid
            // package, for each ivSize.
            const int PackageSize = 128;

            using var protector = new PackageProtector(ivSize: ivSize, packageSize: PackageSize);

            var associatedData = new byte[32 - ivSize].Fill(7);

            var content = new byte[protector.MaxContentSize - 2].Fill(9);

            var package = new byte[PackageSize];
            var unprotectedContent = new byte[PackageSize];

            for (int keySize = 32; keySize <= 64; keySize++)
            {
                var key = new byte[keySize].Fill((byte)keySize);

                Array.Clear(package);
                Array.Clear(unprotectedContent);

                int bytesProtected = protector.Protect(content, package, key, 9, associatedData);

                int bytesUnprotected = protector.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), unprotectedContent, key, 9, associatedData);

                Assert.Equal(content.Length, bytesUnprotected);
                Assert.Equal(content, new ArraySegment<byte>(unprotectedContent, 0, bytesUnprotected).ToArray());
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void RoundTripEmptyContentAllIvSizesPass(int ivSize)
        {
            // Empty content produces the minimum package (iv + hash + one padding
            // block) for every ivSize and must round-trip back to zero content bytes.
            const int PackageSize = 128;

            var key = new byte[32].Fill(4);
            var associatedData = new byte[32 - ivSize].Fill(7);

            using var protector = new PackageProtector(ivSize: ivSize, packageSize: PackageSize);

            int expectedPackageSize = ivSize + HashSize + BlockSize;

            var package = new byte[PackageSize];
            var unprotectedContent = new byte[PackageSize];

            int bytesProtected = protector.Protect(ArraySegment<byte>.Empty, package, key, 0, associatedData);

            Assert.Equal(expectedPackageSize, bytesProtected);

            int bytesUnprotected = protector.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), unprotectedContent, key, 0, associatedData);

            Assert.Equal(0, bytesUnprotected);
        }

        [Fact]
        public void ProtectValidationPrecedencePass()
        {
            // When multiple arguments are invalid at once, Protect must report them
            // in this documented order: content -> package -> key(size)
            // -> packageNumber -> associatedData.
            using var p = new PackageProtector(packageSize: 128);

            var tooLargeContent = new byte[p.MaxContentSize + 1];
            var validContent = new byte[p.MaxContentSize];

            var tinyPackage = new byte[1];
            var validPackage = new byte[p.MaxPackageSize];

            var hugeAssociatedData = new byte[999];

            // content (too large) wins over package, key, packageNumber, associatedData.
            var exContent = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Protect(tooLargeContent, tinyPackage, null, -1, hugeAssociatedData));
            Assert.Equal("content", exContent.ParamName);

            // package (insufficient) wins over key, packageNumber, associatedData.
            var exPackage = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Protect(validContent, tinyPackage, null, -1, hugeAssociatedData));
            Assert.Equal("package", exPackage.ParamName);

            // key (empty/bad size) wins over packageNumber, associatedData.
            var exKeyNull = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Protect(validContent, validPackage, null, -1, hugeAssociatedData));
            Assert.Equal("key", exKeyNull.ParamName);

            // key (bad size) wins over packageNumber, associatedData.
            var exKeySize = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Protect(validContent, validPackage, new byte[16], -1, hugeAssociatedData));
            Assert.Equal("key", exKeySize.ParamName);

            // packageNumber (negative) wins over associatedData.
            var exNumber = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Protect(validContent, validPackage, new byte[32], -1, hugeAssociatedData));
            Assert.Equal("packageNumber", exNumber.ParamName);

            // associatedData (too large) is reported last.
            var exAad = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Protect(validContent, validPackage, new byte[32], 0, hugeAssociatedData));
            Assert.Equal("associatedData", exAad.ParamName);
        }

        [Fact]
        public void UnprotectValidationPrecedencePass()
        {
            // When multiple arguments are invalid at once, Unprotect must report them
            // in this documented order: package -> content -> key(null) -> key(size)
            // -> packageNumber -> associatedData.
            using var p = new PackageProtector(packageSize: 128);

            var invalidPackage = new byte[1];
            var validPackage = new byte[p.MaxPackageSize];

            var tinyContent = new byte[0];
            var validContent = new byte[p.MaxPackageSize];

            var hugeAssociatedData = new byte[999];

            // package (bad size) wins over content, key, packageNumber, associatedData.
            var exPackage = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Unprotect(invalidPackage, tinyContent, null, -1, hugeAssociatedData));
            Assert.Equal("package", exPackage.ParamName);

            // content (insufficient) wins over key, packageNumber, associatedData.
            var exContent = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Unprotect(validPackage, tinyContent, null, -1, hugeAssociatedData));
            Assert.Equal("content", exContent.ParamName);

            // key (null) wins over packageNumber, associatedData.
            var exKeyNull = Assert.Throws<ArgumentNullException>(
                () => p.Unprotect(validPackage, validContent, null, -1, hugeAssociatedData));
            Assert.Equal("key", exKeyNull.ParamName);

            // key (bad size) wins over packageNumber, associatedData.
            var exKeySize = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Unprotect(validPackage, validContent, new byte[16], -1, hugeAssociatedData));
            Assert.Equal("key", exKeySize.ParamName);

            // packageNumber (negative) wins over associatedData.
            var exNumber = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Unprotect(validPackage, validContent, new byte[32], -1, hugeAssociatedData));
            Assert.Equal("packageNumber", exNumber.ParamName);

            // associatedData (too large) is reported last.
            var exAad = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Unprotect(validPackage, validContent, new byte[32], 0, hugeAssociatedData));
            Assert.Equal("associatedData", exAad.ParamName);
        }

        // Well known test vectors. Using ivSize 0 makes protection fully deterministic
        // (no random IV), so the produced package is reproducible. These vectors guard
        // against any accidental change to the wire format or cryptographic primitives.
        public static IEnumerable<object[]> KnownVectors()
        {
            // key (hex), packageNumber, content (hex), associatedData (hex), expected package (hex)
            yield return new object[]
            {
                "0000000000000000000000000000000000000000000000000000000000000000",
                0L,
                "",
                "",
                "590f24d12b4faf918babd1bd097c7818150084662c11ede3d487b42ad9ff3d2c5134199f2fb55e7e9328ac075debfdd3",
            };

            yield return new object[]
            {
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                1L,
                "00112233445566778899aabbccddeeff",
                "6164",
                "d4371eb4e1db03b9b7151aa888bc7479f3ed019cc0a74850958bbdf4fe07a2911ebca781f0a9b588a50348ed1fc8c9ecd1958a0bd4e97a9716895d1a00635779",
            };
        }

        [Theory]
        [MemberData(nameof(KnownVectors))]
        public void ProtectKnownVectorPass(string keyHex, long packageNumber, string contentHex, string associatedDataHex, string expectedPackageHex)
        {
            using var protector = new PackageProtector(ivSize: 0, packageSize: 64);

            byte[] key = Convert.FromHexString(keyHex);
            byte[] content = Convert.FromHexString(contentHex);
            byte[] associatedData = Convert.FromHexString(associatedDataHex);

            byte[] package = new byte[protector.MaxPackageSize];

            int protectedLength = protector.Protect(content, package, key, packageNumber, associatedData);

            Assert.Equal(expectedPackageHex, Convert.ToHexString(package, 0, protectedLength).ToLowerInvariant());
        }

        [Theory]
        [MemberData(nameof(KnownVectors))]
        public void UnprotectKnownVectorPass(string keyHex, long packageNumber, string contentHex, string associatedDataHex, string expectedPackageHex)
        {
            using var protector = new PackageProtector(ivSize: 0, packageSize: 64);

            byte[] key = Convert.FromHexString(keyHex);
            byte[] expectedContent = Convert.FromHexString(contentHex);
            byte[] associatedData = Convert.FromHexString(associatedDataHex);
            byte[] package = Convert.FromHexString(expectedPackageHex);

            byte[] content = new byte[package.Length];

            int unprotectedLength = protector.Unprotect(package, content, key, packageNumber, associatedData);

            Assert.Equal(expectedContent.Length, unprotectedLength);
            Assert.Equal(expectedContent, content[..unprotectedLength]);
        }
    }
}
