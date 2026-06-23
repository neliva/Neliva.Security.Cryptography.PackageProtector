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
        private const int SignKeySize = 64;

        private const int MinPackageSize = BlockSize + BlockSize + HashSize;

        // The maximum package size supported by the constructor (1 GiB).
        private const int MaxPackageSize = 1024 * 1024 * 1024;

        // A large, but readily allocatable, package size used by round-trip
        // tests that materialize full-size buffers in memory.
        private const int LargeTestPackageSize = (16 * 1024 * 1024) - BlockSize;

        // Test double that overrides FillRandom to supply deterministic
        // "random" bytes (for example a fixed IV) so that produced packages
        // are reproducible during testing. When constructed without a delegate,
        // it defers to the default (cryptographically strong) RNG.
        private sealed class TestPackageProtector : PackageProtector
        {
            private readonly RngFillAction _fillRandom;

            public TestPackageProtector(int ivSize = BlockSize, int packageSize = 64 * 1024)
                : base(ivSize, packageSize)
            {
            }

            public TestPackageProtector(RngFillAction fillRandom, int ivSize = BlockSize, int packageSize = 64 * 1024)
                : base(ivSize, packageSize)
            {
                this._fillRandom = fillRandom;
            }

            protected override void FillRandom(Span<byte> data)
            {
                if (this._fillRandom is null)
                {
                    base.FillRandom(data);
                    return;
                }

                this._fillRandom(data);
            }
        }

        [Fact]
        public void ProtectOverlapFail()
        {
            var protector = new TestPackageProtector(packageSize: 64);

            var buf = new byte[protector.MaxPackageSize * 2];

            var content = new ArraySegment<byte>(buf, 1, protector.MaxContentSize);

            var package = new ArraySegment<byte>(buf, protector.MaxContentSize, protector.MaxPackageSize);

            using var key = new PackageKey(new byte[32]);

            var ex = Assert.Throws<InvalidOperationException>(() => protector.Protect(content, package, key, 0, null));
            Assert.Equal("The 'package' must not overlap in memory with the 'content'.", ex.Message);
        }

        [Fact]
        public void ProtectNoOverlapPass()
        {
            var protector = new TestPackageProtector(packageSize: 64);

            var buf = new byte[protector.MaxPackageSize * 2];

            var content = new ArraySegment<byte>(buf, protector.MaxPackageSize, protector.MaxContentSize);

            var package = new ArraySegment<byte>(buf);

            using var key = new PackageKey(new byte[32]);

            Assert.Equal(protector.MaxPackageSize, protector.Protect(content, package, key, 0, null));
        }

        [Fact]
        public void UnprotectOverlapFail()
        {
            var protector = new TestPackageProtector(packageSize: 64);

            var buf = new byte[protector.MaxPackageSize * 2];

            var package = new ArraySegment<byte>(buf, protector.MaxContentSize, protector.MaxPackageSize);

            var content = new ArraySegment<byte>(buf, 1, protector.MaxPackageSize);

            using var key = new PackageKey(new byte[32]);

            var ex = Assert.Throws<InvalidOperationException>(() => protector.Unprotect(package, content, key, 0, null));
            Assert.Equal("The 'content' must not overlap in memory with the 'package'.", ex.Message);
        }

        [Fact]
        public void UnprotectNoOverlapPass()
        {
            var protector = new TestPackageProtector(packageSize: 64);

            var buf = new byte[protector.MaxPackageSize * 2];

            var package = new ArraySegment<byte>(buf, protector.MaxPackageSize, protector.MaxPackageSize);

            var content = new ArraySegment<byte>(buf);

            using var key = new PackageKey(new byte[32]);

            protector.Protect(content.Slice(0, protector.MaxContentSize), package, key, 0, null);

            Assert.Equal(protector.MaxContentSize, protector.Unprotect(package, content, key, 0, null));
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
            var ex = Assert.Throws<ArgumentException>(() => new TestPackageProtector(ivSize: ivSize));

            Assert.Equal(nameof(ivSize), ex.ParamName);
            Assert.Equal("IV size must be 0, 16, or 32 bytes. (Parameter 'ivSize')", ex.Message);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void NewPackageProtectorValidIvSizePass(int ivSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize);
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
            var ex = Assert.Throws<ArgumentException>(() => new TestPackageProtector(ivSize: ivSize, packageSize: packageSize));

            Assert.Equal(nameof(packageSize), ex.ParamName);
            Assert.Equal("Package size must be a multiple of 16 bytes, at least (ivSize + 48), and no greater than 1073741824 bytes. (Parameter 'packageSize')", ex.Message);
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
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: packageSize);

            int overhead = ivSize + HashSize + 1;

            int maxContentSize = packageSize - overhead;

            Assert.Equal(packageSize, p.MaxPackageSize);
            Assert.Equal(maxContentSize, p.MaxContentSize);

            Assert.Equal(overhead, p.MaxPackageSize - p.MaxContentSize);
        }

        [Theory]
        // Zero IV
        [InlineData(0, 48)]
        [InlineData(0, 64 * 1024)]
        // 16 bytes IV
        [InlineData(16, 64)]
        [InlineData(16, 64 * 1024)]
        // 32 bytes IV
        [InlineData(32, 80)]
        [InlineData(32, 64 * 1024)]
        public void NewPackageProtectorExposesConfigurationPropertiesPass(int ivSize, int packageSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: packageSize);

            // IvSize echoes the constructor argument.
            Assert.Equal(ivSize, p.IvSize);

            // MinPackageSize is iv + MAC (32) + one full padding block (16).
            Assert.Equal(ivSize + HashSize + BlockSize, p.MinPackageSize);

            // MaxAssociatedDataSize is the 80 byte KDF args region minus the IV.
            Assert.Equal(80 - ivSize, p.MaxAssociatedDataSize);

            // MaxPackageSize echoes the constructor argument; MaxContentSize is
            // the package minus the iv + MAC (32) + one padding byte overhead.
            Assert.Equal(packageSize, p.MaxPackageSize);
            Assert.Equal(packageSize - (ivSize + HashSize + 1), p.MaxContentSize);

            // The configuration must be internally consistent.
            Assert.True(p.MinPackageSize <= p.MaxPackageSize);
            Assert.True(p.MaxContentSize >= 0);
        }

        [Fact]
        public void SystemExposesExpectedConfigurationPropertiesPass()
        {
            // The System protector is configured with a 32 byte IV and a 64 KiB
            // package size.
            var system = PackageProtector.System;

            Assert.IsAssignableFrom<PackageProtector>(system);

            Assert.Equal(32, system.IvSize);
            Assert.Equal(64 * 1024, system.MaxPackageSize);
            Assert.Equal(32 + HashSize + BlockSize, system.MinPackageSize);
            Assert.Equal(80 - 32, system.MaxAssociatedDataSize);
            Assert.Equal((64 * 1024) - (32 + HashSize + 1), system.MaxContentSize);
        }

        [Fact]
        public void ProtectNullKeyFail()
        {
            var p = new TestPackageProtector(packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentNullException>(() => p.Protect(content, package, null, 0, null));
            Assert.Equal("key", ex.ParamName);
        }

        [Fact]
        public void UnprotectNullKeyFail()
        {
            var p = new TestPackageProtector(packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentNullException>(() => p.Unprotect(package, package, null, 0, null));
            Assert.Equal("key", ex.ParamName);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void ProtectFillRandomOverridePass(int ivSize)
        {
            int callCount = 0;
            byte[] filledIV = Array.Empty<byte>();

            RngFillAction fillRandom = (Span<byte> data) =>
            {
                callCount++;

                if (data.Length != ivSize)
                {
                    throw new XunitException("FillRandom received an unexpected span length.");
                }

                filledIV = new byte[data.Length].Fill((byte)data.Length);

                filledIV.AsSpan().CopyTo(data);
            };

            var protector = new TestPackageProtector(fillRandom, ivSize: ivSize, packageSize: 128);

            var content = new byte[1].Fill(100);
            var package = new byte[protector.MaxPackageSize];

            protector.Protect(content, package, new PackageKey(new byte[32].Fill(32)), 0, null);

            // FillRandom is invoked exactly once to generate the IV.
            Assert.Equal(1, callCount);
            Assert.Equal(ivSize, filledIV.Length);

            var pkgIV = new ArraySegment<byte>(package, 0, ivSize).ToArray();

            Assert.Equal(filledIV, pkgIV);
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

            var protector = new TestPackageProtector(rng, ivSize: ivSize, packageSize: 80);

            var content = new byte[1].Fill(100);
            var package = new byte[protector.MaxPackageSize];

            var ex = Assert.Throws<Exception>(() => protector.Protect(content, package, new PackageKey(new byte[32].Fill(32)), 0, null));
            Assert.Equal(exStr, ex.Message);

            Assert.Equal(ivSize, rngVal.Length);

            var pkgIV = new ArraySegment<byte>(package, 0, ivSize);

            Assert.True(pkgIV.IsAllZeros(), "Destination not cleared on Protect() failure.");

            Assert.NotEqual(rngVal, pkgIV.ToArray());
        }

        [Fact]
        public void ProtectInvalidPackageNumberFail()
        {
            var p = new TestPackageProtector(packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Protect(content, package, new PackageKey(new byte[32]), -1, null));
            Assert.Equal("packageNumber", ex.ParamName);
            Assert.Equal("Package number must not be negative. (Parameter 'packageNumber')", ex.Message);
        }

        [Fact]
        public void UnprotectInvalidPackageNumberFail()
        {
            var p = new TestPackageProtector(packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => p.Unprotect(package, package, new PackageKey(new byte[32]), -1, null));
            Assert.Equal("packageNumber", ex.ParamName);
            Assert.Equal("Package number must not be negative. (Parameter 'packageNumber')", ex.Message);
        }

        [Theory]
        [InlineData(0, 81)]
        [InlineData(16, 65)]
        [InlineData(32, 49)]
        public void ProtectInvalidAssociatedDataFail(int ivSize, int associatedDataSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentException>(() => p.Protect(content, package, new PackageKey(new byte[32]), long.MaxValue, new byte[associatedDataSize]));
            Assert.Equal("associatedData", ex.ParamName);
            Assert.Equal("Associated data length is too large. (Parameter 'associatedData')", ex.Message);
        }

        [Theory]
        [InlineData(0, 81)]
        [InlineData(16, 65)]
        [InlineData(32, 49)]
        public void UnprotectInvalidAssociatedDataSizeFail(int ivSize, int associatedDataSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentException>(() => p.Unprotect(package, package, new PackageKey(new byte[32]), long.MaxValue, new byte[associatedDataSize]));
            Assert.Equal("associatedData", ex.ParamName);
            Assert.Equal("Associated data length is too large. (Parameter 'associatedData')", ex.Message);
        }

        [Theory]
        [InlineData(0, 48)]
        [InlineData(16, 64)]
        [InlineData(32, 80)]
        public void ProtectInvalidPackageSizeFail(int ivSize, int packageSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: packageSize);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize - 1];

            var ex = Assert.Throws<ArgumentException>(() => p.Protect(content, package, new PackageKey(new byte[32]), long.MaxValue, null));
            Assert.Equal("package", ex.ParamName);
            Assert.Equal("Insufficient space for package output. (Parameter 'package')", ex.Message);
        }

        [Theory]
        [InlineData(0, 48)]
        [InlineData(16, 64)]
        [InlineData(32, 80)]
        public void ProtectInvalidContentSizeFail(int ivSize, int packageSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: packageSize);

            var content = new byte[p.MaxContentSize + 1];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.Throws<ArgumentException>(() => p.Protect(content, package, new PackageKey(new byte[32]), long.MaxValue, null));
            Assert.Equal("content", ex.ParamName);
            Assert.Equal("Content length is too large. (Parameter 'content')", ex.Message);
        }

        [Theory]
        [InlineData(0, 48)]
        [InlineData(16, 64)]
        [InlineData(32, 80)]
        public void UnprotectInvalidContentSizeFail(int ivSize, int packageSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: packageSize);

            var package = new byte[p.MaxPackageSize];

            var content = new byte[p.MaxContentSize];

            var ex = Assert.Throws<ArgumentException>(() => p.Unprotect(package, content, new PackageKey(new byte[32]), long.MaxValue, null));
            Assert.Equal("content", ex.ParamName);
            Assert.Equal("Insufficient space for content output. (Parameter 'content')", ex.Message);
        }

        [Theory]
        // Length below the minimum or above the maximum (also unaligned).
        [InlineData(0, 48, 47)]
        [InlineData(0, 48, 49)]
        [InlineData(16, 64, 63)]
        [InlineData(16, 64, 65)]
        [InlineData(32, 80, 79)]
        [InlineData(32, 80, 81)]
        // In-range length but not aligned to the 16 byte block boundary, or above max.
        [InlineData(0, 48 + 16, 48 + 16 - 1)]
        [InlineData(0, 48 + 16, 48 + 16 + 1)]
        [InlineData(16, 64 + 16, 64 + 16 - 1)]
        [InlineData(16, 64 + 16, 64 + 16 + 1)]
        [InlineData(32, 80 + 16, 80 + 16 - 1)]
        [InlineData(32, 80 + 16, 80 + 16 + 1)]
        public void UnprotectInvalidPackageSizeFail(int ivSize, int packageSize, int invalidPackageSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: packageSize);

            var package = new byte[invalidPackageSize];

            var content = new byte[p.MaxContentSize + 1];

            var ex = Assert.Throws<ArgumentException>(() => p.Unprotect(package, content, new PackageKey(new byte[32]), 0, null));
            Assert.Equal("package", ex.ParamName);
            Assert.Equal("Package length is invalid or not aligned to the required boundary. (Parameter 'package')", ex.Message);
        }

        [Fact]
        public void ProtectNullOrDefaultContentPass()
        {
            var p = new TestPackageProtector(packageSize: 128);

            p.Protect(null, new byte[128], new PackageKey(new byte[32]), 0, new byte[1]);
            p.Protect(default, new byte[128], new PackageKey(new byte[32]), 0, new byte[1]);
            p.Protect(ArraySegment<byte>.Empty, new byte[128], new PackageKey(new byte[32]), 0, new byte[1]);
        }

        [Fact]
        public void ProtectNullOrDefaultAssociatedDataPass()
        {
            var p = new TestPackageProtector(packageSize: 128);

            p.Protect(new byte[1], new byte[128], new PackageKey(new byte[32]), 0, null);
            p.Protect(new byte[1], new byte[128], new PackageKey(new byte[33]), 0, default);
            p.Protect(new byte[1], new byte[128], new PackageKey(new byte[64]), 0, ArraySegment<byte>.Empty);
        }

        [Fact]
        public void UnprotectNullOrDefaultAssociatedDataPass()
        {
            var protector = new TestPackageProtector(packageSize: 64);

            var p = new byte[64];
            var c = new byte[64];
            protector.Protect(default, p, new PackageKey(new byte[32]), 0, default);

            protector.Unprotect(p, c, new PackageKey(new byte[32]), 0, null);
            protector.Unprotect(p, c, new PackageKey(new byte[32]), 0, default);
            protector.Unprotect(p, c, new PackageKey(new byte[32]), 0, ArraySegment<byte>.Empty);
        }

        [Theory]
        [InlineData(0, 48, 0)]
        [InlineData(0, 48 + BlockSize, 0)]
        [InlineData(0, LargeTestPackageSize, 0)]
        [InlineData(0, 48, 16)]
        [InlineData(0, 48 + BlockSize, 16)]
        [InlineData(0, LargeTestPackageSize, 16)]
        [InlineData(0, 48, 32)]
        [InlineData(0, 48 + BlockSize, 32)]
        [InlineData(0, LargeTestPackageSize, 32)]
        //
        [InlineData(16, 64, 0)]
        [InlineData(16, 64 + BlockSize, 0)]
        [InlineData(16, LargeTestPackageSize, 0)]
        [InlineData(16, 64, 16)]
        [InlineData(16, 64 + BlockSize, 16)]
        [InlineData(16, LargeTestPackageSize, 16)]
        //
        [InlineData(32, 80, 0)]
        [InlineData(32, 80 + BlockSize, 0)]
        [InlineData(32, LargeTestPackageSize, 0)]
        public void RoundTripFullPackagePass(int ivSize, int packageSize, int associatedDataSize)
        {
            using var key = new PackageKey(new byte[64].Fill(4));
            var associatedData = new byte[associatedDataSize].Fill((byte)associatedDataSize);

            var protector = new TestPackageProtector(ivSize, packageSize);
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
            using var key = new PackageKey(new byte[32].Fill(4));
            var associatedData = new byte[13].Fill(4);

            foreach (var packageSize in new int[] { MinPackageSize, MinPackageSize + BlockSize, LargeTestPackageSize })
            {
                var protector = new TestPackageProtector(packageSize: packageSize);
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
            using var key = new PackageKey(new byte[32].Fill(4));
            var associatedData = new byte[1].Fill(4);

            const int PackageSize = MinPackageSize + BlockSize;

            byte[] contentBuffer = new byte[PackageSize].Fill(33);
            byte[] packageBuffer = new byte[PackageSize];
            byte[] unprotectedContentBuffer = new byte[PackageSize];

            var protector = new TestPackageProtector(packageSize: PackageSize);

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

            using (var packageKey = new PackageKey(masterKey))
            {
                Internals.DeriveKeys(packageKey, 42, 4096, kdfIV, associatedData, encKey, sigKey);
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

            using (var packageKey = new PackageKey(masterKey))
            {
                for (int i = 0; i < iv1.Length; i++)
                {
                    var s1 = iv1.Slice(0, i);
                    var s2 = iv2.Slice(i);

                    Internals.DeriveKeys(packageKey, 42, 4096, s1, s2, encKey, sigKey);

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

            using (var packageKey = new PackageKey(masterKey))
            {
                // The combined ivArg1 + ivArg2 region is 80 bytes; exceeding it must throw.
                Assert.Throws<ArgumentException>(() => Internals.DeriveKeys(packageKey, 42, 4096, new byte[81], new byte[0], encKey, sigKey));
                Assert.Throws<ArgumentException>(() => Internals.DeriveKeys(packageKey, 42, 4096, new byte[0], new byte[81], encKey, sigKey));

                Assert.Throws<ArgumentException>(() => Internals.DeriveKeys(packageKey, 42, 4096, new byte[80], new byte[1], encKey, sigKey));
                Assert.Throws<ArgumentException>(() => Internals.DeriveKeys(packageKey, 42, 4096, new byte[1], new byte[80], encKey, sigKey));

                Assert.Throws<ArgumentException>(() => Internals.DeriveKeys(packageKey, 42, 4096, new byte[41], new byte[40], encKey, sigKey));
                Assert.Throws<ArgumentException>(() => Internals.DeriveKeys(packageKey, 42, 4096, new byte[40], new byte[41], encKey, sigKey));
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
                using (var packageKey = new PackageKey(masterKey))
                {
                    Internals.DeriveKeys(packageKey, a.Item1, a.Item2, kdfIV, a.Item3, encKey, sigKey);
                }

                var expectedEncKey = DeriveKeyTestImpl(masterKey, true, a.Item1, a.Item2, kdfIV, a.Item3);
                var expectedSigKey = DeriveKeyTestImpl(masterKey, false, a.Item1, a.Item2, kdfIV, a.Item3);

                Assert.Equal(expectedEncKey, encKey);
                Assert.Equal(expectedSigKey, sigKey);
            }
        }

        [Fact]
        public void UnprotectWrongKeyFail()
        {
            var protector = new TestPackageProtector(packageSize: MinPackageSize);

            var keyBytes = new byte[32].Fill(4);
            using var key = new PackageKey(keyBytes);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize - 8].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            keyBytes[31] ^= 1;
            using var wrongKey = new PackageKey(keyBytes);

            Assert.Throws<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, wrongKey, 5, associatedData));

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        [Fact]
        public void UnprotectWrongPackageNumberFail()
        {
            var protector = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(4));
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
            var protector = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(4));
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize - 5].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            var protector1 = new TestPackageProtector(packageSize: MinPackageSize + BlockSize);

            Assert.Throws<BadPackageException>(() => protector1.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        [Fact]
        public void UnprotectWrongAssociatedDataFail()
        {
            var protector = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(4));

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

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public void UnprotectTamperEveryByteAndBitMultiBlockFail(int ivSize)
        {
            // Exhaustive tamper detection: flipping any single bit at any byte
            // position of a multi block package must be rejected and must clear the
            // output. Covers the IV region (bytes 0..ivSize, which the KDF binds the
            // derived keys to), the MAC region, and the encrypted body.
            const int PackageSize = 128; // Multiple AES blocks beyond the minimum.

            var protector = new TestPackageProtector(ivSize: ivSize, packageSize: PackageSize);

            using var key = new PackageKey(new byte[32].Fill(4));

            // MaxAssociatedDataSize == 80 - ivSize; use the maximum valid for each ivSize.
            var associatedData = new byte[80 - ivSize].Fill(7);

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

            var protector = new TestPackageProtector(ivSize: 16, packageSize: PackageSize);

            using var key = new PackageKey(new byte[32].Fill(4));
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

            var protector = new TestPackageProtector(ivSize: 16, packageSize: PackageSize);

            using var key = new PackageKey(new byte[32].Fill(4));
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

            var protector = new TestPackageProtector(packageSize: MinPackageSize);

            var keyBytes = new byte[32].Fill(93);
            using var key = new PackageKey(keyBytes);
            var associatedData = new byte[13].Fill(56);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize].Fill(231));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            protector.Protect(content, package, key, 5, associatedData);

            var encKey = DeriveKeyTestImpl(keyBytes, true, 5, MinPackageSize, package.Slice(0, BlockSize), associatedData);
            var sigKey = DeriveKeyTestImpl(keyBytes, false, 5, MinPackageSize, package.Slice(0, BlockSize), associatedData, SignKeySize);

            using (var aes = Aes.Create())
            {
                aes.Padding = PaddingMode.None;
                aes.Mode = CipherMode.CBC;

                using (var dec = aes.CreateDecryptor(encKey, ZeroIV))
                {
                    dec.TransformBlock(package.Array, BlockSize, MinPackageSize - BlockSize, package.Array, BlockSize);
                }

                Assert.Equal(content.Array, package.Slice(BlockSize + HashSize, content.Count).ToArray());

                using (var hmac = new HMACSHA512(sigKey))
                {
                    // The package MAC is an HMAC-SHA512 truncated to 32 bytes.
                    Span<byte> fullMac = stackalloc byte[SignKeySize];

                    hmac.TryComputeHash(package.AsSpan(BlockSize + HashSize, MinPackageSize - BlockSize - HashSize), fullMac, out _);

                    Assert.Equal(fullMac.Slice(0, HashSize).ToArray(), package.Slice(BlockSize, HashSize).ToArray());

                    package[MinPackageSize - 1] = 2;

                    hmac.TryComputeHash(package.AsSpan(BlockSize + HashSize, MinPackageSize - BlockSize - HashSize), fullMac, out _);

                    fullMac.Slice(0, HashSize).CopyTo(package.AsSpan(BlockSize, HashSize));
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

        private static byte[] DeriveKeyTestImpl(byte[] masterKey, bool encrypt, long packageNumber, int packageSize, ReadOnlySpan<byte> ivArg1, ReadOnlySpan<byte> ivArg2, int keyLength = HashSize)
        {
            ReadOnlySpan<byte> label = encrypt
                ? new byte[] { (byte)'E', (byte)'N', (byte)'C' }
                : new byte[] { (byte)'M', (byte)'A', (byte)'C' };

            Span<byte> context = stackalloc byte[99];
            context.Clear();

            BinaryPrimitives.WriteInt64BigEndian(context, packageNumber);

            var ivArgs = context.Slice(8, 80);
            ivArg1.CopyTo(ivArgs);
            ivArg2.CopyTo(ivArgs.Slice(ivArg1.Length));

            context[88] = (byte)ivArg1.Length;
            context[89] = (byte)ivArg2.Length;
            context[90] = 0; // Reserved (ivArg3 length).
            context[91] = BlockSize; // Package padding size in bytes.

            BinaryPrimitives.WriteInt32BigEndian(context.Slice(92), packageSize);

            context[96] = 0; // Reserved.
            context[97] = 0; // Reserved.
            context[98] = 1; // Format version number.

            using (var hmac = new HMACSHA512(masterKey))
            {
                var derivedKey = new byte[keyLength];

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

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        public void ProtectRandomIvProducesDifferentCiphertextPass(int ivSize)
        {
            // Semantic security: same plaintext + key + packageNumber + associatedData
            // must yield distinct ciphertexts when a random IV is used.
            var protector = new TestPackageProtector(ivSize: ivSize, packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(11));
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
            var protector = new TestPackageProtector(ivSize: 0, packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(11));
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
            using var key = new PackageKey(new byte[64].Fill(17));

            // MaxAssociatedDataSize == 80 - ivSize; empty is a simple valid choice.
            var associatedData = ArraySegment<byte>.Empty;

            var pA = new TestPackageProtector(ivSize: ivSize, packageSize: 256);
            var pB = new TestPackageProtector(ivSize: ivSize, packageSize: 256);

            var content = new byte[pA.MaxContentSize - 13].Fill(99);

            var package = new byte[pA.MaxPackageSize];

            int bytesProtected = pA.Protect(content, package, key, 12345, associatedData);

            var output = new byte[pB.MaxPackageSize];

            int bytesUnprotected = pB.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), output, key, 12345, associatedData);

            Assert.Equal(content.Length, bytesUnprotected);
            Assert.Equal(content, new ArraySegment<byte>(output, 0, bytesUnprotected).ToArray());
        }

        [Fact]
        public void SystemReturnsSingletonInstancePass()
        {
            // The System property exposes a single shared, lazily-initialized
            // instance. Repeated access must return the same reference.
            var first = PackageProtector.System;
            var second = PackageProtector.System;

            Assert.NotNull(first);
            Assert.Same(first, second);
        }

        [Fact]
        public void SystemRoundTripPass()
        {
            // The System protector uses the default cryptographically strong RNG.
            // A round-trip through Protect/Unprotect must succeed bit-for-bit.
            var system = PackageProtector.System;

            using var key = new PackageKey(new byte[32].Fill(13));

            // System uses ivSize 32, so MaxAssociatedDataSize is 80 - 32 = 48; empty is a simple valid choice.
            var associatedData = ReadOnlySpan<byte>.Empty;

            var content = new byte[200].Fill(200);

            var package = new byte[content.Length + system.MaxPackageSize];

            int bytesProtected = system.Protect(content, package, key, 9, associatedData);

            var output = new byte[bytesProtected];

            int bytesUnprotected = system.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), output, key, 9, associatedData);

            Assert.Equal(content.Length, bytesUnprotected);
            Assert.Equal(content, new ArraySegment<byte>(output, 0, bytesUnprotected).ToArray());
        }

        [Fact]
        public void SystemProducesRandomIvPass()
        {
            // The System protector sources a fresh random IV for each Protect
            // call (ivSize is 32). Two packages over identical inputs
            // must therefore differ in both the IV prefix and the encrypted body.
            const int IvSize = 32;

            var system = PackageProtector.System;

            using var key = new PackageKey(new byte[32].Fill(11));
            var content = new byte[64].Fill(42);

            var pkg1 = new byte[content.Length + system.MaxPackageSize];
            var pkg2 = new byte[content.Length + system.MaxPackageSize];

            int len1 = system.Protect(content, pkg1, key, 7, null);
            int len2 = system.Protect(content, pkg2, key, 7, null);

            Assert.Equal(len1, len2);

            var body1 = new ArraySegment<byte>(pkg1, 0, len1).ToArray();
            var body2 = new ArraySegment<byte>(pkg2, 0, len2).ToArray();

            Assert.NotEqual(body1, body2);

            // Difference must include the random IV prefix.
            Assert.NotEqual(
                new ArraySegment<byte>(pkg1, 0, IvSize).ToArray(),
                new ArraySegment<byte>(pkg2, 0, IvSize).ToArray());
        }

        [Fact]
        public void SystemRoundTripAcrossInstancesPass()
        {
            // A package produced by the System protector must be decryptable by
            // any other instance with the same parameters, confirming there is no
            // hidden per-instance state and that the random IV is embedded in the
            // package.
            var system = PackageProtector.System;
            var other = new TestPackageProtector(ivSize: 32, packageSize: 64 * 1024);

            using var key = new PackageKey(new byte[64].Fill(17));

            // System uses ivSize 32, so MaxAssociatedDataSize is 80 - 32 = 48; empty is a simple valid choice.
            var associatedData = ReadOnlySpan<byte>.Empty;

            var content = new byte[128].Fill(123);

            var package = new byte[content.Length + system.MaxPackageSize];

            int bytesProtected = system.Protect(content, package, key, 99, associatedData);

            var output = new byte[bytesProtected];

            int bytesUnprotected = other.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), output, key, 99, associatedData);

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

            using var key = new PackageKey(new byte[32].Fill(5));

            var pProtect = new TestPackageProtector(ivSize: protectIvSize, packageSize: PackageSize);
            var pUnprotect = new TestPackageProtector(ivSize: unprotectIvSize, packageSize: PackageSize);

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
            // size from 0 to MaxAssociatedDataSize (== 80 - ivSize) for each ivSize.
            const int PackageSize = 128;

            using var key = new PackageKey(new byte[32].Fill(4));

            int maxAssociatedDataSize = 80 - ivSize;

            var protector = new TestPackageProtector(ivSize: ivSize, packageSize: PackageSize);

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
        public void AssociatedDataMaxBoundaryPass(int ivSize)
        {
            // The associated data limit is exactly (80 - ivSize): the KDF ivArgs
            // region is 80 bytes and holds the KDF IV and associated data combined.
            // The maximum size must round-trip, and one byte over must be rejected
            // by both Protect and Unprotect.
            const int PackageSize = 128;

            using var key = new PackageKey(new byte[32].Fill(4));

            int maxAssociatedDataSize = 80 - ivSize;

            var protector = new TestPackageProtector(ivSize: ivSize, packageSize: PackageSize);

            var content = new byte[protector.MaxContentSize].Fill(9);

            var package = new byte[PackageSize];
            var unprotectedContent = new byte[PackageSize];

            // Exactly the maximum associated data size round-trips.
            var maxAssociatedData = new byte[maxAssociatedDataSize].Fill(7);

            int bytesProtected = protector.Protect(content, package, key, 5, maxAssociatedData);

            int bytesUnprotected = protector.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), unprotectedContent, key, 5, maxAssociatedData);

            Assert.Equal(content.Length, bytesUnprotected);
            Assert.Equal(content, new ArraySegment<byte>(unprotectedContent, 0, bytesUnprotected).ToArray());

            // One byte over the maximum must be rejected by both Protect and Unprotect.
            var tooLargeAssociatedData = new byte[maxAssociatedDataSize + 1];

            var protectEx = Assert.Throws<ArgumentException>(() => protector.Protect(content, package, key, 5, tooLargeAssociatedData));
            Assert.Equal("associatedData", protectEx.ParamName);

            var unprotectEx = Assert.Throws<ArgumentException>(() => protector.Unprotect(new ArraySegment<byte>(package, 0, bytesProtected), unprotectedContent, key, 5, tooLargeAssociatedData));
            Assert.Equal("associatedData", unprotectEx.ParamName);
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

            var protector = new TestPackageProtector(ivSize: ivSize, packageSize: PackageSize);

            var associatedData = new byte[80 - ivSize].Fill(7);

            var content = new byte[protector.MaxContentSize - 2].Fill(9);

            var package = new byte[PackageSize];
            var unprotectedContent = new byte[PackageSize];

            for (int keySize = 32; keySize <= 64; keySize++)
            {
                using var key = new PackageKey(new byte[keySize].Fill((byte)keySize));

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

            using var key = new PackageKey(new byte[32].Fill(4));
            var associatedData = new byte[80 - ivSize].Fill(7);

            var protector = new TestPackageProtector(ivSize: ivSize, packageSize: PackageSize);

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
            // in this documented order: content -> package -> key(null)
            // -> packageNumber -> associatedData.
            var p = new TestPackageProtector(packageSize: 128);

            using var validKey = new PackageKey(new byte[32]);

            var tooLargeContent = new byte[p.MaxContentSize + 1];
            var validContent = new byte[p.MaxContentSize];

            var tinyPackage = new byte[1];
            var validPackage = new byte[p.MaxPackageSize];

            var hugeAssociatedData = new byte[999];

            // content (too large) wins over package, key, packageNumber, associatedData.
            var exContent = Assert.Throws<ArgumentException>(
                () => p.Protect(tooLargeContent, tinyPackage, null, -1, hugeAssociatedData));
            Assert.Equal("content", exContent.ParamName);

            // package (insufficient) wins over key, packageNumber, associatedData.
            var exPackage = Assert.Throws<ArgumentException>(
                () => p.Protect(validContent, tinyPackage, null, -1, hugeAssociatedData));
            Assert.Equal("package", exPackage.ParamName);

            // key (null) wins over packageNumber, associatedData.
            var exKeyNull = Assert.Throws<ArgumentNullException>(
                () => p.Protect(validContent, validPackage, null, -1, hugeAssociatedData));
            Assert.Equal("key", exKeyNull.ParamName);

            // packageNumber (negative) wins over associatedData.
            var exNumber = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Protect(validContent, validPackage, validKey, -1, hugeAssociatedData));
            Assert.Equal("packageNumber", exNumber.ParamName);

            // associatedData (too large) is reported last.
            var exAad = Assert.Throws<ArgumentException>(
                () => p.Protect(validContent, validPackage, validKey, 0, hugeAssociatedData));
            Assert.Equal("associatedData", exAad.ParamName);
        }

        [Fact]
        public void UnprotectValidationPrecedencePass()
        {
            // When multiple arguments are invalid at once, Unprotect must report them
            // in this documented order: package -> content -> key(null)
            // -> packageNumber -> associatedData.
            var p = new TestPackageProtector(packageSize: 128);

            using var validKey = new PackageKey(new byte[32]);

            var invalidPackage = new byte[1];
            var validPackage = new byte[p.MaxPackageSize];

            var tinyContent = new byte[0];
            var validContent = new byte[p.MaxPackageSize];

            var hugeAssociatedData = new byte[999];

            // package (bad size) wins over content, key, packageNumber, associatedData.
            var exPackage = Assert.Throws<ArgumentException>(
                () => p.Unprotect(invalidPackage, tinyContent, null, -1, hugeAssociatedData));
            Assert.Equal("package", exPackage.ParamName);

            // content (insufficient) wins over key, packageNumber, associatedData.
            var exContent = Assert.Throws<ArgumentException>(
                () => p.Unprotect(validPackage, tinyContent, null, -1, hugeAssociatedData));
            Assert.Equal("content", exContent.ParamName);

            // key (null) wins over packageNumber, associatedData.
            var exKeyNull = Assert.Throws<ArgumentNullException>(
                () => p.Unprotect(validPackage, validContent, null, -1, hugeAssociatedData));
            Assert.Equal("key", exKeyNull.ParamName);

            // packageNumber (negative) wins over associatedData.
            var exNumber = Assert.Throws<ArgumentOutOfRangeException>(
                () => p.Unprotect(validPackage, validContent, validKey, -1, hugeAssociatedData));
            Assert.Equal("packageNumber", exNumber.ParamName);

            // associatedData (too large) is reported last.
            var exAad = Assert.Throws<ArgumentException>(
                () => p.Unprotect(validPackage, validContent, validKey, 0, hugeAssociatedData));
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
                "aa00521418d47845617c22e26da2b44bc1b5388adb6922a7097826d0627dbb7cb4b808b99678dc4f6a0c704bf49e98b4",
            };

            yield return new object[]
            {
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                1L,
                "00112233445566778899aabbccddeeff",
                "6164",
                "94e7aae55187496fe9affb005d1af33d74491e4214cbfdbae86c1c7fbe38c1855e36883b213168215fb3fdb74be6e6a0f13c99ea0a5d6dcd1981e91add11d149",
            };
        }

        [Theory]
        [MemberData(nameof(KnownVectors))]
        public void ProtectKnownVectorPass(string keyHex, long packageNumber, string contentHex, string associatedDataHex, string expectedPackageHex)
        {
            var protector = new TestPackageProtector(ivSize: 0, packageSize: 64);

            using var key = new PackageKey(Convert.FromHexString(keyHex));
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
            var protector = new TestPackageProtector(ivSize: 0, packageSize: 64);

            using var key = new PackageKey(Convert.FromHexString(keyHex));
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
