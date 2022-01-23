// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    [TestClass]
    public class PackageProtectorTests
    {
        private const int BlockSize = 16;
        private const int HashSize = 32;

        private const int MinPackageSize = BlockSize + BlockSize + HashSize;
        private const int MaxPackageSize = (16 * 1024 * 1024) - BlockSize;

        [TestMethod]
        public void PackageProtectorUseAfterDisposeFail()
        {
            using var protector = new PackageProtector(packageSize: 64);

            protector.Dispose();

            var content = new byte[protector.MaxContentSize];
            var package = new byte[protector.MaxPackageSize];

            var key = new byte[32];

            var ex = Assert.ThrowsException<ObjectDisposedException>(() => protector.Protect(content, package, key, 0, null));
            Assert.AreEqual(typeof(PackageProtector).FullName, ex.ObjectName);

            ex = Assert.ThrowsException<ObjectDisposedException>(() => protector.Unprotect(package, package, key, 0, null));
            Assert.AreEqual(typeof(PackageProtector).FullName, ex.ObjectName);
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(15)]
        [DataRow(17)]
        [DataRow(31)]
        [DataRow(33)]
        [DataRow(48)]
        public void NewPackageProtectorInvalidIvSizeFail(int ivSize)
        {
            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => new PackageProtector(ivSize: ivSize));

            Assert.AreEqual(nameof(ivSize), ex.ParamName);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(16)]
        [DataRow(32)]
        public void NewPackageProtectorValidIvSizePass(int ivSize)
        {
            using var p = new PackageProtector(ivSize: ivSize);
        }

        [TestMethod]
        // Zero IV
        [DataRow(0, 0)]
        [DataRow(0, 15)]
        [DataRow(0, 16)]
        [DataRow(0, 17)]
        [DataRow(0, 32)]
        [DataRow(0, 47)]
        [DataRow(0, 49)]
        [DataRow(0, 63)]
        [DataRow(0, 65)]
        [DataRow(0, 120)]
        [DataRow(0, MaxPackageSize + 1)]
        // 16 bytes IV
        [DataRow(16, 0)]
        [DataRow(16, 15)]
        [DataRow(16, 16)]
        [DataRow(16, 17)]
        [DataRow(16, 32)]
        [DataRow(16, 47)]
        [DataRow(16, 49)]
        [DataRow(16, 63)]
        [DataRow(16, 65)]
        [DataRow(16, 120)]
        [DataRow(16, MaxPackageSize + 1)]
        // 32 bytes IV
        [DataRow(32, 0)]
        [DataRow(32, 15)]
        [DataRow(32, 16)]
        [DataRow(32, 17)]
        [DataRow(32, 32)]
        [DataRow(32, 47)]
        [DataRow(32, 49)]
        [DataRow(32, 63)]
        [DataRow(32, 65)]
        [DataRow(32, 120)]
        [DataRow(32, MaxPackageSize + 1)]
        public void NewPackageProtectorInvalidPackageSizeFail(int ivSize, int packageSize)
        {
            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => new PackageProtector(ivSize: ivSize, packageSize: packageSize));

            Assert.AreEqual(nameof(packageSize), ex.ParamName);
        }

        [TestMethod]
        // Zero IV
        [DataRow(0, 48)]
        [DataRow(0, 64)]
        [DataRow(0, 64 * 1024)]
        [DataRow(0, MaxPackageSize - BlockSize)]
        // 16 bytes IV
        [DataRow(16, 64)]
        [DataRow(16, 80)]
        [DataRow(16, 64 * 1024)]
        [DataRow(16, MaxPackageSize - BlockSize)]
        // 32 bytes IV
        [DataRow(32, 80)]
        [DataRow(32, 96)]
        [DataRow(32, 64 * 1024)]
        [DataRow(32, MaxPackageSize - BlockSize)]
        public void NewPackageProtectorValidPackageSizePass(int ivSize, int packageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            int overhead = ivSize + HashSize + 1;

            int maxContentSize = packageSize - overhead;

            Assert.AreEqual(packageSize, p.MaxPackageSize, nameof(p.MaxPackageSize));
            Assert.AreEqual(maxContentSize, p.MaxContentSize, nameof(p.MaxContentSize));

            Assert.AreEqual(overhead, p.MaxPackageSize - p.MaxContentSize, $"{nameof(p.MaxPackageSize)} - {nameof(p.MaxContentSize)}");
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(16)]
        [DataRow(31)]
        [DataRow(65)]
        [DataRow(128)]
        public void ProtectInvalidKeySizeFail(int keySize)
        {
            using var p = new PackageProtector(packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[keySize], 0, null));
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(16)]
        [DataRow(31)]
        [DataRow(65)]
        [DataRow(128)]
        public void UnprotectInvalidKeySizeFail(int keySize)
        {
            using var p = new PackageProtector(packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Unprotect(package, package, new byte[keySize], 0, null));
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        public void ProtectNullKeyFail()
        {
            using var p = new PackageProtector(packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<ArgumentNullException>(() => p.Protect(content, package, null, 0, null));
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        public void UnprotectNullKeyFail()
        {
            using var p = new PackageProtector(packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<ArgumentNullException>(() => p.Unprotect(package, package, null, 0, null));
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(16)]
        [DataRow(32)]
        public void ProtectRngActionCallbackPass(int ivSize)
        {
            byte[] rngVal = Array.Empty<byte>();

            RngFillAction rng = (Span<byte> data) =>
            {
                if (data.Length == 0 || rngVal.Length != 0)
                {
                    throw new AssertFailedException("Callback is not operating properly.");
                }

                rngVal = new byte[data.Length].Fill((byte)data.Length);

                rngVal.AsSpan().CopyTo(data);
            };

            using var protector = new PackageProtector(ivSize: ivSize, packageSize: 128, rngFill: rng);

            var content = new byte[1].Fill(100);
            var package = new byte[protector.MaxPackageSize];

            protector.Protect(content, package, new byte[32], 0, null);

            Assert.AreEqual(ivSize, rngVal.Length);

            var pkgIV = new ArraySegment<byte>(package, 0, ivSize).ToArray();

            CollectionAssert.AreEqual(rngVal, pkgIV);
        }

        [TestMethod]
        public void ProtectInvalidPackageNumberFail()
        {
            using var p = new PackageProtector(packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[32], -1, null));
            Assert.AreEqual("packageNumber", ex.ParamName);
        }

        [TestMethod]
        public void UnprotectInvalidPackageNumberFail()
        {
            using var p = new PackageProtector(packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Unprotect(package, package, new byte[32], -1, null));
            Assert.AreEqual("packageNumber", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0, 33)]
        [DataRow(16, 17)]
        [DataRow(32, 1)]
        public void ProtectInvalidAssociatedDataFail(int ivSize, int associatedDataSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[32], long.MaxValue, new byte[associatedDataSize]));
            Assert.AreEqual("associatedData", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0, 33)]
        [DataRow(16, 17)]
        [DataRow(32, 1)]
        public void UnprotectInvalidAssociatedDataSizeFail(int ivSize, int associatedDataSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Unprotect(package, package, new byte[32], long.MaxValue, new byte[associatedDataSize]));
            Assert.AreEqual("associatedData", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0, 48)]
        [DataRow(16, 64)]
        [DataRow(32, 80)]
        public void ProtectInvalidPackageSizeFail(int ivSize, int packageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize - 1];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[32], long.MaxValue, null));
            Assert.AreEqual("package", ex.ParamName);
            Assert.AreEqual($"Insufficient space for package output. (Parameter 'package')", ex.Message);
        }

        [TestMethod]
        [DataRow(0, 48)]
        [DataRow(16, 64)]
        [DataRow(32, 80)]
        public void ProtectInvalidContentSizeFail(int ivSize, int packageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var content = new byte[p.MaxContentSize + 1];
            var package = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(content, package, new byte[32], long.MaxValue, null));
            Assert.AreEqual("content", ex.ParamName);
            Assert.AreEqual($"Content cannot be larger than '{p.MaxContentSize}' bytes. (Parameter 'content')", ex.Message);
        }

        [TestMethod]
        [DataRow(0, 48)]
        [DataRow(16, 64)]
        [DataRow(32, 80)]
        public void UnprotectInvalidContentSizeSizeFail(int ivSize, int packageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var package = new byte[p.MaxPackageSize];

            var content = new byte[p.MaxPackageSize - 1];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Unprotect(package, content, new byte[32], long.MaxValue, null));
            Assert.AreEqual("content", ex.ParamName);
            Assert.AreEqual("Insufficient space for content output. (Parameter 'content')", ex.Message);
        }

        [TestMethod]
        [DataRow(0, 48, 47)]
        [DataRow(0, 48, 49)]
        [DataRow(16, 64, 63)]
        [DataRow(16, 64, 65)]
        [DataRow(32, 80, 79)]
        [DataRow(32, 80, 81)]
        public void UnprotectInvalidPackageSizeFail(int ivSize, int packageSize, int invalidPackageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var package = new byte[invalidPackageSize];

            var content = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<BadPackageException>(() => p.Unprotect(package, content, new byte[32], 0, null));
            Assert.AreEqual($"Package size must be {packageSize} bytes.", ex.Message);
        }

        [TestMethod]
        [DataRow(0, 48 + 16, 48 + 16 - 1)]
        [DataRow(0, 48 + 16, 48 + 16 + 1)]
        [DataRow(16, 64 + 16, 64 + 16 - 1)]
        [DataRow(16, 64 + 16, 64 + 16 + 1)]
        [DataRow(32, 80 + 16, 80 + 16 - 1)]
        [DataRow(32, 80 + 16, 80 + 16 + 1)]
        public void UnprotectInvalidPackageSize2Fail(int ivSize, int packageSize, int invalidPackageSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: packageSize);

            var package = new byte[invalidPackageSize];

            var content = new byte[p.MaxPackageSize];

            var ex = Assert.ThrowsException<BadPackageException>(() => p.Unprotect(package, content, new byte[32], 0, null));
            Assert.AreEqual($"Package size must be between {packageSize - 16} and {packageSize} bytes and aligned on a 16 byte boundary.", ex.Message);
        }

        [TestMethod]
        public void ProtectNullOrDefaultContentPass()
        {
            using var p = new PackageProtector(packageSize: 128);

            p.Protect(null, new byte[128], new byte[32], 0, new byte[1]);
            p.Protect(default, new byte[128], new byte[32], 0, new byte[1]);
            p.Protect(ArraySegment<byte>.Empty, new byte[128], new byte[32], 0, new byte[1]);
        }

        [TestMethod]
        public void ProtectNullOrDefaultAssociatedDataPass()
        {
            using var p = new PackageProtector(packageSize: 128);

            p.Protect(new byte[1], new byte[128], new byte[32], 0, null);
            p.Protect(new byte[1], new byte[128], new byte[33], 0, default);
            p.Protect(new byte[1], new byte[128], new byte[64], 0, ArraySegment<byte>.Empty);
        }

        [TestMethod]
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

        [TestMethod]
        [DataRow(0, 48, 0)]
        [DataRow(0, 48 + BlockSize, 0)]
        [DataRow(0, MaxPackageSize, 0)]
        [DataRow(0, 48, 16)]
        [DataRow(0, 48 + BlockSize, 16)]
        [DataRow(0, MaxPackageSize, 16)]
        [DataRow(0, 48, 32)]
        [DataRow(0, 48 + BlockSize, 32)]
        [DataRow(0, MaxPackageSize, 32)]
        //
        [DataRow(16, 64, 0)]
        [DataRow(16, 64 + BlockSize, 0)]
        [DataRow(16, MaxPackageSize, 0)]
        [DataRow(16, 64, 16)]
        [DataRow(16, 64 + BlockSize, 16)]
        [DataRow(16, MaxPackageSize, 16)]
        //
        [DataRow(32, 80, 0)]
        [DataRow(32, 80 + BlockSize, 0)]
        [DataRow(32, MaxPackageSize, 0)]
        public void RoundTripFullPackagePass(int ivSize, int packageSize, int associatedDataSize)
        {
            var key = new byte[64].Fill(4);
            var associatedData = new byte[associatedDataSize].Fill((byte)associatedDataSize);

            using (var protector = new PackageProtector(ivSize, packageSize))
            {
                var content = new ArraySegment<byte>(new byte[protector.MaxContentSize].Fill(7));

                var package = new ArraySegment<byte>(new byte[packageSize]);

                var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

                Assert.AreEqual<int>(packageSize, bytesProtected);

                var unprotectedContent = new ArraySegment<byte>(new byte[packageSize]);

                var bytesUnprotected = protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData);

                Assert.AreEqual<int>(content.Count, bytesUnprotected);

                CollectionAssert.AreEqual(content.Array, unprotectedContent.Slice(0, bytesUnprotected).ToArray());
            }
        }

        [TestMethod]
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

                    Assert.AreEqual<int>(MinPackageSize, bytesProtected);

                    var unprotectedContent = new ArraySegment<byte>(new byte[packageSize]);

                    var bytesUnprotected = protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData);

                    Assert.AreEqual<int>(content.Count, bytesUnprotected);

                    CollectionAssert.AreEqual(content.Array, unprotectedContent.Slice(0, bytesUnprotected).ToArray());
                }
            }
        }

        [TestMethod]
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

                Assert.AreEqual<int>(content.Count, bytesUnprotected);

                CollectionAssert.AreEqual(content.Slice(0, contentSize).ToArray(), unprotectedContent.Slice(0, bytesUnprotected).ToArray());

                Array.Clear(packageBuffer, 0, packageBuffer.Length);
                Array.Clear(unprotectedContentBuffer, 0, unprotectedContentBuffer.Length);
            }
        }

        [TestMethod]
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

            CollectionAssert.AreNotEqual(masterKey, sigKey);
            CollectionAssert.AreNotEqual(masterKey, encKey);

            CollectionAssert.AreNotEqual(encKey, sigKey);
        }

        [TestMethod]
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

                    CollectionAssert.AreNotEqual(masterKey, sigKey);
                    CollectionAssert.AreNotEqual(masterKey, encKey);

                    CollectionAssert.AreNotEqual(encKey, sigKey);
                }
            }
        }

        [TestMethod]
        public void DeriveKeysBadIVSizeFail()
        {
            var masterKey = new byte[32].Fill(31);

            var encKey = new byte[32];
            var sigKey = new byte[32];

            using (var hmac = new HMACSHA256(masterKey))
            {
                Assert.ThrowsException<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[33], new byte[0], encKey, sigKey));
                Assert.ThrowsException<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[0], new byte[33], encKey, sigKey));

                Assert.ThrowsException<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[32], new byte[1], encKey, sigKey));
                Assert.ThrowsException<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[1], new byte[32], encKey, sigKey));

                Assert.ThrowsException<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[17], new byte[16], encKey, sigKey));
                Assert.ThrowsException<ArgumentException>(() => PackageProtector.DeriveKeys(hmac, 42, 4096, new byte[16], new byte[17], encKey, sigKey));
            }
        }

        [TestMethod]
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

                CollectionAssert.AreEqual(expectedEncKey, encKey);
                CollectionAssert.AreEqual(expectedSigKey, sigKey);
            }
        }

        [TestMethod]
        public void UnprotectWrongKeyFail()
        {
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize - 8].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            key[31] ^= 1; // make wrong key

            Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));
        }

        [TestMethod]
        public void UnprotectWrongPackageNumberFail()
        {
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize - 7].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 6, associatedData));
        }

        [TestMethod]
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

            Assert.ThrowsException<BadPackageException>(() => protector1.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));
        }

        [TestMethod]
        public void UnprotectWrongAssociatedDataFail()
        {
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(4);

            var associatedData = new ArraySegment<byte>(new byte[13].Fill(7));

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize - 3].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected = protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            // wrong length test
            Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData.Slice(1)));

            associatedData[0] ^= 1; // produce wrong associated data
            Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData));
        }

        [TestMethod]
        public void UnprotectCorruptedPackageFail()
        {
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[protector.MaxContentSize].Fill(9));

            var package = new ArraySegment<byte>(new byte[protector.MaxPackageSize]);

            var bytesProtected =protector.Protect(content, package, key, 5, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            foreach (var i in new int[] { 0, 15, 16, 31, 32, 47, 48, 63})
            {
                package[i] ^= 1;

                Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, associatedData), "Didn't throw for byte index '{0}'.", i);

                package[i] ^= 1;
            }
        }

        [TestMethod]
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
                    // Decrypt to package itself
                    dec.TransformBlock(package.Array, BlockSize, MinPackageSize - BlockSize, package.Array, BlockSize);
                }

                // Verify decrypted payload
                CollectionAssert.AreEqual(content.Array, package.Slice(BlockSize + HashSize, content.Count).ToArray());

                using (var hmac = new HMACSHA256(sigKey))
                {
                    var hash = hmac.ComputeHash(package.Array, BlockSize + HashSize, MinPackageSize - BlockSize - HashSize);

                    // Verify original hash - should pass
                    CollectionAssert.AreEqual(hash, package.Slice(BlockSize, HashSize).ToArray());

                    // Set invalid padding
                    package[MinPackageSize - 1] = 2;

                    // Compute new mac on data with corrupted padding
                    if (!hmac.TryComputeHash(package.Slice(BlockSize + HashSize, MinPackageSize - BlockSize - HashSize), package.Slice(BlockSize, HashSize), out _))
                    {
                        throw new CryptographicUnexpectedOperationException();
                    }
                }

                using (var enc = aes.CreateEncryptor(encKey, ZeroIV))
                {
                    // Encrypt to package itself the corrupted padding with valid mac
                    enc.TransformBlock(package.Array, BlockSize, MinPackageSize - BlockSize, package.Array, BlockSize);
                }
            }

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package, unprotectedContent, key, 5, associatedData));
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

                hmac.DeriveKey(label, context, derivedKey);

                return derivedKey;
            }
        }

        [TestMethod]
        public void DotNETArraySegmentAssumptionsPass()
        {
            Assert.AreEqual(null, ((ArraySegment<byte>)null).Array);
            Assert.AreEqual(0, ((ArraySegment<byte>)null).Count);
            Assert.AreEqual(0, ((ArraySegment<byte>)null).Offset);

            Assert.AreEqual(null, default(ArraySegment<byte>).Array);
            Assert.AreEqual(0, default(ArraySegment<byte>).Count);
            Assert.AreEqual(0, default(ArraySegment<byte>).Offset);

            Assert.AreNotEqual(null, ArraySegment<byte>.Empty.Array);
            Assert.AreEqual(0, ArraySegment<byte>.Empty.Count);
            Assert.AreEqual(0, ArraySegment<byte>.Empty.Offset);

            Assert.AreEqual(0, ArraySegment<byte>.Empty.Array.Length);
        }
    }
}