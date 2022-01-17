﻿// This is free and unencumbered software released into the public domain.
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
        private const int MaxContentSize = MaxPackageSize - Overhead;
        private const int Overhead = BlockSize + HashSize + 1;

        private static byte[] ZeroIV = new byte[BlockSize];

        /*
        [TestMethod]
        public void ProtectInvalidArgsFail()
        {
            using var p = new PackageProtector();

            ArgumentException ex;

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(new byte[MaxContentSize + 1], new byte[MaxPackageSize], new byte[HashSize], 0, MaxPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("content", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(new byte[MaxContentSize], new byte[MaxPackageSize - 1], new byte[HashSize], 0, MaxPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("package", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentNullException>(() => p.Protect(Array.Empty<byte>(), new byte[MinPackageSize], null, 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[0], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[31], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[65], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[HashSize], -1, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("packageNumber", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[HashSize], 0, MinPackageSize - 1, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[HashSize], 0, MaxPackageSize + 1, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => p.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[HashSize], 0, MinPackageSize, new byte[BlockSize + 1]));
            Assert.AreEqual<string>("associatedData", ex.ParamName);
        }

        [TestMethod]
        public void UnprotectInvalidArgsFail()
        {
            ArgumentException ex;

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Unprotect(new byte[MinPackageSize], new byte[MinPackageSize - 1], new byte[HashSize], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("content", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentNullException>(() => PackageProtector.Unprotect(new byte[MinPackageSize], new byte[MinPackageSize], null, 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Unprotect(new byte[MinPackageSize], new byte[MinPackageSize], new byte[0], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Unprotect(new byte[MinPackageSize], new byte[MinPackageSize], new byte[31], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Unprotect(new byte[MinPackageSize], new byte[MinPackageSize], new byte[65], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Unprotect(new byte[MinPackageSize], new byte[MinPackageSize], new byte[HashSize], -1, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("packageNumber", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Unprotect(new byte[MinPackageSize], new byte[MinPackageSize], new byte[HashSize], 0, MinPackageSize - 1, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Unprotect(new byte[MinPackageSize], new byte[MinPackageSize], new byte[HashSize], 0, MaxPackageSize + 1, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Unprotect(new byte[MinPackageSize], new byte[MinPackageSize], new byte[HashSize], 0, MinPackageSize, new byte[BlockSize + 1]));
            Assert.AreEqual<string>("associatedData", ex.ParamName);

            var badPackageEx = Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(new byte[MinPackageSize - 1], new byte[MinPackageSize], new byte[HashSize], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreNotEqual<string>(badPackageEx.Message, new BadPackageException().Message);

            badPackageEx = Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(new byte[MaxPackageSize + 1], new byte[MinPackageSize], new byte[HashSize], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreNotEqual<string>(badPackageEx.Message, new BadPackageException().Message);

            badPackageEx = Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(new byte[MinPackageSize * 2], new byte[MinPackageSize], new byte[HashSize], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreNotEqual<string>(badPackageEx.Message, new BadPackageException().Message);

            badPackageEx = Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(new byte[MinPackageSize * 2 + 1], new byte[MinPackageSize * 2], new byte[HashSize], 0, MinPackageSize * 2, ArraySegment<byte>.Empty));
            Assert.AreNotEqual<string>(badPackageEx.Message, new BadPackageException().Message);
        }
        */

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

            for (int contentSize = PackageSize - Overhead; contentSize >= 0; contentSize--)
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

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead - 8].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

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

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead - 7].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

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

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead - 5].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

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

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead - 3].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

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

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

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
            using var protector = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(93);
            var associatedData = new byte[13].Fill(56);

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead].Fill(231));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

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