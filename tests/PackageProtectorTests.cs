// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverageAttribute]
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

        [TestMethod]
        public void ProtectInvalidArgsFail()
        {
            ArgumentException ex;

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Protect(new byte[MaxContentSize + 1], new byte[MaxPackageSize], new byte[HashSize], 0, MaxPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("content", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Protect(new byte[MaxContentSize], new byte[MaxPackageSize - 1], new byte[HashSize], 0, MaxPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("package", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentNullException>(() => PackageProtector.Protect(Array.Empty<byte>(), new byte[MinPackageSize], null, 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[0], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[31], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[65], 0, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[HashSize], -1, MinPackageSize, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("packageNumber", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[HashSize], 0, MinPackageSize - 1, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[HashSize], 0, MaxPackageSize + 1, ArraySegment<byte>.Empty));
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => PackageProtector.Protect(Array.Empty<byte>(), new byte[MinPackageSize], new byte[HashSize], 0, MinPackageSize, new byte[BlockSize + 1]));
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

        [TestMethod]
        public void ProtectNullOrDefaultContentPass()
        {
            PackageProtector.Protect(null, new byte[128], new byte[32], 0, 128, new byte[1]);
            PackageProtector.Protect(default, new byte[128], new byte[32], 0, 128, new byte[1]);
            PackageProtector.Protect(ArraySegment<byte>.Empty, new byte[128], new byte[32], 0, 128, new byte[1]);
        }

        [TestMethod]
        public void ProtectNullOrDefaultAssociatedDataPass()
        {
            PackageProtector.Protect(new byte[1], new byte[128], new byte[32], 0, 128, null);
            PackageProtector.Protect(new byte[1], new byte[128], new byte[33], 0, 128, default);
            PackageProtector.Protect(new byte[1], new byte[128], new byte[64], 0, 128, ArraySegment<byte>.Empty);
        }

        [TestMethod]
        public void UnprotectNullOrDefaultAssociatedDataPass()
        {
            var p = new byte[64];
            var c = new byte[64];
            PackageProtector.Protect(default, p, new byte[32], 0, 64, default);

            PackageProtector.Unprotect(p, c, new byte[32], 0, 64, null);
            PackageProtector.Unprotect(p, c, new byte[32], 0, 64, default);
            PackageProtector.Unprotect(p, c, new byte[32], 0, 64, ArraySegment<byte>.Empty);
        }

        [TestMethod]
        public void RoundTripFullPackagePass()
        {
            var key = new byte[64].Fill(4);
            var associatedData = new byte[13].Fill(4);

            foreach (var packageSize in new int[] { MinPackageSize, MinPackageSize + BlockSize, MaxPackageSize })
            {
                var content = new ArraySegment<byte>(new byte[packageSize - Overhead].Fill(7));

                var package = new ArraySegment<byte>(new byte[packageSize]);

                var bytesProtected = PackageProtector.Protect(content, package, key, 5, packageSize, associatedData);

                Assert.AreEqual<int>(packageSize, bytesProtected);

                var unprotectedContent = new ArraySegment<byte>(new byte[packageSize]);

                var bytesUnprotected = PackageProtector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, packageSize, associatedData);

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
                var content = ArraySegment<byte>.Empty;

                var package = new ArraySegment<byte>(new byte[MinPackageSize]);

                var bytesProtected = PackageProtector.Protect(content, package, key, 5, packageSize, associatedData);

                Assert.AreEqual<int>(MinPackageSize, bytesProtected);

                var unprotectedContent = new ArraySegment<byte>(new byte[packageSize]);

                var bytesUnprotected = PackageProtector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, packageSize, associatedData);

                Assert.AreEqual<int>(content.Count, bytesUnprotected);

                CollectionAssert.AreEqual(content.Array, unprotectedContent.Slice(0, bytesUnprotected).ToArray());
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

            for (int contentSize = PackageSize - Overhead; contentSize >= 0; contentSize--)
            {
                var content = new ArraySegment<byte>(contentBuffer, 0, contentSize);
                var package = new ArraySegment<byte>(packageBuffer);

                var bytesProtected = PackageProtector.Protect(content, package, key, 5, PackageSize, associatedData);

                var unprotectedContent = new ArraySegment<byte>(unprotectedContentBuffer);

                var bytesUnprotected = PackageProtector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, PackageSize, associatedData);

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
            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead - 8].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

            var bytesProtected = PackageProtector.Protect(content, package, key, 5, MinPackageSize, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            key[31] ^= 1; // make wrong key

            Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, MinPackageSize, associatedData));
        }

        [TestMethod]
        public void UnprotectWrongPackageNumberFail()
        {
            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead - 7].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

            var bytesProtected = PackageProtector.Protect(content, package, key, 5, MinPackageSize, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 6, MinPackageSize, associatedData));
        }

        [TestMethod]
        public void UnprotectWrongPackageSizeFail()
        {
            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead - 5].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

            var bytesProtected = PackageProtector.Protect(content, package, key, 5, MinPackageSize, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, MinPackageSize + BlockSize, associatedData));
        }

        [TestMethod]
        public void UnprotectWrongAssociatedDataFail()
        {
            var key = new byte[32].Fill(4);

            var associatedData = new ArraySegment<byte>(new byte[13].Fill(7));

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead - 3].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

            var bytesProtected = PackageProtector.Protect(content, package, key, 5, MinPackageSize, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            // wrong length test
            Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, MinPackageSize, associatedData.Slice(1)));

            associatedData[0] ^= 1; // produce wrong associated data
            Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, MinPackageSize, associatedData));
        }

        [TestMethod]
        public void UnprotectCorruptedPackageFail()
        {
            var key = new byte[32].Fill(4);
            var associatedData = new byte[13].Fill(7);

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead].Fill(9));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

            var bytesProtected = PackageProtector.Protect(content, package, key, 5, MinPackageSize, associatedData);

            var unprotectedContent = new ArraySegment<byte>(new byte[MinPackageSize]);

            foreach (var i in new int[] { 0, 15, 16, 31, 32, 47, 48, 63})
            {
                package[i] ^= 1;

                Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(package.Slice(0, bytesProtected), unprotectedContent, key, 5, MinPackageSize, associatedData), "Didn't throw for byte index '{0}'.", i);

                package[i] ^= 1;
            }
        }

        [TestMethod]
        public void UnprotectGoodMacBadPadFail()
        {
            var key = new byte[32].Fill(93);
            var associatedData = new byte[13].Fill(56);

            var content = new ArraySegment<byte>(new byte[MinPackageSize - Overhead].Fill(231));

            var package = new ArraySegment<byte>(new byte[MinPackageSize]);

            PackageProtector.Protect(content, package, key, 5, MinPackageSize, associatedData);

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

            Assert.ThrowsException<BadPackageException>(() => PackageProtector.Unprotect(package, unprotectedContent, key, 5, MinPackageSize, associatedData));
        }

        private static byte[] DeriveKey32(byte[] masterKey, bool encrypt, long packageNumber, int packageSize, ReadOnlySpan<byte> kdfIV, ReadOnlySpan<byte> associatedData)
        {
            byte purpose = encrypt ? (byte)0xff : (byte)0x00;

            var context = new byte[55];
            var data = (Span<byte>)context;

            using (var hmac = new HMACSHA256(masterKey))
            {
                data[3] = 1;
                data[5] = purpose;
                data[6] = (byte)associatedData.Length;

                data[8] = (byte)(packageNumber >> 56);
                data[9] = (byte)(packageNumber >> 48);
                data[10] = (byte)(packageNumber >> 40);
                data[11] = (byte)(packageNumber >> 32);
                data[12] = (byte)(packageNumber >> 24);
                data[13] = (byte)(packageNumber >> 16);
                data[14] = (byte)(packageNumber >> 8);
                data[15] = (byte)packageNumber;

                kdfIV.CopyTo(data.Slice(16, 16));

                var destAD = data.Slice(32, 16);
                destAD.Clear();

                associatedData.CopyTo(destAD);

                data[48] = (byte)(packageSize >> 16);
                data[49] = (byte)(packageSize >> 8);
                data[50] = (byte)packageSize;

                data[53] = 1;

                return hmac.ComputeHash(context);
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