// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    [TestClass]
    public class KeyProtectorTests
    {
        private const int MaxContentSize = 65424;
        private const int ChecksumSize = 16;
        private const int Overhead = 96;

        private static ReadOnlySpan<byte> Version => new byte[] { (byte)'P', (byte)'B', (byte)'2', (byte)'K' };

        [TestMethod]
        [DataRow(32)]
        [DataRow(64)]
        [DataRow(MaxContentSize)]
        public void RoundTripPass(int contentLength)
        {
            var password = "user-password#3";
            var iterations = 1;

            using var protector = new KeyProtector();

            var content = new byte[contentLength];

            var package = new byte[content.Length + protector.Overhead];

            int protectedLength = protector.Protect(content, package, password, iterations);

            Assert.AreEqual(package.Length, protectedLength);

            var unprotectedContent = new byte[content.Length];

            int unprotectedLength = protector.Unprotect(package, unprotectedContent, password);

            Assert.AreEqual(unprotectedContent.Length, unprotectedLength);

            CollectionAssert.AreEquivalent(content, unprotectedContent);
        }

        [TestMethod]
        [DataRow(32, (byte)3)] // min content length
        [DataRow(48, (byte)1)]
        [DataRow(64, (byte)5)]
        [DataRow(192, (byte)8)]
        [DataRow(MaxContentSize, (byte)2)]
        public void ProtectProducesCorrectFormatPass(int contentLength, byte iterations)
        {
            var password = "user-password";

            ReadOnlySpan<byte> iterSpanExpected = stackalloc byte[4] { 0, 0, 0, iterations };

            byte fillByte = (byte)(100 + iterations);

            RngFillAction rng = (Span<byte> data) =>
            {
                data.Fill(fillByte);
            };

            using var protector = new KeyProtector(rng);

            const byte contentByte = 226;

            ReadOnlySpan<byte> content = new byte[contentLength].Fill(contentByte);

            byte[] package = new byte[content.Length + protector.Overhead];
            Span<byte> packageSpan = package;

            int protectedLength = protector.Protect(content, packageSpan, password, iterations);

            Assert.AreEqual(packageSpan.Length, protectedLength);

            Assert.IsTrue(packageSpan.Slice(0, 4).SequenceEqual(Version));

            var iterSpan = packageSpan.Slice(4, 4);
            int iter = (int)BinaryPrimitives.ReadUInt32BigEndian(iterSpan);

            Assert.AreEqual(iterations, iter);

            Assert.IsTrue(iterSpan.SequenceEqual(iterSpanExpected));

            var salt = packageSpan.Slice(8, 40);

            Assert.IsTrue(salt.IsAllSameValue(fillByte));

            int checksumOffset = protectedLength - ChecksumSize;

            Span<byte> checksumHash = new byte[64];

            SHA512.HashData(packageSpan.Slice(0, checksumOffset), checksumHash);

            Assert.AreEqual(true, packageSpan.Slice(checksumOffset).SequenceEqual(checksumHash.Slice(0, ChecksumSize)));

            var encoder = new UTF8Encoding(false, true);

            byte[] passBytes = encoder.GetBytes(password);

            byte[] derivedKey = Rfc2898DeriveBytes.Pbkdf2(passBytes, salt, iter, HashAlgorithmName.SHA512, 64);

            byte[] encLabel = encoder.GetBytes("AES256-CBC");
            byte[] macLabel = encoder.GetBytes("HMAC-SHA512");

            byte[] encKey = new byte[32];
            byte[] macKey = new byte[64];

            using (var hmac = new HMACSHA512(derivedKey))
            {
                hmac.DeriveKey(encLabel, null,  encKey);
            }

            using (var hmac = new HMACSHA512(derivedKey))
            {
                hmac.DeriveKey(macLabel, null, macKey);
            }

            ReadOnlySpan<byte> expectedContentHash = null;

            using (var hmac = new HMACSHA512(macKey))
            {
                var contentHash = new byte[64];
                
                hmac.ComputeHash(content, contentHash);

                expectedContentHash = new ReadOnlySpan<byte>(contentHash).Slice(0, 32);
            }

            byte[] decryptedHashAndContent = new byte[32 + contentLength];

            var decryptedHash = ((ReadOnlySpan<byte>)decryptedHashAndContent).Slice(0, 32);
            var decryptedContent = ((ReadOnlySpan<byte>)decryptedHashAndContent).Slice(32);

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (var dec = aes.CreateDecryptor(encKey, new byte[16])) // zero IV
                {
                    int bytesDecrypted = dec.TransformBlock(package, 4 + 4 + 40, decryptedHashAndContent.Length, decryptedHashAndContent, 0);

                    Assert.AreEqual(decryptedHashAndContent.Length, bytesDecrypted);
                }
            }

            Assert.IsTrue(expectedContentHash.SequenceEqual(decryptedHash), "Hash doesn't match.");

            Assert.IsTrue(content.SequenceEqual(decryptedContent), "Content doesn't match.");
        }

        [TestMethod]
        public void IncorrectPasswordFails()
        {
            var iterations = 1;

            using var protector = new KeyProtector();

            var content = new byte[32].Fill(223);

            var package = new byte[content.Length + protector.Overhead];

            protector.Protect(content, package, "user-password", iterations);

            var unprotectedContent = new byte[content.Length].Fill(88);

            var ex = Assert.ThrowsException<CryptographicException>(() => protector.Unprotect(package, unprotectedContent, "bad-user-password"));
            Assert.AreEqual("The provided password is incorrect.", ex.Message);

            Assert.IsTrue(unprotectedContent.IsAllZeros(), "Destination not cleared on Protect() failure.");
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(16)]
        [DataRow(31)] // min content length - 1
        [DataRow(33)]
        [DataRow(47)]
        [DataRow(MaxContentSize + 1)]
        public void ProtectBadContentSizeFails(int contentLength)
        {
            var password = "user-password";
            var iterations = 2;

            using var protector = new KeyProtector();

            var content = new byte[contentLength];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, iterations));

            Assert.AreEqual("content", ex.ParamName);
            Assert.AreEqual("Content length is invalid or not aligned on the required boundary. (Parameter 'content')", ex.Message);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(32 + Overhead - 1)]
        [DataRow(32 + Overhead + 1)]
        [DataRow(MaxContentSize + Overhead - 1)]
        [DataRow(MaxContentSize + Overhead + 1)]
        public void UnprotectBadPackageSizeFails(int packageSize)
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var package = new byte[packageSize];

            var content = new byte[packageSize];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => protector.Unprotect(package, content, password));

            Assert.AreEqual("package", ex.ParamName);
            Assert.AreEqual("Package length is invalid or not aligned on the required boundary. (Parameter 'package')", ex.Message);
        }

        [TestMethod]
        public void ProtectBadPackageSpaceFails()
        {
            var password = "user-password";
            var iterations = 2;

            using var protector = new KeyProtector();

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead - 1];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, iterations));

            Assert.AreEqual("package", ex.ParamName);
            Assert.AreEqual("Insufficient space for package output. (Parameter 'package')", ex.Message);
        }

        [TestMethod]
        public void UnprotectBadContentSpaceFails()
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var package = new byte[32 + protector.Overhead];

            var context = new byte[package.Length - protector.Overhead - 1];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => protector.Unprotect(package, context, password));

            Assert.AreEqual("content", ex.ParamName);
            Assert.AreEqual("Insufficient space for content output. (Parameter 'content')", ex.Message);
        }

        [TestMethod]
        [DataRow(int.MinValue)]
        [DataRow(-1)]
        [DataRow(0)]
        public void ProtectBadIterationsFails(int iterations)
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, iterations));

            Assert.AreEqual("iterations", ex.ParamName);
        }

        [TestMethod]
        public void ProtectOverlapFails()
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var ex = Assert.ThrowsException<InvalidOperationException>(() =>
            {
                Span<byte> buf = new byte[32 + protector.Overhead + 32];

                var content = buf.Slice(32 + protector.Overhead, 32);

                var package = buf.Slice(1, 32 + protector.Overhead);

                protector.Protect(content, package, password, 1);
            });

            Assert.AreEqual("The 'package' must not overlap in memory with the 'content'.", ex.Message);
        }

        [TestMethod]
        public void UnprotectOverlapFails()
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var ex = Assert.ThrowsException<InvalidOperationException>(() =>
            {
                Span<byte> buf = new byte[32 + protector.Overhead + 32];

                var content = buf.Slice(32 + protector.Overhead, 32);

                var package = buf.Slice(1, 32 + protector.Overhead);

                protector.Unprotect(package, content, password);
            });

            Assert.AreEqual("The 'content' must not overlap in memory with the 'package'.", ex.Message);
        }

        [TestMethod]
        public void ProtectUseAfterDisposeFail()
        {
            using var protector = new KeyProtector();

            protector.Dispose();

            var password = "user-password";
            var iterations = 2;

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.ThrowsException<ObjectDisposedException>(() => protector.Protect(content, package, password, iterations));
            Assert.AreEqual(typeof(KeyProtector).FullName, ex.ObjectName);
        }

        [TestMethod]
        public void UnprotectUseAfterDisposeFail()
        {
            using var protector = new KeyProtector();

            protector.Dispose();

            var password = "user-password";

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.ThrowsException<ObjectDisposedException>(() => protector.Unprotect(package, content, password));
            Assert.AreEqual(typeof(KeyProtector).FullName, ex.ObjectName);
        }

        [TestMethod]
        public void ProtectClearOutputOnFailurePass()
        {
            var password = "user-password";
            var iterations = 1;

            const string exStr = "CRNG FAILED";

            RngFillAction rng = (Span<byte> data) =>
            {
                data.Fill((byte)data.Length);

                throw new Exception(exStr);
            };

            using var protector = new KeyProtector(rng);

            var content = new byte[32].Fill(223);
            var package = new byte[32 + protector.Overhead].Fill(88);

            var ex = Assert.ThrowsException<Exception>(() => protector.Protect(content, package, password, iterations));
            Assert.AreEqual(exStr, ex.Message);

            Assert.IsTrue(package.IsAllZeros(), "Destination not cleared on Protect() failure.");
        }

        [TestMethod]
        public void UnprotectClearOutputOnFailurePass()
        {
            var password = "user-password";
            var iterations = 1;

            RngFillAction rng = (Span<byte> data) =>
            {
                data.Fill((byte)data.Length);
            };

            using var protector = new KeyProtector(rng);

            var content = new byte[32].Fill(242);
            var package = new byte[32 + protector.Overhead];

            var packageSpan = package.AsSpan();

            protector.Protect(content, package, password, iterations);

            int checksumOffset = package.Length - ChecksumSize;

            package[checksumOffset - 1] ^= 1; // Intentionally corrupt last byte of encrypted payload

            Span<byte> checksumHash = new byte[64];

            SHA512.HashData(packageSpan.Slice(0, checksumOffset), checksumHash); // Recompute checksum over corrupted payload.

            checksumHash.Slice(0, ChecksumSize).CopyTo(packageSpan.Slice(checksumOffset));  // Replace checksum.

            var unprotectedContent = new byte[content.Length].Fill(byte.MaxValue);

            var ex = Assert.ThrowsException<CryptographicException>(() => protector.Unprotect(package, unprotectedContent, password));
            Assert.AreEqual("The provided password is incorrect.", ex.Message);

            Assert.IsTrue(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        [TestMethod]
        public void UnprotectClearOutputOnBadPasswordPass()
        {
            const string password = "user-password";
            const string badPassword = "user-Password";

            var iterations = 1;

            RngFillAction rng = (Span<byte> data) =>
            {
                data.Fill((byte)data.Length);
            };

            using var protector = new KeyProtector(rng);

            var content = new byte[32].Fill(242);
            var package = new byte[32 + protector.Overhead];

            var packageSpan = package.AsSpan();

            protector.Protect(content, package, password, iterations);

            var unprotectedContent = new byte[content.Length].Fill(byte.MaxValue);

            var ex = Assert.ThrowsException<CryptographicException>(() => protector.Unprotect(package, unprotectedContent, badPassword));
            Assert.AreEqual("The provided password is incorrect.", ex.Message);

            Assert.IsTrue(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() bad password.");
        }

        [TestMethod]
        [DataRow(int.MinValue)]
        [DataRow(-1)]
        [DataRow(0)]
        public void UnprotectBadIterationsFails(int iterations)
        {
            const string password = "user-password";
            const string badPassword = "user-Password";

            RngFillAction rng = (Span<byte> data) => data.Fill(97);

            using var protector = new KeyProtector(rng);

            var content = new byte[32].Fill(242);
            var package = new byte[32 + protector.Overhead];

            var packageSpan = package.AsSpan();

            protector.Protect(content, package, password, 1);

            BinaryPrimitives.WriteUInt32BigEndian(packageSpan.Slice(4, 4), (uint)iterations);

            var ex = Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package, content, badPassword));
            Assert.AreEqual("The package iterations count is invalid.", ex.Message);
        }

        [TestMethod]
        public void UnprotectVersionFails()
        {
            const string password = "user-password";
            const string badPassword = "user-Password";

            RngFillAction rng = (Span<byte> data) => data.Fill(97);

            using var protector = new KeyProtector(rng);

            var content = new byte[32].Fill(242);
            var package = new byte[32 + protector.Overhead];

            var packageSpan = package.AsSpan();

            protector.Protect(content, package, password, 1);

            // Write lowercase header version which is invalid.
            BinaryPrimitives.WriteUInt32BigEndian(packageSpan.Slice(0, 4), ((uint)'p' << 24) | ((uint)'b' << 16) | ((uint)'2' << 8) | (uint)'k');

            var ex = Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package, content, badPassword));
            Assert.AreEqual("The package version is invalid.", ex.Message);
        }

        [TestMethod]
        public void UnprotectBadChecksumFails()
        {
            const string password = "user-password";
            const string badPassword = "user-Password";

            RngFillAction rng = (Span<byte> data) => data.Fill(97);

            using var protector = new KeyProtector(rng);

            var content = new byte[32].Fill(242);
            var package = new byte[32 + protector.Overhead];

            var packageSpan = package.AsSpan();

            protector.Protect(content, package, password, 1);

            // Corrupt last byte of package/checksum
            package[^1] ^= 1;

            var ex = Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package, content, badPassword));
            Assert.AreEqual("The package checksum is invalid.", ex.Message);

            // Revert previous corruption.
            package[^1] ^= 1;

            // Corrupt first byte of salt.
            package[8] ^= 1;

            ex = Assert.ThrowsException<BadPackageException>(() => protector.Unprotect(package, content, badPassword));
            Assert.AreEqual("The package checksum is invalid.", ex.Message);
        }
    }
}