// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    public class KeyProtectorTests
    {
        private const int MaxContentSize = 65424;
        private const int ChecksumSize = 16;
        private const int Overhead = 96;

        private static ReadOnlySpan<byte> Version => new byte[] { (byte)'P', (byte)'B', (byte)'2', (byte)'K' };

        [Theory]
        [InlineData(0, 32, 0)]
        [InlineData(1, 48, 1)]
        [InlineData(64, 64, 32)]
        [InlineData(128, 64, 63)]
        [InlineData(1024, MaxContentSize, 64)]
        public void RoundTripPass(int passwordLength, int contentLength, int associatedDataLength)
        {
            var password = new string('p', passwordLength);
            var iterations = 1;

            var associatedData = new byte[associatedDataLength];

            using var protector = new KeyProtector();

            var content = new byte[contentLength];

            var package = new byte[content.Length + protector.Overhead];

            int protectedLength = protector.Protect(content, package, password, iterations, associatedData);

            Assert.Equal(package.Length, protectedLength);

            var unprotectedContent = new byte[content.Length];

            int unprotectedLength = protector.Unprotect(package, unprotectedContent, password, associatedData);

            Assert.Equal(unprotectedContent.Length, unprotectedLength);

            Assert.Equal(content, unprotectedContent);
        }

        [Theory]
        [InlineData(32, (byte)3, 0)]
        [InlineData(48, (byte)1, 1)]
        [InlineData(64, (byte)5, 32)]
        [InlineData(192, (byte)8, 63)]
        [InlineData(MaxContentSize, (byte)2, 64)]
        public void ProtectProducesCorrectFormatPass(int contentLength, byte iterations, int associatedDataLength)
        {
            var password = "user-password";

            var associatedData = (ReadOnlySpan<byte>)new byte[associatedDataLength].Fill((byte)(10 + iterations));

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

            int protectedLength = protector.Protect(content, packageSpan, password, iterations, associatedData);

            Assert.Equal(packageSpan.Length, protectedLength);

            Assert.True(packageSpan.Slice(0, 4).SequenceEqual(Version));

            var iterSpan = packageSpan.Slice(4, 4);
            int iter = (int)BinaryPrimitives.ReadUInt32BigEndian(iterSpan);

            Assert.Equal(iterations, iter);

            Assert.True(iterSpan.SequenceEqual(iterSpanExpected));

            var salt = (ReadOnlySpan<byte>)packageSpan.Slice(8, 40);

            Assert.True(salt.IsAllSameValue(fillByte));

            int checksumOffset = protectedLength - ChecksumSize;

            Span<byte> checksumHash = new byte[64];

            SHA512.HashData(packageSpan.Slice(0, checksumOffset), checksumHash);

            Assert.True(packageSpan.Slice(checksumOffset).SequenceEqual(checksumHash.Slice(0, ChecksumSize)), "Checksum doesn't match.");

            var key = (Span<byte>)new byte[128];
            var keySalt = packageSpan.Slice(0, 48);

            key[0] = 1;
            key[1] = 64;
            key[2] = (byte)keySalt.Length;
            key[3] = (byte)associatedDataLength;

            keySalt.CopyTo(key.Slice(4));
            associatedData.CopyTo(key.Slice(4 + keySalt.Length));

            var encoder = new UTF8Encoding(false, true);

            var passBytes = (ReadOnlySpan<byte>)encoder.GetBytes(password);
            var hashAndPassBytesBuf = new byte[64 + passBytes.Length];
            Span<byte> hashAndPassBytes = hashAndPassBytesBuf;
            passBytes.CopyTo(hashAndPassBytes.Slice(64));

            var prehashedPass = new byte[64];

            HMACSHA512.HashData(key, passBytes, hashAndPassBytes);
            HMACSHA512.HashData(key, hashAndPassBytes, prehashedPass);

            var pbkdf2Salt = encoder.GetBytes("PREHASHED PASSWORD ALREADY INCLUDES SALT AND ASSOCIATED DATA");

            byte[] derivedKey = Rfc2898DeriveBytes.Pbkdf2((Span<byte>)prehashedPass, pbkdf2Salt, iter, HashAlgorithmName.SHA512, 64);

            byte[] encLabel = encoder.GetBytes("AES256-CBC");
            byte[] macLabel = encoder.GetBytes("HMAC-SHA512-256");

            byte[] encKey = new byte[32];
            byte[] macKey = new byte[64];

            using (var hmac = new HMACSHA512(derivedKey))
            {
                hmac.DeriveKey(encKey, encLabel, null);
            }

            using (var hmac = new HMACSHA512(derivedKey))
            {
                hmac.DeriveKey(macKey, macLabel, null);
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

                using (var dec = aes.CreateDecryptor(encKey, new byte[16]))
                {
                    int bytesDecrypted = dec.TransformBlock(package, 4 + 4 + 40, decryptedHashAndContent.Length, decryptedHashAndContent, 0);

                    Assert.Equal(decryptedHashAndContent.Length, bytesDecrypted);
                }
            }

            Assert.True(expectedContentHash.SequenceEqual(decryptedHash), "Hash doesn't match.");

            Assert.True(content.SequenceEqual(decryptedContent), "Content doesn't match.");
        }

        [Theory]
        [InlineData("user-password", 1, 0, "bad-user-password", 1, 0, (byte)0, false)]
        [InlineData("", 1, 0, "b", 1, 0, (byte)0, false)]
        [InlineData("user-password", 1, 0, "user-password", 2, 0, (byte)0, false)]
        [InlineData("user-password", 1, 0, "user-password", 1, 1, (byte)0, false)]
        [InlineData("user-password", 1, 2, "user-password", 1, 2, (byte)1, false)]
        [InlineData("user-password", 1, 64, "user-password", 1, 64, (byte)3, false)]
        [InlineData("user-password", 1, 0, "user-password", 1, 0, (byte)0, true)]
        public void IncorrectParamsUnprotectFails(string protectPass, int protectIters, int protectAdLen, string unprotectPass, int unprotectIters, int unprotectAdLen, byte unprotectAdVal, bool unprotectBadSalt)
        {
            using var protector = new KeyProtector(rng => rng.Fill(33));

            var protectAd = new byte[protectAdLen];
            var unprotectAd = new byte[unprotectAdLen].Fill(unprotectAdVal);

            var content = new byte[32].Fill(223);

            var package = new byte[content.Length + protector.Overhead];

            var pkgSpan = package.AsSpan();

            protector.Protect(content, package, protectPass, protectIters, protectAd);

            if (protectIters != unprotectIters)
            {
                BinaryPrimitives.WriteUInt32BigEndian(pkgSpan.Slice(4), (uint)unprotectIters);
            }

            if (unprotectBadSalt)
            {
                pkgSpan[4 + 4] ^= 1;
            }

            if (protectIters != unprotectIters || unprotectBadSalt)
            {
                Span<byte> hash = new byte[64];

                SHA512.HashData(pkgSpan.Slice(0, pkgSpan.Length - 16), hash);

                hash.Slice(0, 16).CopyTo(pkgSpan.Slice(pkgSpan.Length - 16));
            }

            var unprotectedContent = new byte[content.Length].Fill(88);

            var ex = Assert.Throws<BadPasswordException>(() => protector.Unprotect(package, unprotectedContent, unprotectPass, unprotectAd));
            Assert.Equal("The provided password is incorrect.", ex.Message);

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Protect() failure.");
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(31)]
        [InlineData(33)]
        [InlineData(47)]
        [InlineData(MaxContentSize + 1)]
        public void ProtectBadContentSizeFails(int contentLength)
        {
            var password = "user-password";
            var iterations = 2;

            using var protector = new KeyProtector();

            var content = new byte[contentLength];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, iterations));

            Assert.Equal("content", ex.ParamName);
            Assert.Equal("Content length is invalid or not aligned on the required boundary. (Parameter 'content')", ex.Message);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(32 + Overhead - 1)]
        [InlineData(32 + Overhead + 1)]
        [InlineData(MaxContentSize + Overhead - 1)]
        [InlineData(MaxContentSize + Overhead + 1)]
        public void UnprotectBadPackageSizeFails(int packageSize)
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var package = new byte[packageSize];

            var content = new byte[packageSize];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => protector.Unprotect(package, content, password));

            Assert.Equal("package", ex.ParamName);
            Assert.Equal("Package length is invalid or not aligned on the required boundary. (Parameter 'package')", ex.Message);
        }

        [Fact]
        public void ProtectBadPackageSpaceFails()
        {
            var password = "user-password";
            var iterations = 2;

            using var protector = new KeyProtector();

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead - 1];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, iterations));

            Assert.Equal("package", ex.ParamName);
            Assert.Equal("Insufficient space for package output. (Parameter 'package')", ex.Message);
        }

        [Fact]
        public void UnprotectBadContentSpaceFails()
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var package = new byte[32 + protector.Overhead];

            var context = new byte[package.Length - protector.Overhead - 1];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => protector.Unprotect(package, context, password));

            Assert.Equal("content", ex.ParamName);
            Assert.Equal("Insufficient space for content output. (Parameter 'content')", ex.Message);
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
        public void ProtectBadIterationsFails(int iterations)
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, iterations));

            Assert.Equal("iterations", ex.ParamName);
        }

        [Theory]
        [InlineData(65)]
        public unsafe void ProtectBadAssociatedDataTooLargeFails(int associatedDataLength)
        {
            var password = "user-password";

            var ad = new byte[associatedDataLength];

            using var protector = new KeyProtector();

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, 1, ad));

            Assert.Equal("associatedData", ex.ParamName);
        }

        [Theory]
        [InlineData(65)]
        public unsafe void UnprotectBadAssociatedDataTooLargeFails(int associatedDataLength)
        {
            var password = "user-password";

            var ad = new byte[associatedDataLength];

            using var protector = new KeyProtector();

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => protector.Unprotect(package, content, password, ad));

            Assert.Equal("associatedData", ex.ParamName);
        }

        [Fact]
        public void ProtectOverlapFails()
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            int overhead = protector.Overhead;

            var ex = Assert.Throws<InvalidOperationException>(() =>
            {
                Span<byte> buf = new byte[32 + overhead + 32];

                var content = buf.Slice(32 + overhead, 32);

                var package = buf.Slice(1, 32 + overhead);

                protector.Protect(content, package, password, 1);
            });

            Assert.Equal("The 'package' must not overlap in memory with the 'content'.", ex.Message);
        }

        [Fact]
        public void UnprotectOverlapFails()
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            int overhead = protector.Overhead;

            var ex = Assert.Throws<InvalidOperationException>(() =>
            {
                Span<byte> buf = new byte[32 + overhead + 32];

                var content = buf.Slice(32 + overhead, 32);

                var package = buf.Slice(1, 32 + overhead);

                protector.Unprotect(package, content, password);
            });

            Assert.Equal("The 'content' must not overlap in memory with the 'package'.", ex.Message);
        }

        [Fact]
        public void ProtectUseAfterDisposeFail()
        {
            using var protector = new KeyProtector();

            protector.Dispose();

            var password = "user-password";
            var iterations = 2;

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.Throws<ObjectDisposedException>(() => protector.Protect(content, package, password, iterations));
            Assert.Equal(typeof(KeyProtector).FullName, ex.ObjectName);
        }

        [Fact]
        public void UnprotectUseAfterDisposeFail()
        {
            using var protector = new KeyProtector();

            protector.Dispose();

            var password = "user-password";

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.Throws<ObjectDisposedException>(() => protector.Unprotect(package, content, password));
            Assert.Equal(typeof(KeyProtector).FullName, ex.ObjectName);
        }

        [Fact]
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

            var ex = Assert.Throws<Exception>(() => protector.Protect(content, package, password, iterations));
            Assert.Equal(exStr, ex.Message);

            Assert.True(package.IsAllZeros(), "Destination not cleared on Protect() failure.");
        }

        [Fact]
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

            package[checksumOffset - 1] ^= 1;

            Span<byte> checksumHash = new byte[64];

            SHA512.HashData(packageSpan.Slice(0, checksumOffset), checksumHash);

            checksumHash.Slice(0, ChecksumSize).CopyTo(packageSpan.Slice(checksumOffset));

            var unprotectedContent = new byte[content.Length].Fill(byte.MaxValue);

            var ex = Assert.Throws<BadPasswordException>(() => protector.Unprotect(package, unprotectedContent, password));
            Assert.Equal("The provided password is incorrect.", ex.Message);

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() failure.");
        }

        [Fact]
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

            protector.Protect(content, package, password, iterations);

            var unprotectedContent = new byte[content.Length].Fill(byte.MaxValue);

            var ex = Assert.Throws<BadPasswordException>(() => protector.Unprotect(package, unprotectedContent, badPassword));
            Assert.Equal("The provided password is incorrect.", ex.Message);

            Assert.True(unprotectedContent.IsAllZeros(), "Destination not cleared on Unprotect() bad password.");
        }

        [Theory]
        [InlineData(int.MinValue)]
        [InlineData(-1)]
        [InlineData(0)]
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

            var ex = Assert.Throws<BadPackageException>(() => protector.Unprotect(package, content, badPassword));
            Assert.Equal("The package iterations count is invalid.", ex.Message);
        }

        [Fact]
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

            BinaryPrimitives.WriteUInt32BigEndian(packageSpan.Slice(0, 4), ((uint)'p' << 24) | ((uint)'b' << 16) | ((uint)'2' << 8) | (uint)'k');

            var ex = Assert.Throws<BadPackageException>(() => protector.Unprotect(package, content, badPassword));
            Assert.Equal("The package version is invalid.", ex.Message);
        }

        [Fact]
        public void UnprotectBadChecksumFails()
        {
            const string password = "user-password";
            const string badPassword = "user-Password";

            RngFillAction rng = (Span<byte> data) => data.Fill(97);

            using var protector = new KeyProtector(rng);

            var content = new byte[32].Fill(242);
            var package = new byte[32 + protector.Overhead];

            protector.Protect(content, package, password, 1);

            package[^1] ^= 1;

            var ex = Assert.Throws<BadPackageException>(() => protector.Unprotect(package, content, badPassword));
            Assert.Equal("The package checksum is invalid.", ex.Message);

            package[^1] ^= 1;

            package[8] ^= 1;

            ex = Assert.Throws<BadPackageException>(() => protector.Unprotect(package, content, badPassword));
            Assert.Equal("The package checksum is invalid.", ex.Message);
        }

        [Fact]
        public void NullRngFillConstructorPass()
        {
            using var p = new KeyProtector(null);
            Assert.Equal(96, p.Overhead);
        }

        [Fact]
        public void DoubleDisposeNoThrow()
        {
            var p = new KeyProtector();
            p.Dispose();
            p.Dispose();
        }

        [Fact]
        public void ProtectInvalidUtf8PasswordFails()
        {
            using var protector = new KeyProtector(d => d.Fill(1));

            var content = new byte[32];
            var package = new byte[32 + protector.Overhead];

            // Lone high surrogate is invalid UTF-8 when encoded with throwOnInvalidBytes.
            string badPassword = "\uD800";

            Assert.Throws<EncoderFallbackException>(() => protector.Protect(content, package, badPassword, 1));

            Assert.True(package.IsAllZeros(), "Package not cleared on failure.");
        }
    }
}
