// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverageAttribute]
    [TestClass]
    public class StreamExtensionsTests
    {
        private const int BlockSize = 16;
        private const int HashSize = 32;
        private const int MinPackageSize = BlockSize + BlockSize + HashSize;
        private const int MaxPackageSize = (16 * 1024 * 1024) - BlockSize;
        private const int MaxContentSize = MaxPackageSize - Overhead;
        private const int Overhead = BlockSize + HashSize + 1;

        [TestMethod]
        public async Task ProtectInvalidArgsFail()
        {
            ArgumentException ex;

            ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => StreamExtensions.ProtectAsync(null, Stream.Null, new byte[32], MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("content", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => StreamExtensions.ProtectAsync(Stream.Null, null, new byte[32], MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("package", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => StreamExtensions.ProtectAsync(Stream.Null, Stream.Null, null, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => StreamExtensions.ProtectAsync(Stream.Null, Stream.Null, new byte[32], MinPackageSize - 1)).ConfigureAwait(false);
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => StreamExtensions.ProtectAsync(Stream.Null, Stream.Null, new byte[32], MaxPackageSize + 1)).ConfigureAwait(false);
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => StreamExtensions.ProtectAsync(Stream.Null, Stream.Null, new byte[32], MinPackageSize, new byte[BlockSize + 1])).ConfigureAwait(false);
            Assert.AreEqual<string>("associatedData", ex.ParamName);
        }

        [TestMethod]
        public async Task UnprotectInvalidArgsFail()
        {
            ArgumentException ex;

            ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => StreamExtensions.UnprotectAsync(null, Stream.Null, new byte[32], MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("package", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => StreamExtensions.UnprotectAsync(Stream.Null, null, new byte[32], MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("content", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => StreamExtensions.UnprotectAsync(Stream.Null, Stream.Null, null, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("key", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => StreamExtensions.UnprotectAsync(Stream.Null, Stream.Null, new byte[32], MinPackageSize - 1)).ConfigureAwait(false);
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => StreamExtensions.UnprotectAsync(Stream.Null, Stream.Null, new byte[32], MaxPackageSize + 1)).ConfigureAwait(false);
            Assert.AreEqual<string>("packageSize", ex.ParamName);

            ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => StreamExtensions.UnprotectAsync(Stream.Null, Stream.Null, new byte[32], MinPackageSize, new byte[BlockSize + 1])).ConfigureAwait(false);
            Assert.AreEqual<string>("associatedData", ex.ParamName);
        }

        [TestMethod]
        public async Task UnprotectTruncatedAtPackageBoundaryFail()
        {
            var key = new byte[32].Fill(33);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - Overhead]);

            var len = await content.ProtectAsync(package, key, MinPackageSize).ConfigureAwait(false);

            package.Position = 0; // rewind for reading
            package.SetLength(len - MinPackageSize); // completely drop last package

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => package.UnprotectAsync(Stream.Null, key, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("Unexpected end of stream. Stream is truncated or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectPartiallyTruncatedStreamFail()
        {
            var key = new byte[32].Fill(183);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - Overhead]);

            var len = await content.ProtectAsync(package, key, MinPackageSize).ConfigureAwait(false);

            package.Position = 0; // rewind for reading
            package.SetLength(len - (MinPackageSize / 3)); // partially drop last package

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => package.UnprotectAsync(Stream.Null, key, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("Unexpected stream length. Stream is truncated or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectExtraPackageAfterEndOfStreamFail()
        {
            var key = new byte[32].Fill(203);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 6 - Overhead]);

            var len = await content.ProtectAsync(package, key, MinPackageSize).ConfigureAwait(false);

            package.Position = 0; // rewind for reading
            package.SetLength(len - MinPackageSize); // drop last package.

            content.Position = MinPackageSize * 3 - Overhead; // reduce content to be protected

            len = await content.ProtectAsync(package, key, MinPackageSize).ConfigureAwait(false); // overwrite existing stream with shorter stream

            package.Position = 0;

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => package.UnprotectAsync(Stream.Null, key, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("Unexpected data after end of stream marker.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadPackageFail()
        {
            var key = new byte[32].Fill(249);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - Overhead]);

            var len = await content.ProtectAsync(package, key, MinPackageSize).ConfigureAwait(false);

            package.Position = 0; // rewind for reading

            // Corrupt package
            package.GetBuffer()[MinPackageSize * 2 + BlockSize + 3] ^= 1;

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => package.UnprotectAsync(Stream.Null, key, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadKeyFail()
        {
            var key = new byte[32].Fill(239);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - Overhead]);

            var len = await content.ProtectAsync(package, key, MinPackageSize).ConfigureAwait(false);

            package.Position = 0; // rewind for reading

            // Corrupt key
            key[3] ^= 1;

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => package.UnprotectAsync(Stream.Null, key, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadPackageSizeFail()
        {
            var key = new byte[32].Fill(200);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - Overhead]);

            var len = await content.ProtectAsync(package, key, MinPackageSize).ConfigureAwait(false);

            package.Position = 0; // rewind for reading

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => package.UnprotectAsync(Stream.Null, key, MinPackageSize + BlockSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadAssociatedDataFail()
        {
            var key = new byte[32].Fill(199);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - Overhead]);

            var len = await content.ProtectAsync(package, key, MinPackageSize).ConfigureAwait(false);

            package.Position = 0; // rewind for reading

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => package.UnprotectAsync(Stream.Null, key, MinPackageSize, new byte[1])).ConfigureAwait(false);
            Assert.AreEqual<string>("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadPackageNumberFail()
        {
            var key = new byte[32].Fill(199);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - Overhead]);

            var len = await content.ProtectAsync(package, key, MinPackageSize).ConfigureAwait(false);

            // Mess up the offset, unprotect stream uses 0 as starting offset.
            package.Position = MinPackageSize;

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => package.UnprotectAsync(Stream.Null, key, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectEmptyPackageStreamFail()
        {
            var key = new byte[32].Fill(199);

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => Stream.Null.UnprotectAsync(Stream.Null, key, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("Unexpected end of stream. Stream is truncated or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectSingleTruncatedPackageFail()
        {
            var key = new byte[32].Fill(199);

            var content = new MemoryStream();
            content.SetLength(MinPackageSize - 13);

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => content.UnprotectAsync(Stream.Null, key, MinPackageSize)).ConfigureAwait(false);
            Assert.AreEqual<string>("Unexpected stream length. Stream is truncated or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task StreamEncryptDecryptRoundTripPass()
        {
            var key = CreateArray(61, 209);

            var data = new List<byte[]>()
            {
                CreateArray(0, 101),
                CreateArray(1, 11),
                CreateArray(14, 8),
                CreateArray(15, 24),
                CreateArray(16, 63),
                CreateArray(17, 12),
                CreateArray(30, 68),
                CreateArray(31, 85),
                CreateArray(32, 156),
                CreateArray(33, 128),
                CreateArray(62, 217),
                CreateArray(63, 42),
                CreateArray(64, 67),
                CreateArray(65, 167),
                CreateArray(66, 255),
                CreateArray(1022, 216),
                CreateArray(1023, 31),
                CreateArray(1024, 7),
                CreateArray(1025, 79),
                CreateArray(1026, 159),
                CreateArray(256 - PackageProtector.Overhead, 3),
            };

            foreach (var d in data)
            {
                var encrypted = new MemoryStream();

                var encryptedLength = await new MemoryStream(d).ProtectAsync(encrypted, key, 256).ConfigureAwait(false);

                encrypted.Position = 0;

                var decrypted = new MemoryStream();

                var decryptedLength = await encrypted.UnprotectAsync(decrypted, key, 256).ConfigureAwait(false);

                decrypted.Position = 0;

                Assert.AreEqual(d.Length, decryptedLength);

                Assert.AreEqual(d.Length, decrypted.Length);

                CollectionAssert.AreEqual(d, decrypted.GetBuffer().Take((int)decrypted.Length).ToArray());
            }
        }

        private static byte[] CreateArray(int arrayLength, byte elementValue)
        {
            return new byte[arrayLength].Fill(elementValue);
        }
    }
}