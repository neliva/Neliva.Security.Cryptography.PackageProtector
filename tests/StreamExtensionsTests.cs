// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    [TestClass]
    public class StreamExtensionsTests
    {
        private const int BlockSize = 16;
        private const int HashSize = 32;
        private const int MinPackageSize = BlockSize + BlockSize + HashSize;

        [TestMethod]
        public async Task PackageProtectorUseAfterDisposeFail()
        {
            using var protector = new PackageProtector(packageSize: 64);

            protector.Dispose();

            var key = new byte[32];

            var ex = await Assert.ThrowsExceptionAsync<ObjectDisposedException>(() => protector.ProtectAsync(Stream.Null, Stream.Null, key));
            Assert.AreEqual(nameof(PackageProtector), ex.ObjectName);

            ex = await Assert.ThrowsExceptionAsync<ObjectDisposedException>(() => protector.UnprotectAsync(Stream.Null, Stream.Null, key));
            Assert.AreEqual(nameof(PackageProtector), ex.ObjectName);
        }

        [TestMethod]
        public async Task ProtectContentStreamNullArgFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => protector.ProtectAsync(null, Stream.Null, new byte[32])).ConfigureAwait(false);
            Assert.AreEqual("content", ex.ParamName);
        }

        [TestMethod]
        public async Task ProtectPackageStreamNullArgFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => protector.ProtectAsync(Stream.Null, null, new byte[32])).ConfigureAwait(false);
            Assert.AreEqual("package", ex.ParamName);
        }

        [TestMethod]
        public async Task UnprotectContentStreamNullArgFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => protector.UnprotectAsync(null, Stream.Null, new byte[32])).ConfigureAwait(false);
            Assert.AreEqual("package", ex.ParamName);
        }

        [TestMethod]
        public async Task UnprotectPackageStreamNullArgFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => protector.UnprotectAsync(Stream.Null, null, new byte[32])).ConfigureAwait(false);
            Assert.AreEqual("content", ex.ParamName);
        }

        [TestMethod]
        public async Task ProtectNullKeyFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => protector.ProtectAsync(Stream.Null, Stream.Null, null)).ConfigureAwait(false);
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        public async Task UnprotectNullKeyFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => protector.UnprotectAsync(Stream.Null, Stream.Null, null)).ConfigureAwait(false);
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(16)]
        [DataRow(31)]
        [DataRow(65)]
        [DataRow(128)]
        public async Task ProtectBadKeySizeFail(int keySize)
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => protector.ProtectAsync(Stream.Null, Stream.Null, new byte[keySize])).ConfigureAwait(false);
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(16)]
        [DataRow(31)]
        [DataRow(65)]
        [DataRow(128)]
        public async Task UnprotectBadKeySizeFail(int keySize)
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => protector.UnprotectAsync(Stream.Null, Stream.Null, new byte[keySize])).ConfigureAwait(false);
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0, 33)]
        [DataRow(16, 17)]
        [DataRow(32, 1)]
        public async Task ProtectBadAssociatedDataFail(int ivSize, int associatedDataSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => p.ProtectAsync(Stream.Null, Stream.Null, new byte[32], new byte[associatedDataSize]));
            Assert.AreEqual("associatedData", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0, 33)]
        [DataRow(16, 17)]
        [DataRow(32, 1)]
        public async Task UnprotectBadAssociatedDataSizeFail(int ivSize, int associatedDataSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = await Assert.ThrowsExceptionAsync<ArgumentOutOfRangeException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, new byte[32], new byte[associatedDataSize]));
            Assert.AreEqual("associatedData", ex.ParamName);
        }

        [TestMethod]
        public async Task UnprotectTruncatedAtPackageBoundaryFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[64].Fill(33);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key).ConfigureAwait(false);

            package.Position = 0; // rewind for reading
            package.SetLength(len - MinPackageSize); // completely drop last package

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key)).ConfigureAwait(false);
            Assert.AreEqual("Unexpected end of stream. Stream is truncated or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectPartiallyTruncatedStreamFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(183);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key).ConfigureAwait(false);

            package.Position = 0; // rewind for reading
            package.SetLength(len - (MinPackageSize / 3)); // partially drop last package

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key)).ConfigureAwait(false);
            Assert.AreEqual("Unexpected stream length. Stream is truncated or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectExtraPackageAfterEndOfStreamFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(203);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 6 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key).ConfigureAwait(false);

            package.Position = 0; // rewind for reading
            package.SetLength(len - MinPackageSize); // drop last package.

            content.Position = MinPackageSize * 3 - (p.MaxPackageSize - p.MaxContentSize); // reduce content to be protected

            len = await p.ProtectAsync(content, package, key).ConfigureAwait(false); // overwrite existing stream with shorter stream

            package.Position = 0;

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key)).ConfigureAwait(false);
            Assert.AreEqual("Unexpected data after end of stream marker.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadPackageFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(249);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key).ConfigureAwait(false);

            package.Position = 0; // rewind for reading

            // Corrupt package
            package.GetBuffer()[MinPackageSize * 2 + BlockSize + 3] ^= 1;

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key)).ConfigureAwait(false);
            Assert.AreEqual("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadKeyFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(239);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key).ConfigureAwait(false);

            package.Position = 0; // rewind for reading

            // Corrupt key
            key[3] ^= 1;

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key)).ConfigureAwait(false);
            Assert.AreEqual("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadPackageSizeFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);
            using var p1 = new PackageProtector(packageSize: MinPackageSize + BlockSize);

            var key = new byte[32].Fill(200);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key).ConfigureAwait(false);

            package.Position = 0; // rewind for reading

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => p1.UnprotectAsync(package, Stream.Null, key)).ConfigureAwait(false);
            Assert.AreEqual("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadAssociatedDataFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[64].Fill(199);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key).ConfigureAwait(false);

            package.Position = 0; // rewind for reading

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key, new byte[1])).ConfigureAwait(false);
            Assert.AreEqual("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectBadPackageNumberFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(199);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key).ConfigureAwait(false);

            // Mess up the offset, unprotect stream uses 0 as starting offset.
            package.Position = MinPackageSize;

            var ex = await Assert.ThrowsExceptionAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key)).ConfigureAwait(false);
            Assert.AreEqual("Package is invalid or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectEmptyPackageStreamFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(199);

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, key)).ConfigureAwait(false);
            Assert.AreEqual("Unexpected end of stream. Stream is truncated or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task UnprotectSingleTruncatedPackageFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(199);

            var content = new MemoryStream();
            content.SetLength(MinPackageSize - 13);

            var ex = await Assert.ThrowsExceptionAsync<InvalidDataException>(() => p.UnprotectAsync(content, Stream.Null, key)).ConfigureAwait(false);
            Assert.AreEqual("Unexpected stream length. Stream is truncated or corrupted.", ex.Message);
        }

        [TestMethod]
        public async Task StreamEncryptDecryptRoundTripPass()
        {
            using var p = new PackageProtector(packageSize: 256);

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
                CreateArray(256 - (p.MaxPackageSize - p.MaxContentSize), 3),
            };

            foreach (var d in data)
            {
                var encrypted = new MemoryStream();

                var encryptedLength = await p.ProtectAsync(new MemoryStream(d), encrypted, key, ArraySegment<byte>.Empty, CancellationToken.None).ConfigureAwait(false);

                encrypted.Position = 0;

                var decrypted = new MemoryStream();

                var decryptedLength = await p.UnprotectAsync(encrypted, decrypted, key, ArraySegment<byte>.Empty, CancellationToken.None).ConfigureAwait(false);

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