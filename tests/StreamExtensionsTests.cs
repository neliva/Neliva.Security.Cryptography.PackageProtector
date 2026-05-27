// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    public class StreamExtensionsTests
    {
        private const int BlockSize = 16;
        private const int HashSize = 32;
        private const int MinPackageSize = BlockSize + BlockSize + HashSize;

        [Fact]
        public async Task PackageProtectorUseAfterDisposeFail()
        {
            using var protector = new PackageProtector(packageSize: 64);

            protector.Dispose();

            var key = new byte[32];

            var ex = await Assert.ThrowsAsync<ObjectDisposedException>(() => protector.ProtectAsync(Stream.Null, Stream.Null, key));
            Assert.Equal(typeof(PackageProtector).FullName, ex.ObjectName);

            ex = await Assert.ThrowsAsync<ObjectDisposedException>(() => protector.UnprotectAsync(Stream.Null, Stream.Null, key));
            Assert.Equal(typeof(PackageProtector).FullName, ex.ObjectName);
        }

        [Fact]
        public async Task ProtectContentStreamNullArgFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.ProtectAsync(null, Stream.Null, new byte[32]));
            Assert.Equal("content", ex.ParamName);
        }

        [Fact]
        public async Task ProtectPackageStreamNullArgFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.ProtectAsync(Stream.Null, null, new byte[32]));
            Assert.Equal("package", ex.ParamName);
        }

        [Fact]
        public async Task UnprotectContentStreamNullArgFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.UnprotectAsync(null, Stream.Null, new byte[32]));
            Assert.Equal("package", ex.ParamName);
        }

        [Fact]
        public async Task UnprotectPackageStreamNullArgFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.UnprotectAsync(Stream.Null, null, new byte[32]));
            Assert.Equal("content", ex.ParamName);
        }

        [Fact]
        public async Task ProtectNullKeyFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.ProtectAsync(Stream.Null, Stream.Null, null));
            Assert.Equal("key", ex.ParamName);
        }

        [Fact]
        public async Task UnprotectNullKeyFail()
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.UnprotectAsync(Stream.Null, Stream.Null, null));
            Assert.Equal("key", ex.ParamName);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(31)]
        [InlineData(65)]
        [InlineData(128)]
        public async Task ProtectBadKeySizeFail(int keySize)
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => protector.ProtectAsync(Stream.Null, Stream.Null, new byte[keySize]));
            Assert.Equal("key", ex.ParamName);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(31)]
        [InlineData(65)]
        [InlineData(128)]
        public async Task UnprotectBadKeySizeFail(int keySize)
        {
            using var protector = new PackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => protector.UnprotectAsync(Stream.Null, Stream.Null, new byte[keySize]));
            Assert.Equal("key", ex.ParamName);
        }

        [Theory]
        [InlineData(0, 33)]
        [InlineData(16, 17)]
        [InlineData(32, 1)]
        public async Task ProtectBadAssociatedDataFail(int ivSize, int associatedDataSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.ProtectAsync(Stream.Null, Stream.Null, new byte[32], new byte[associatedDataSize]));
            Assert.Equal("associatedData", ex.ParamName);
        }

        [Theory]
        [InlineData(0, 33)]
        [InlineData(16, 17)]
        [InlineData(32, 1)]
        public async Task UnprotectBadAssociatedDataSizeFail(int ivSize, int associatedDataSize)
        {
            using var p = new PackageProtector(ivSize: ivSize, packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, new byte[32], new byte[associatedDataSize]));
            Assert.Equal("associatedData", ex.ParamName);
        }

        [Fact]
        public async Task UnprotectTruncatedAtPackageBoundaryFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[64].Fill(33);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;
            package.SetLength(len - MinPackageSize);

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Unexpected end of stream. Stream is truncated or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectPartiallyTruncatedStreamFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(183);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;
            package.SetLength(len - (MinPackageSize / 3));

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Unexpected stream length. Stream is truncated or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectExtraPackageAfterEndOfStreamFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(203);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 6 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;
            package.SetLength(len - MinPackageSize);

            content.Position = MinPackageSize * 3 - (p.MaxPackageSize - p.MaxContentSize);

            len = await p.ProtectAsync(content, package, key);

            package.Position = 0;

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Unexpected data after end of stream marker.", ex.Message);
        }

        [Fact]
        public async Task UnprotectBadPackageFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(249);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;

            package.GetBuffer()[MinPackageSize * 2 + BlockSize + 3] ^= 1;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectBadKeyFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(239);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;

            key[3] ^= 1;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectBadPackageSizeFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);
            using var p1 = new PackageProtector(packageSize: MinPackageSize + BlockSize);

            var key = new byte[32].Fill(200);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p1.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectBadAssociatedDataFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[64].Fill(199);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key, new byte[1]));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectBadPackageNumberFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(199);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = MinPackageSize;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectEmptyPackageStreamFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(199);

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, key));
            Assert.Equal("Unexpected end of stream. Stream is truncated or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectSingleTruncatedPackageFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32].Fill(199);

            var content = new MemoryStream();
            content.SetLength(MinPackageSize - 13);

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(content, Stream.Null, key));
            Assert.Equal("Unexpected stream length. Stream is truncated or corrupted.", ex.Message);
        }

        [Fact]
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

                var encryptedLength = await p.ProtectAsync(new MemoryStream(d), encrypted, key, ArraySegment<byte>.Empty, CancellationToken.None);

                encrypted.Position = 0;

                var decrypted = new MemoryStream();

                var decryptedLength = await p.UnprotectAsync(encrypted, decrypted, key, ArraySegment<byte>.Empty, CancellationToken.None);

                decrypted.Position = 0;

                Assert.Equal(d.Length, decryptedLength);

                Assert.Equal(d.Length, decrypted.Length);

                Assert.Equal(d, decrypted.GetBuffer().Take((int)decrypted.Length).ToArray());
            }
        }

        private static byte[] CreateArray(int arrayLength, byte elementValue)
        {
            return new byte[arrayLength].Fill(elementValue);
        }
    }
}

