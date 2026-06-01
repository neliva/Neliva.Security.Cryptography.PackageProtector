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
            Assert.StartsWith("Key length must be between 32 and 64 bytes.", ex.Message);
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
            Assert.StartsWith("Key length must be between 32 and 64 bytes.", ex.Message);
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
            Assert.StartsWith("Associated data length is too large.", ex.Message);
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
            Assert.StartsWith("Associated data length is too large.", ex.Message);
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

        [Fact]
        public async Task ProtectAsyncPreCancelledFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32];
            var content = new MemoryStream(new byte[MinPackageSize * 4]);
            var package = new MemoryStream();

            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => p.ProtectAsync(content, package, key, default, cts.Token));
        }

        [Fact]
        public async Task UnprotectAsyncPreCancelledFail()
        {
            using var p = new PackageProtector(packageSize: MinPackageSize);

            var key = new byte[32];

            var package = new MemoryStream();
            var src = new MemoryStream(new byte[MinPackageSize]);
            await p.ProtectAsync(src, package, key);
            package.Position = 0;

            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => p.UnprotectAsync(package, new MemoryStream(), key, default, cts.Token));
        }

        [Fact]
        public async Task ProtectAsyncShortReadsRoundTripPass()
        {
            using var p = new PackageProtector(packageSize: 128);

            var key = new byte[32].Fill(5);
            var data = new byte[p.MaxContentSize * 3 + 17].Fill(42);

            var content = new ShortReadStream(data, maxRead: 7);
            var package = new MemoryStream();

            await p.ProtectAsync(content, package, key);

            package.Position = 0;
            var unprotected = new MemoryStream();
            await p.UnprotectAsync(package, unprotected, key);

            Assert.Equal(data, unprotected.ToArray());
        }

        private sealed class ShortReadStream : Stream
        {
            private readonly byte[] _data;
            private readonly int _maxRead;
            private int _pos;

            public ShortReadStream(byte[] data, int maxRead) { _data = data; _maxRead = maxRead; }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => _data.Length;
            public override long Position { get => _pos; set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            public override int Read(byte[] buffer, int offset, int count)
            {
                int remaining = _data.Length - _pos;
                if (remaining <= 0) return 0;
                int n = Math.Min(Math.Min(count, _maxRead), remaining);
                Buffer.BlockCopy(_data, _pos, buffer, offset, n);
                _pos += n;
                return n;
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(32)]
        public async Task StreamRoundTripAllIvSizesPass(int ivSize)
        {
            // Validate ivSize=0 (deterministic), ivSize=16 (default) and ivSize=32
            // (largest IV) end-to-end, including the empty-package end-of-stream
            // marker semantics.
            using var p = new PackageProtector(ivSize: ivSize, packageSize: 256);

            var key = new byte[32].Fill(91);

            // Choose a content length that does NOT align on a package boundary so
            // the last package is a short package and no extra end-of-stream marker
            // is emitted.
            int contentLength = p.MaxContentSize * 2 + 13;
            var contentBytes = new byte[contentLength].Fill(77);

            var package = new MemoryStream();

            long protectedLen = await p.ProtectAsync(new MemoryStream(contentBytes), package, key);

            Assert.True(protectedLen > 0);

            package.Position = 0;
            var decrypted = new MemoryStream();

            long decryptedLen = await p.UnprotectAsync(package, decrypted, key);

            Assert.Equal(contentLength, decryptedLen);
            Assert.Equal(contentBytes, decrypted.ToArray());
        }

        [Fact]
        public async Task StreamRoundTripWithAssociatedDataPass()
        {
            // The negative associated data path is covered elsewhere; verify a full
            // round-trip succeeds when matching associated data is supplied to both
            // ProtectAsync and UnprotectAsync.
            using var p = new PackageProtector(ivSize: 16, packageSize: 128);

            var key = new byte[32].Fill(71);
            var associatedData = new byte[16].Fill(123);

            var contentBytes = new byte[p.MaxContentSize * 2 + 9].Fill(44);

            var package = new MemoryStream();

            await p.ProtectAsync(new MemoryStream(contentBytes), package, key, associatedData);

            package.Position = 0;
            var decrypted = new MemoryStream();

            long decryptedLen = await p.UnprotectAsync(package, decrypted, key, associatedData);

            Assert.Equal(contentBytes.Length, decryptedLen);
            Assert.Equal(contentBytes, decrypted.ToArray());

            // Unprotecting with mismatched associated data must fail.
            package.Position = 0;
            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key, new byte[16].Fill(124)));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task StreamRoundTripExactContentMultipleAppendsEndMarkerPass()
        {
            // When the content length is an exact multiple of MaxContentSize, the
            // last data package is full, so an extra empty end-of-stream marker
            // package must be appended. Verify exact output length and round-trip.
            using var p = new PackageProtector(packageSize: 128);

            var key = new byte[32].Fill(17);

            int contentLength = p.MaxContentSize * 3;
            var contentBytes = new byte[contentLength].Fill(88);

            var package = new MemoryStream();

            long protectedLen = await p.ProtectAsync(new MemoryStream(contentBytes), package, key);

            // 3 full data packages plus 1 empty end-of-stream marker package.
            // Empty content is PKCS7-padded to a full block, so the marker is a
            // full minimum-size package (iv + padded block + hash).
            Assert.Equal((long)p.MaxPackageSize * 3 + MinPackageSize, protectedLen);

            package.Position = 0;
            var decrypted = new MemoryStream();

            long decryptedLen = await p.UnprotectAsync(package, decrypted, key);

            Assert.Equal(contentLength, decryptedLen);
            Assert.Equal(contentBytes, decrypted.ToArray());
        }

        [Fact]
        public async Task StreamRoundTripEmptyContentProducesSingleMarkerPass()
        {
            // Empty content must still produce exactly one end-of-stream marker
            // package, and unprotecting it must yield zero content bytes.
            using var p = new PackageProtector(packageSize: 128);

            var key = new byte[32].Fill(53);

            var package = new MemoryStream();

            long protectedLen = await p.ProtectAsync(new MemoryStream(Array.Empty<byte>()), package, key);

            // Empty content is PKCS7-padded to a full block, so the single marker
            // package is a full minimum-size package.
            Assert.Equal(MinPackageSize, protectedLen);

            package.Position = 0;
            var decrypted = new MemoryStream();

            long decryptedLen = await p.UnprotectAsync(package, decrypted, key);

            Assert.Equal(0, decryptedLen);
            Assert.Equal(0, decrypted.Length);
        }

        [Fact]
        public async Task StreamProtectReturnsTotalWrittenLengthPass()
        {
            // The returned length must equal the number of bytes actually written
            // to the package stream.
            using var p = new PackageProtector(packageSize: 128);

            var key = new byte[32].Fill(61);

            var contentBytes = new byte[p.MaxContentSize + 5].Fill(200);

            var package = new MemoryStream();

            long protectedLen = await p.ProtectAsync(new MemoryStream(contentBytes), package, key);

            Assert.Equal(package.Length, protectedLen);
        }

        [Fact]
        public async Task ProtectValidationPrecedencePass()
        {
            // Validation order: content -> package -> key -> key size ->
            // associatedData -> disposed. Each check must take precedence over
            // the next.
            using var p = new PackageProtector(packageSize: 128);

            p.Dispose();

            // content null wins over everything.
            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.ProtectAsync(null, null, null));
            Assert.Equal("content", ex.ParamName);

            // package null wins over key null.
            ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.ProtectAsync(Stream.Null, null, null));
            Assert.Equal("package", ex.ParamName);

            // key null wins over key size and disposed.
            ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.ProtectAsync(Stream.Null, Stream.Null, null));
            Assert.Equal("key", ex.ParamName);

            // key size wins over associatedData and disposed.
            var exRange = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.ProtectAsync(Stream.Null, Stream.Null, new byte[16], new byte[1024]));
            Assert.Equal("key", exRange.ParamName);

            // associatedData wins over disposed.
            exRange = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.ProtectAsync(Stream.Null, Stream.Null, new byte[32], new byte[1024]));
            Assert.Equal("associatedData", exRange.ParamName);

            // disposed is last.
            var exDisposed = await Assert.ThrowsAsync<ObjectDisposedException>(() => p.ProtectAsync(Stream.Null, Stream.Null, new byte[32]));
            Assert.Equal(typeof(PackageProtector).FullName, exDisposed.ObjectName);
        }

        [Fact]
        public async Task UnprotectValidationPrecedencePass()
        {
            // Validation order: package -> content -> key -> key size ->
            // associatedData -> disposed. Each check must take precedence over
            // the next.
            using var p = new PackageProtector(packageSize: 128);

            p.Dispose();

            // package null wins over everything.
            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.UnprotectAsync(null, null, null));
            Assert.Equal("package", ex.ParamName);

            // content null wins over key null.
            ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.UnprotectAsync(Stream.Null, null, null));
            Assert.Equal("content", ex.ParamName);

            // key null wins over key size and disposed.
            ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, null));
            Assert.Equal("key", ex.ParamName);

            // key size wins over associatedData and disposed.
            var exRange = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, new byte[16], new byte[1024]));
            Assert.Equal("key", exRange.ParamName);

            // associatedData wins over disposed.
            exRange = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, new byte[32], new byte[1024]));
            Assert.Equal("associatedData", exRange.ParamName);

            // disposed is last.
            var exDisposed = await Assert.ThrowsAsync<ObjectDisposedException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, new byte[32]));
            Assert.Equal(typeof(PackageProtector).FullName, exDisposed.ObjectName);
        }

        [Theory]
        [InlineData(32)]
        [InlineData(33)]
        [InlineData(48)]
        [InlineData(63)]
        [InlineData(64)]
        public async Task StreamRoundTripValidKeySizesPass(int keySize)
        {
            // All key sizes between 32 and 64 bytes (inclusive) are valid and must
            // round-trip successfully.
            using var p = new PackageProtector(packageSize: 128);

            var key = new byte[keySize].Fill(97);

            var contentBytes = new byte[p.MaxContentSize * 2 + 11].Fill(13);

            var package = new MemoryStream();

            await p.ProtectAsync(new MemoryStream(contentBytes), package, key);

            package.Position = 0;
            var decrypted = new MemoryStream();

            long decryptedLen = await p.UnprotectAsync(package, decrypted, key);

            Assert.Equal(contentBytes.Length, decryptedLen);
            Assert.Equal(contentBytes, decrypted.ToArray());
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(8)]
        [InlineData(16)]
        public async Task StreamRoundTripFullAssociatedDataRangePass(int associatedDataSize)
        {
            // Associated data lengths from empty up to the maximum allowed (for
            // ivSize 16 the max is 16 bytes) must round-trip when supplied
            // identically to protect and unprotect.
            using var p = new PackageProtector(ivSize: 16, packageSize: 128);

            var key = new byte[32].Fill(151);
            var associatedData = new byte[associatedDataSize].Fill(211);

            var contentBytes = new byte[p.MaxContentSize + 7].Fill(60);

            var package = new MemoryStream();

            await p.ProtectAsync(new MemoryStream(contentBytes), package, key, associatedData);

            package.Position = 0;
            var decrypted = new MemoryStream();

            long decryptedLen = await p.UnprotectAsync(package, decrypted, key, associatedData);

            Assert.Equal(contentBytes.Length, decryptedLen);
            Assert.Equal(contentBytes, decrypted.ToArray());
        }

        [Fact]
        public async Task StreamRoundTripMaxAssociatedDataBoundaryPass()
        {
            // The maximum associated data size is exactly valid; one byte more must
            // fail with the associatedData out-of-range message.
            using var p = new PackageProtector(ivSize: 16, packageSize: 128);

            var key = new byte[32].Fill(181);

            // Max associated data size is (32 - ivSize) bytes.
            int maxAssociatedDataSize = 32 - 16;
            var maxAssociatedData = new byte[maxAssociatedDataSize].Fill(9);

            var contentBytes = new byte[p.MaxContentSize + 3].Fill(72);

            var package = new MemoryStream();

            await p.ProtectAsync(new MemoryStream(contentBytes), package, key, maxAssociatedData);

            package.Position = 0;
            var decrypted = new MemoryStream();

            long decryptedLen = await p.UnprotectAsync(package, decrypted, key, maxAssociatedData);

            Assert.Equal(contentBytes.Length, decryptedLen);
            Assert.Equal(contentBytes, decrypted.ToArray());

            // One byte over the maximum must fail.
            var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.ProtectAsync(Stream.Null, Stream.Null, key, new byte[maxAssociatedDataSize + 1]));
            Assert.Equal("associatedData", ex.ParamName);
            Assert.StartsWith("Associated data length is too large.", ex.Message);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(15)]
        [InlineData(16)]
        [InlineData(17)]
        public async Task StreamRoundTripContentLengthAlignmentRangePass(int extra)
        {
            // Exercise content lengths around block-size and package-size
            // boundaries to cover both the exact-multiple end marker path and the
            // short final package path.
            using var p = new PackageProtector(packageSize: 128);

            var key = new byte[32].Fill(120);

            int contentLength = p.MaxContentSize + extra;
            var contentBytes = new byte[contentLength].Fill(48);

            var package = new MemoryStream();

            await p.ProtectAsync(new MemoryStream(contentBytes), package, key);

            package.Position = 0;
            var decrypted = new MemoryStream();

            long decryptedLen = await p.UnprotectAsync(package, decrypted, key);

            Assert.Equal(contentLength, decryptedLen);
            Assert.Equal(contentBytes, decrypted.ToArray());
        }

        [Fact]
        public async Task StreamRoundTripDefaultAssociatedDataEquivalentToEmptyPass()
        {
            // Default ArraySegment<byte> and ArraySegment<byte>.Empty must be
            // interchangeable across protect and unprotect.
            using var p = new PackageProtector(packageSize: 128);

            var key = new byte[32].Fill(64);

            var contentBytes = new byte[p.MaxContentSize + 1].Fill(200);

            var package = new MemoryStream();

            // Protect with default associated data.
            await p.ProtectAsync(new MemoryStream(contentBytes), package, key, default);

            package.Position = 0;
            var decrypted = new MemoryStream();

            // Unprotect with explicit empty associated data.
            long decryptedLen = await p.UnprotectAsync(package, decrypted, key, ArraySegment<byte>.Empty);

            Assert.Equal(contentBytes.Length, decryptedLen);
            Assert.Equal(contentBytes, decrypted.ToArray());
        }
    }
}

