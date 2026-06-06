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

        // Concrete PackageProtector for testing. PackageProtector is abstract,
        // so tests instantiate this subclass which uses the default
        // (cryptographically strong) RNG inherited from the base class.
        private sealed class TestPackageProtector : PackageProtector
        {
            public TestPackageProtector(int ivSize = BlockSize, int packageSize = 64 * 1024)
                : base(ivSize, packageSize)
            {
            }
        }

        [Fact]
        public async Task ProtectContentStreamNullArgFail()
        {
            var protector = new TestPackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.ProtectAsync(null, Stream.Null, new PackageKey(new byte[32])));
            Assert.Equal("content", ex.ParamName);
        }

        [Fact]
        public async Task ProtectPackageStreamNullArgFail()
        {
            var protector = new TestPackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.ProtectAsync(Stream.Null, null, new PackageKey(new byte[32])));
            Assert.Equal("package", ex.ParamName);
        }

        [Fact]
        public async Task UnprotectContentStreamNullArgFail()
        {
            var protector = new TestPackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.UnprotectAsync(null, Stream.Null, new PackageKey(new byte[32])));
            Assert.Equal("package", ex.ParamName);
        }

        [Fact]
        public async Task UnprotectPackageStreamNullArgFail()
        {
            var protector = new TestPackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.UnprotectAsync(Stream.Null, null, new PackageKey(new byte[32])));
            Assert.Equal("content", ex.ParamName);
        }

        [Fact]
        public async Task ProtectNullKeyFail()
        {
            var protector = new TestPackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.ProtectAsync(Stream.Null, Stream.Null, null));
            Assert.Equal("key", ex.ParamName);
        }

        [Fact]
        public async Task UnprotectNullKeyFail()
        {
            var protector = new TestPackageProtector();

            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => protector.UnprotectAsync(Stream.Null, Stream.Null, null));
            Assert.Equal("key", ex.ParamName);
        }

        [Theory]
        [InlineData(0, 33)]
        [InlineData(16, 17)]
        [InlineData(32, 1)]
        public async Task ProtectBadAssociatedDataFail(int ivSize, int associatedDataSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: 128);

            var content = new byte[p.MaxContentSize];
            var package = new byte[p.MaxPackageSize];

            var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.ProtectAsync(Stream.Null, Stream.Null, new PackageKey(new byte[32]), new byte[associatedDataSize]));
            Assert.Equal("associatedData", ex.ParamName);
            Assert.StartsWith("Associated data length is too large.", ex.Message);
        }

        [Theory]
        [InlineData(0, 33)]
        [InlineData(16, 17)]
        [InlineData(32, 1)]
        public async Task UnprotectBadAssociatedDataSizeFail(int ivSize, int associatedDataSize)
        {
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: 128);

            var package = new byte[p.MaxPackageSize];

            var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, new PackageKey(new byte[32]), new byte[associatedDataSize]));
            Assert.Equal("associatedData", ex.ParamName);
            Assert.StartsWith("Associated data length is too large.", ex.Message);
        }

        [Fact]
        public async Task UnprotectTruncatedAtPackageBoundaryFail()
        {
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[64].Fill(33));

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;
            package.SetLength(len - MinPackageSize);

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Missing end-of-stream marker. The stream is truncated or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectPartiallyTruncatedStreamFail()
        {
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(183));

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;
            package.SetLength(len - (MinPackageSize / 3));

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Invalid package length. The stream is truncated or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectExtraPackageAfterEndOfStreamFail()
        {
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(203));

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 6 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;
            package.SetLength(len - MinPackageSize);

            content.Position = MinPackageSize * 3 - (p.MaxPackageSize - p.MaxContentSize);

            len = await p.ProtectAsync(content, package, key);

            package.Position = 0;

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Unexpected data after the end-of-stream marker.", ex.Message);
        }

        [Fact]
        public async Task UnprotectBadPackageFail()
        {
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(249));

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
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            var keyBytes = new byte[32].Fill(239);
            using var key = new PackageKey(keyBytes);

            var package = new MemoryStream();
            var content = new MemoryStream(new byte[MinPackageSize * 4 - (p.MaxPackageSize - p.MaxContentSize)]);

            var len = await p.ProtectAsync(content, package, key);

            package.Position = 0;

            keyBytes[3] ^= 1;
            using var wrongKey = new PackageKey(keyBytes);

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, wrongKey));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectBadPackageSizeFail()
        {
            var p = new TestPackageProtector(packageSize: MinPackageSize);
            var p1 = new TestPackageProtector(packageSize: MinPackageSize + BlockSize);

            using var key = new PackageKey(new byte[32].Fill(200));

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
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[64].Fill(199));

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
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(199));

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
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(199));

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, key));
            Assert.Equal("Missing end-of-stream marker. The stream is truncated or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectReorderedInteriorPackagesFail()
        {
            // Attack: swap two interior data packages (reordering).
            // Each package is authenticated with its position (packageNumber),
            // so a package placed at the wrong position must fail authentication.
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(71));

            // Four full data packages followed by an empty end-of-stream marker.
            var content = new MemoryStream(new byte[p.MaxContentSize * 4].Fill(123));

            var package = new MemoryStream();
            await p.ProtectAsync(content, package, key);

            var buffer = package.GetBuffer();

            // Swap package 1 and package 2 on the wire.
            SwapPackages(buffer, p.MaxPackageSize, 1, 2);

            package.Position = 0;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectSwappedFirstAndLastDataPackagesFail()
        {
            // Attack: swap the first and last data packages.
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(55));

            // Three full data packages plus an empty end-of-stream marker.
            var content = new MemoryStream(new byte[p.MaxContentSize * 3].Fill(88));

            var package = new MemoryStream();
            await p.ProtectAsync(content, package, key);

            var buffer = package.GetBuffer();

            // Swap package 0 and package 2 (both full data packages).
            SwapPackages(buffer, p.MaxPackageSize, 0, 2);

            package.Position = 0;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectDuplicatedPackageSubstitutionFail()
        {
            // Attack: substitute a package with a copy of another package from the
            // same stream. The duplicated package authenticates only at its
            // original position, so it must fail at the substituted position.
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(144));

            var content = new MemoryStream(new byte[p.MaxContentSize * 4].Fill(212));

            var package = new MemoryStream();
            await p.ProtectAsync(content, package, key);

            var buffer = package.GetBuffer();

            // Overwrite package 2 with a copy of package 0.
            Array.Copy(buffer, 0, buffer, p.MaxPackageSize * 2, p.MaxPackageSize);

            package.Position = 0;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectFirstPackageRemovedFail()
        {
            // Attack: drop the first package. All subsequent packages now decrypt
            // at a position one less than the one they were protected with, so the
            // first remaining package fails authentication.
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(91));

            var content = new MemoryStream(new byte[p.MaxContentSize * 4].Fill(17));

            var package = new MemoryStream();
            var len = await p.ProtectAsync(content, package, key);

            var buffer = package.GetBuffer();

            // Shift everything left by one package, discarding package 0.
            Array.Copy(buffer, p.MaxPackageSize, buffer, 0, (int)len - p.MaxPackageSize);

            var truncated = new MemoryStream();
            await truncated.WriteAsync(buffer, 0, (int)len - p.MaxPackageSize);
            truncated.Position = 0;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(truncated, Stream.Null, key));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectLastDataPackageMarkerRemovedFail()
        {
            // Attack: truncate the final data-carrying end-of-stream marker.
            // When content is not a multiple of MaxContentSize the last package is
            // a short marker; removing it leaves only full packages, so the stream
            // ends without a marker.
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(64));

            // Three full packages plus a short (data-carrying) marker package.
            var content = new MemoryStream(new byte[p.MaxContentSize * 3 + 7].Fill(201));

            var package = new MemoryStream();
            var len = await p.ProtectAsync(content, package, key);

            // Remove the final marker package.
            package.SetLength(len - p.MaxPackageSize);
            package.Position = 0;

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(package, Stream.Null, key));
            Assert.Equal("Missing end-of-stream marker. The stream is truncated or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectSubstituteFromDifferentStreamDifferentAssociatedDataFail()
        {
            // Attack: splice a package from a different stream that was protected
            // with the same key but different associated data. Per-stream
            // associated data binds packages to their stream, so the spliced
            // package must fail authentication.
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(33));

            var adA = new byte[1].Fill(1);
            var adB = new byte[1].Fill(2);

            var contentA = new MemoryStream(new byte[p.MaxContentSize * 4].Fill(70));
            var contentB = new MemoryStream(new byte[p.MaxContentSize * 4].Fill(70));

            var packageA = new MemoryStream();
            var packageB = new MemoryStream();

            await p.ProtectAsync(contentA, packageA, key, adA);
            await p.ProtectAsync(contentB, packageB, key, adB);

            var bufferA = packageA.GetBuffer();
            var bufferB = packageB.GetBuffer();

            // Replace package 1 of stream A with package 1 of stream B.
            Array.Copy(bufferB, p.MaxPackageSize, bufferA, p.MaxPackageSize, p.MaxPackageSize);

            packageA.Position = 0;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(packageA, Stream.Null, key, adA));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectSubstituteFromDifferentStreamDifferentKeyFail()
        {
            // Attack: splice a package from a different stream protected under a
            // different key. The key binding makes the spliced package fail.
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var keyA = new PackageKey(new byte[32].Fill(40));
            using var keyB = new PackageKey(new byte[32].Fill(41));

            var contentA = new MemoryStream(new byte[p.MaxContentSize * 4].Fill(99));
            var contentB = new MemoryStream(new byte[p.MaxContentSize * 4].Fill(99));

            var packageA = new MemoryStream();
            var packageB = new MemoryStream();

            await p.ProtectAsync(contentA, packageA, keyA);
            await p.ProtectAsync(contentB, packageB, keyB);

            var bufferA = packageA.GetBuffer();
            var bufferB = packageB.GetBuffer();

            // Replace package 2 of stream A with package 2 of stream B.
            Array.Copy(bufferB, p.MaxPackageSize * 2, bufferA, p.MaxPackageSize * 2, p.MaxPackageSize);

            packageA.Position = 0;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(packageA, Stream.Null, keyA));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        [Fact]
        public async Task UnprotectMarkerMovedToInteriorFail()
        {
            // Attack: move the end-of-stream marker into an interior position to
            // truncate the stream early. The marker authenticates only at its
            // original position, so it fails when relocated.
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(150));

            // Four full data packages plus an empty marker (package index 4).
            var content = new MemoryStream(new byte[p.MaxContentSize * 4].Fill(5));

            var package = new MemoryStream();
            var len = await p.ProtectAsync(content, package, key);

            var buffer = package.GetBuffer();

            int markerIndex = (int)(len / p.MaxPackageSize) - 1;

            // Build a stream that ends with the marker placed at interior index 2.
            var tampered = new MemoryStream();
            await tampered.WriteAsync(buffer, 0, p.MaxPackageSize * 2); // packages 0,1
            await tampered.WriteAsync(buffer, markerIndex * p.MaxPackageSize, p.MaxPackageSize); // marker at index 2
            tampered.Position = 0;

            var ex = await Assert.ThrowsAsync<BadPackageException>(() => p.UnprotectAsync(tampered, Stream.Null, key));
            Assert.Equal("Package is invalid or corrupted.", ex.Message);
        }

        private static void SwapPackages(byte[] buffer, int packageSize, int indexA, int indexB)
        {
            var temp = new byte[packageSize];

            Array.Copy(buffer, indexA * packageSize, temp, 0, packageSize);
            Array.Copy(buffer, indexB * packageSize, buffer, indexA * packageSize, packageSize);
            Array.Copy(temp, 0, buffer, indexB * packageSize, packageSize);
        }

        [Fact]
        public async Task UnprotectSingleTruncatedPackageFail()
        {
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32].Fill(199));

            var content = new MemoryStream();
            content.SetLength(MinPackageSize - 13);

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => p.UnprotectAsync(content, Stream.Null, key));
            Assert.Equal("Invalid package length. The stream is truncated or corrupted.", ex.Message);
        }

        [Fact]
        public async Task StreamEncryptDecryptRoundTripPass()
        {
            var p = new TestPackageProtector(packageSize: 256);

            var key = new PackageKey(CreateArray(61, 209));

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
        public async Task SystemStreamRoundTripPass()
        {
            // The System protector is the default public instance. A multi-package
            // stream round-trip through the async API must succeed bit-for-bit.
            // System uses ivSize 32, so MaxAssociatedDataSize is 32 - 32 = 0.
            var p = PackageProtector.System;

            var key = new PackageKey(CreateArray(32, 209));
            var associatedData = ReadOnlyMemory<byte>.Empty;

            // Spans several packages to exercise chunked stream protection.
            var content = CreateArray((p.MaxContentSize * 2) + 123, 200);

            var encrypted = new MemoryStream();

            await p.ProtectAsync(new MemoryStream(content), encrypted, key, associatedData, CancellationToken.None);

            encrypted.Position = 0;

            var decrypted = new MemoryStream();

            var decryptedLength = await p.UnprotectAsync(encrypted, decrypted, key, associatedData, CancellationToken.None);

            Assert.Equal(content.Length, decryptedLength);
            Assert.Equal(content.Length, decrypted.Length);
            Assert.Equal(content, decrypted.GetBuffer().Take((int)decrypted.Length).ToArray());
        }

        [Fact]
        public async Task ProtectAsyncPreCancelledFail()
        {
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32]);
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
            var p = new TestPackageProtector(packageSize: MinPackageSize);

            using var key = new PackageKey(new byte[32]);

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
            var p = new TestPackageProtector(packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(5));
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
            var p = new TestPackageProtector(ivSize: ivSize, packageSize: 256);

            using var key = new PackageKey(new byte[32].Fill(91));

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
            var p = new TestPackageProtector(ivSize: 16, packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(71));
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
            var p = new TestPackageProtector(packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(17));

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
            var p = new TestPackageProtector(packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(53));

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
            var p = new TestPackageProtector(packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(61));

            var contentBytes = new byte[p.MaxContentSize + 5].Fill(200);

            var package = new MemoryStream();

            long protectedLen = await p.ProtectAsync(new MemoryStream(contentBytes), package, key);

            Assert.Equal(package.Length, protectedLen);
        }

        [Fact]
        public async Task ProtectValidationPrecedencePass()
        {
            // Validation order: content -> package -> key ->
            // associatedData. Each check must take precedence over the next.
            var p = new TestPackageProtector(packageSize: 128);

            using var validKey = new PackageKey(new byte[32]);

            // content null wins over everything.
            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.ProtectAsync(null, null, null));
            Assert.Equal("content", ex.ParamName);

            // package null wins over key null.
            ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.ProtectAsync(Stream.Null, null, null));
            Assert.Equal("package", ex.ParamName);

            // key null wins over associatedData.
            ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.ProtectAsync(Stream.Null, Stream.Null, null));
            Assert.Equal("key", ex.ParamName);

            // associatedData is reported last.
            var exRange = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.ProtectAsync(Stream.Null, Stream.Null, validKey, new byte[1024]));
            Assert.Equal("associatedData", exRange.ParamName);
        }

        [Fact]
        public async Task UnprotectValidationPrecedencePass()
        {
            // Validation order: package -> content -> key ->
            // associatedData. Each check must take precedence over the next.
            var p = new TestPackageProtector(packageSize: 128);

            using var validKey = new PackageKey(new byte[32]);

            // package null wins over everything.
            var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.UnprotectAsync(null, null, null));
            Assert.Equal("package", ex.ParamName);

            // content null wins over key null.
            ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.UnprotectAsync(Stream.Null, null, null));
            Assert.Equal("content", ex.ParamName);

            // key null wins over associatedData.
            ex = await Assert.ThrowsAsync<ArgumentNullException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, null));
            Assert.Equal("key", ex.ParamName);

            // associatedData is reported last.
            var exRange = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => p.UnprotectAsync(Stream.Null, Stream.Null, validKey, new byte[1024]));
            Assert.Equal("associatedData", exRange.ParamName);
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
            var p = new TestPackageProtector(packageSize: 128);

            using var key = new PackageKey(new byte[keySize].Fill(97));

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
            var p = new TestPackageProtector(ivSize: 16, packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(151));
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
            var p = new TestPackageProtector(ivSize: 16, packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(181));

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
            var p = new TestPackageProtector(packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(120));

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
            var p = new TestPackageProtector(packageSize: 128);

            using var key = new PackageKey(new byte[32].Fill(64));

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

