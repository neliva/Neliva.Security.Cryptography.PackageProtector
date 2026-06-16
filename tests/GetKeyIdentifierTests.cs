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
    public class GetKeyIdentifierTests
    {
        private const int MinKeySize = 32;
        private const int MaxKeySize = 64;
        private const int MaxContextSize = 64;

        // Independent reference implementation of the two-stage derivation that
        // Package.GetKeyIdentifier performs. Computed directly from the documented
        // labels, the fixed all-zero stage 1 context, and the length-prefixed stage 2
        // context, so a byte-for-byte match proves the production code is correct.
        private static Guid ReferenceKeyIdentifier(byte[] masterKey, ReadOnlySpan<byte> context)
        {
            ReadOnlySpan<byte> keyLabel = Encoding.UTF8.GetBytes("R7NSHARGV1R6YA4H36VQ61JJCAJ2115QS2RXVF6CMZ6S9VQWF4JMAK1PRSJ7JCTE__KEY_IDENTIFIER_KEY_V20260615");
            ReadOnlySpan<byte> keyContext = stackalloc byte[sizeof(uint)]; // all zero
            ReadOnlySpan<byte> idLabel = Encoding.UTF8.GetBytes("KEY_IDENTIFIER_V20260615");

            // Stage 1: derive the 64 byte intermediate key.
            Span<byte> stage1Key = stackalloc byte[MaxKeySize];

            using (var kdf1 = new SP800108HmacCounterKdf(masterKey, HashAlgorithmName.SHA512))
            {
                kdf1.DeriveKey(keyLabel, keyContext, stage1Key);
            }

            // Stage 2: build [uint32-BE length][context] and derive 64 bytes.
            Span<byte> idContext = stackalloc byte[sizeof(uint) + MaxContextSize];

            BinaryPrimitives.WriteUInt32BigEndian(idContext, (uint)context.Length);
            context.CopyTo(idContext.Slice(sizeof(uint)));

            Span<byte> id64 = stackalloc byte[MaxKeySize];

            using (var kdf2 = new SP800108HmacCounterKdf(stage1Key, HashAlgorithmName.SHA512))
            {
                kdf2.DeriveKey(idLabel, idContext.Slice(0, sizeof(uint) + context.Length), id64);
            }

            Span<byte> id = id64.Slice(0, 16);

            id[6] = (byte)((id[6] & 0x0F) | 0x40);
            id[8] = (byte)((id[8] & 0x3F) | 0x80);

            return new Guid(id, bigEndian: true);
        }

        // --- Argument validation ---

        [Fact]
        public void NullKeyFail()
        {
            var ex = Assert.Throws<ArgumentNullException>(() => Package.GetKeyIdentifier(null, new byte[1]));

            Assert.Equal("key", ex.ParamName);
        }

        [Theory]
        [InlineData(65)]
        [InlineData(80)]
        [InlineData(256)]
        public void ContextTooLargeFail(int contextSize)
        {
            using var key = new PackageKey(new byte[MinKeySize]);

            var ex = Assert.Throws<ArgumentException>(() => Package.GetKeyIdentifier(key, new byte[contextSize]));

            Assert.Equal("context", ex.ParamName);
            Assert.Equal("Context must not exceed 64 bytes. (Parameter 'context')", ex.Message);
        }

        [Fact]
        public void DefaultContextEquivalentToEmptyPass()
        {
            using var key = new PackageKey(new byte[MinKeySize].Fill(7));

            var fromDefault = Package.GetKeyIdentifier(key);
            var fromEmpty = Package.GetKeyIdentifier(key, ReadOnlySpan<byte>.Empty);
            var fromZeroLength = Package.GetKeyIdentifier(key, new byte[0]);

            Assert.Equal(fromDefault, fromEmpty);
            Assert.Equal(fromDefault, fromZeroLength);
        }

        // --- Correctness against the independent reference ---

        [Theory]
        [InlineData(MinKeySize, 0)]
        [InlineData(MinKeySize, 1)]
        [InlineData(MinKeySize, 16)]
        [InlineData(MinKeySize, 63)]
        [InlineData(MinKeySize, MaxContextSize)]
        [InlineData(48, 16)]
        [InlineData(MaxKeySize, 0)]
        [InlineData(MaxKeySize, 32)]
        [InlineData(MaxKeySize, MaxContextSize)]
        public void MatchesReferencePass(int keySize, int contextSize)
        {
            var keyBytes = new byte[keySize].Fill((byte)keySize);
            var context = new byte[contextSize].Fill((byte)(contextSize + 1));

            using var key = new PackageKey(keyBytes);

            var actual = Package.GetKeyIdentifier(key, context);
            var expected = ReferenceKeyIdentifier(keyBytes, context);

            Assert.Equal(expected, actual);
        }

        // --- RFC 4122 version 4 / variant conformance ---

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(32)]
        [InlineData(MaxContextSize)]
        public void ProducesValidVersion4GuidPass(int contextSize)
        {
            using var key = new PackageKey(new byte[MinKeySize].Fill(13));

            var id = Package.GetKeyIdentifier(key, new byte[contextSize].Fill(9));

            Assert.NotEqual(Guid.Empty, id);

            // RFC 4122 / RFC 9562 layout is verified on the big-endian byte ordering.
            Span<byte> bytes = stackalloc byte[16];
            Assert.True(id.TryWriteBytes(bytes, bigEndian: true, out _));

            // Version nibble (high nibble of byte 6) must be 4.
            Assert.Equal(0x40, bytes[6] & 0xF0);

            // Variant (two most significant bits of byte 8) must be 10xx.
            Assert.Equal(0x80, bytes[8] & 0xC0);

            // The built-in Guid version accessor agrees.
            Assert.Equal(4, id.Version);
        }

        // --- Determinism ---

        [Theory]
        [InlineData(0)]
        [InlineData(13)]
        [InlineData(MaxContextSize)]
        public void IsDeterministicPass(int contextSize)
        {
            var keyBytes = new byte[MinKeySize].Fill(42);
            var context = new byte[contextSize].Fill(200);

            using var key = new PackageKey(keyBytes);

            var first = Package.GetKeyIdentifier(key, context);
            var second = Package.GetKeyIdentifier(key, context);

            Assert.Equal(first, second);
        }

        [Fact]
        public void IsDeterministicAcrossKeyInstancesPass()
        {
            var keyBytes = new byte[MaxKeySize].Fill(17);
            var context = new byte[20].Fill(5);

            using var keyA = new PackageKey(keyBytes);
            using var keyB = new PackageKey(keyBytes);

            Assert.Equal(
                Package.GetKeyIdentifier(keyA, context),
                Package.GetKeyIdentifier(keyB, context));
        }

        // --- Distinctness ---

        [Fact]
        public void DifferentKeyProducesDifferentIdPass()
        {
            var context = new byte[8].Fill(1);

            using var keyA = new PackageKey(new byte[MinKeySize].Fill(1));
            using var keyB = new PackageKey(new byte[MinKeySize].Fill(2));

            Assert.NotEqual(
                Package.GetKeyIdentifier(keyA, context),
                Package.GetKeyIdentifier(keyB, context));
        }

        [Fact]
        public void DifferentContextProducesDifferentIdPass()
        {
            using var key = new PackageKey(new byte[MinKeySize].Fill(42));

            Assert.NotEqual(
                Package.GetKeyIdentifier(key, new byte[] { 1 }),
                Package.GetKeyIdentifier(key, new byte[] { 2 }));
        }

        [Fact]
        public void EmptyContextDiffersFromNonEmptyPass()
        {
            using var key = new PackageKey(new byte[MinKeySize].Fill(42));

            var empty = Package.GetKeyIdentifier(key, ReadOnlySpan<byte>.Empty);
            var oneZeroByte = Package.GetKeyIdentifier(key, new byte[1]); // single 0x00

            Assert.NotEqual(empty, oneZeroByte);
        }

        [Fact]
        public void LengthPrefixDisambiguatesContextsPass()
        {
            // Without length prefixing, a zero-padded shorter context could collide
            // with a longer one. Verify they remain distinct.
            using var key = new PackageKey(new byte[MinKeySize].Fill(42));

            var oneByte = Package.GetKeyIdentifier(key, new byte[] { 1 });
            var twoBytes = Package.GetKeyIdentifier(key, new byte[] { 1, 0 });
            var threeBytes = Package.GetKeyIdentifier(key, new byte[] { 1, 0, 0 });

            Assert.NotEqual(oneByte, twoBytes);
            Assert.NotEqual(oneByte, threeBytes);
            Assert.NotEqual(twoBytes, threeBytes);
        }

        [Fact]
        public void DistinctContextsAcrossFullRangeAreUniquePass()
        {
            // Exhaustively confirm uniqueness across context lengths 0..64 (each filled
            // with its own length value), exercising every valid length and boundary.
            using var key = new PackageKey(new byte[MaxKeySize].Fill(99));

            var seen = new System.Collections.Generic.HashSet<Guid>();

            for (int len = 0; len <= MaxContextSize; len++)
            {
                var id = Package.GetKeyIdentifier(key, new byte[len].Fill((byte)len));

                Assert.True(seen.Add(id), $"Duplicate identifier for context length {len}.");
            }

            Assert.Equal(MaxContextSize + 1, seen.Count);
        }
    }
}
