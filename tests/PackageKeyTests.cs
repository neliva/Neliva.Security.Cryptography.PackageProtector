// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Xunit;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    public class PackageKeyTests
    {
        private const int MinKeySize = 32;
        private const int MaxKeySize = 64;
        private const int MaxLabelContextLength = 102;

        private static byte[] ReferenceDeriveKey(byte[] key, byte[] label, byte[] context, int destinationLength)
        {
            var expected = new byte[destinationLength];

            using (var kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA512))
            {
                kdf.DeriveKey(label, context, expected);
            }

            return expected;
        }

        [Theory]
        [InlineData(MinKeySize)]
        [InlineData(48)]
        [InlineData(MaxKeySize)]
        public void CreateValidKeySizePass(int keySize)
        {
            using var pk = new PackageKey(new byte[keySize].Fill((byte)keySize));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(MinKeySize - 1)]
        [InlineData(MaxKeySize + 1)]
        [InlineData(128)]
        public void CreateInvalidKeySizeFail(int keySize)
        {
            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new PackageKey(new byte[keySize]));

            Assert.Equal("key", ex.ParamName);
            Assert.Equal("Key length must be between 32 and 64 bytes. (Parameter 'key')", ex.Message);
        }

        [Fact]
        public void DeriveKeyEmptyLabelFail()
        {
            using var pk = new PackageKey(new byte[MinKeySize]);

            var ex = Assert.Throws<ArgumentException>(() => pk.DeriveKey(ReadOnlySpan<byte>.Empty, new byte[1], new byte[MinKeySize]));

            Assert.Equal("label", ex.ParamName);
        }

        [Fact]
        public void DeriveKeyEmptyContextFail()
        {
            using var pk = new PackageKey(new byte[MinKeySize]);

            var ex = Assert.Throws<ArgumentException>(() => pk.DeriveKey(new byte[1], ReadOnlySpan<byte>.Empty, new byte[MinKeySize]));

            Assert.Equal("context", ex.ParamName);
        }

        [Theory]
        [InlineData(1, MaxLabelContextLength)]
        [InlineData(MaxLabelContextLength, 1)]
        [InlineData(MaxLabelContextLength / 2, MaxLabelContextLength)]
        [InlineData(MaxLabelContextLength, MaxLabelContextLength)]
        public void DeriveKeyCombinedLengthTooLongFail(int labelLength, int contextLength)
        {
            using var pk = new PackageKey(new byte[MinKeySize]);

            var ex = Assert.Throws<ArgumentException>(() => pk.DeriveKey(new byte[labelLength], new byte[contextLength], new byte[MinKeySize]));

            Assert.Null(ex.ParamName);
            Assert.Equal("The combined length of label and context must not exceed 102 bytes.", ex.Message);
        }

        [Theory]
        [InlineData(1, 1)]
        [InlineData(1, MaxLabelContextLength - 1)]
        [InlineData(MaxLabelContextLength - 1, 1)]
        [InlineData(MaxLabelContextLength / 2, MaxLabelContextLength / 2)]
        public void DeriveKeyCombinedLengthBoundaryPass(int labelLength, int contextLength)
        {
            using var pk = new PackageKey(new byte[MinKeySize]);

            // Combined length is exactly at or below the limit; must not throw.
            pk.DeriveKey(new byte[labelLength], new byte[contextLength], new byte[MinKeySize]);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(MinKeySize - 1)]
        [InlineData(MaxKeySize + 1)]
        [InlineData(128)]
        public void DeriveKeyInvalidDestinationSizeFail(int destinationLength)
        {
            using var pk = new PackageKey(new byte[MinKeySize]);

            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => pk.DeriveKey(new byte[1], new byte[1], new byte[destinationLength]));

            Assert.Equal("destination", ex.ParamName);
            Assert.Equal("Destination length must be between 32 and 64 bytes. (Parameter 'destination')", ex.Message);
        }

        [Theory]
        [InlineData(MinKeySize)]
        [InlineData(48)]
        [InlineData(MaxKeySize)]
        public void DeriveKeyValidDestinationSizePass(int destinationLength)
        {
            using var pk = new PackageKey(new byte[MinKeySize].Fill(7));

            pk.DeriveKey(new byte[1].Fill(1), new byte[1].Fill(2), new byte[destinationLength]);
        }

        [Theory]
        [InlineData(MinKeySize, MinKeySize)]
        [InlineData(48, 48)]
        [InlineData(MaxKeySize, MaxKeySize)]
        public void DeriveKeyMatchesReferenceKdfPass(int keySize, int destinationLength)
        {
            var key = new byte[keySize].Fill((byte)keySize);
            var label = new byte[] { 1, 2, 3, 4 };
            var context = new byte[] { 9, 8, 7 };

            using var pk = new PackageKey(key);

            var actual = new byte[destinationLength];
            pk.DeriveKey(label, context, actual);

            var expected = ReferenceDeriveKey(key, label, context, destinationLength);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void DeriveKeyIsDeterministicPass()
        {
            var key = new byte[MinKeySize].Fill(42);
            var label = new byte[] { 10, 20, 30 };
            var context = new byte[] { 40, 50 };

            using var pk = new PackageKey(key);

            var first = new byte[MaxKeySize];
            var second = new byte[MaxKeySize];

            pk.DeriveKey(label, context, first);
            pk.DeriveKey(label, context, second);

            Assert.Equal(first, second);
        }

        [Fact]
        public void DeriveKeyDifferentLabelProducesDifferentKeyPass()
        {
            var key = new byte[MinKeySize].Fill(42);
            var context = new byte[] { 1 };

            using var pk = new PackageKey(key);

            var a = new byte[MinKeySize];
            var b = new byte[MinKeySize];

            pk.DeriveKey(new byte[] { 1 }, context, a);
            pk.DeriveKey(new byte[] { 2 }, context, b);

            Assert.NotEqual(a, b);
        }

        [Fact]
        public void DeriveKeyDifferentContextProducesDifferentKeyPass()
        {
            var key = new byte[MinKeySize].Fill(42);
            var label = new byte[] { 1 };

            using var pk = new PackageKey(key);

            var a = new byte[MinKeySize];
            var b = new byte[MinKeySize];

            pk.DeriveKey(label, new byte[] { 1 }, a);
            pk.DeriveKey(label, new byte[] { 2 }, b);

            Assert.NotEqual(a, b);
        }

        [Fact]
        public void DeriveKeyValidationPrecedencePass()
        {
            // When multiple arguments are invalid at once, DeriveKey must report them
            // in this documented order: label -> context -> combined length -> destination.
            using var pk = new PackageKey(new byte[MinKeySize]);

            var tooLongLabel = new byte[MaxLabelContextLength];
            var tooLongContext = new byte[MaxLabelContextLength];
            var invalidDestination = new byte[1];

            // label (empty) wins over context, combined length, destination.
            var exLabel = Assert.Throws<ArgumentException>(
                () => pk.DeriveKey(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, invalidDestination));
            Assert.Equal("label", exLabel.ParamName);

            // context (empty) wins over combined length, destination.
            var exContext = Assert.Throws<ArgumentException>(
                () => pk.DeriveKey(tooLongLabel, ReadOnlySpan<byte>.Empty, invalidDestination));
            Assert.Equal("context", exContext.ParamName);

            // combined length wins over destination.
            var exCombined = Assert.Throws<ArgumentException>(
                () => pk.DeriveKey(tooLongLabel, tooLongContext, invalidDestination));
            Assert.Null(exCombined.ParamName);

            // destination is reported last.
            var exDestination = Assert.Throws<ArgumentOutOfRangeException>(
                () => pk.DeriveKey(new byte[1], new byte[1], invalidDestination));
            Assert.Equal("destination", exDestination.ParamName);
        }

        [Fact]
        public void DeriveKeyAfterDisposeFail()
        {
            var pk = new PackageKey(new byte[MinKeySize]);

            pk.Dispose();

            Assert.Throws<ObjectDisposedException>(() => pk.DeriveKey(new byte[1], new byte[1], new byte[MinKeySize]));
        }

        [Fact]
        public void DisposeIsIdempotentPass()
        {
            var pk = new PackageKey(new byte[MinKeySize]);

            pk.Dispose();
            pk.Dispose();
        }
    }
}
