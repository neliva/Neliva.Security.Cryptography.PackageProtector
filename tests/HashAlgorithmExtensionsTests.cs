// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Xunit;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    public class HashAlgorithmExtensionsTests
    {
        [Fact]
        public void ComputeHashNullAlgoArgFail()
        {
            var ex = Assert.Throws<ArgumentNullException>(() => HashAlgorithmExtensions.ComputeHash(null, Span<byte>.Empty, Span<byte>.Empty));

            Assert.Equal("alg", ex.ParamName);
        }

        [Theory]
        [InlineData(16, 0)]
        [InlineData(16, 31)]
        public void ComputeHashBadArgsFail(int sourceLength, int destinationLength)
        {
            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.Throws<ArgumentOutOfRangeException>(() => hmac.ComputeHash(new byte[sourceLength], new byte[destinationLength]));

                Assert.Equal("destination", ex.ParamName);
            }
        }

        [Theory]
        [InlineData(0, 32)]
        [InlineData(5, 33)]
        public void ComputeHashPass(int sourceLength, int destinationLength)
        {
            using (var hmac = new HMACSHA256())
            {
                hmac.ComputeHash(new byte[sourceLength], new byte[destinationLength]);
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(63)]
        [InlineData(64)]
        [InlineData(100)]
        public void ComputeHashMatchesReferencePass(int sourceLength)
        {
            var key = new byte[32];

            for (int i = 0; i < key.Length; i++)
            {
                key[i] = (byte)(i + 1);
            }

            var source = new byte[sourceLength];

            for (int i = 0; i < source.Length; i++)
            {
                source[i] = (byte)i;
            }

            var expected = new byte[32];
            HMACSHA256.HashData(key, source, expected);

            using (var hmac = new HMACSHA256(key))
            {
                var actual = new byte[32];

                hmac.ComputeHash(source, actual);

                Assert.Equal(expected, actual);
            }
        }
    }
}
