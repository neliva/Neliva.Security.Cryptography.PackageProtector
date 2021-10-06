// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    [TestClass]
    public class HashAlgorithmExtensionsTests
    {
        [TestMethod]
        public void ComputeHashNullAlgoArgFail()
        {
            var ex = Assert.ThrowsException<ArgumentNullException>(() => HashAlgorithmExtensions.ComputeHash(null, Span<byte>.Empty, Span<byte>.Empty));

            Assert.AreEqual("alg", ex.ParamName);
        }

        [TestMethod]
        [DataRow(16, 0)]
        [DataRow(16, 31)]
        public void ComputeHashBadArgsFail(int sourceLength, int destinationLength)
        {
            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => hmac.ComputeHash(new byte[sourceLength], new byte[destinationLength]));

                Assert.AreEqual("destination", ex.ParamName);
            }
        }

        [TestMethod]
        [DataRow(0, 32)]
        [DataRow(5, 33)]
        public void ComputeHashPass(int sourceLength, int destinationLength)
        {
            using (var hmac = new HMACSHA256())
            {
                hmac.ComputeHash(new byte[sourceLength], new byte[destinationLength]);
            }
        }
    }
}