// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverageAttribute]
    [TestClass]
    public class HMACExtensionsTests
    {
        [TestMethod]
        public void NullHmacFail()
        {
            var keyOut = new byte[32];

            var ex = Assert.ThrowsException<ArgumentNullException>(() => HMACExtensions.DeriveKey(null, Span<byte>.Empty, Span<byte>.Empty, keyOut));

            Assert.AreEqual("hmac", ex.ParamName);
        }

        [TestMethod]
        public void EmptyDerivedKeyFail()
        {
            var keyOut = new byte[0];

            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => HMACExtensions.DeriveKey(hmac, Span<byte>.Empty, Span<byte>.Empty, keyOut));

                Assert.AreEqual("derivedKey", ex.ParamName);
            }
        }
    }
}