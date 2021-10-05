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

                Assert.AreEqual("The derived key length cannot be zero or exceed 536870911 bytes. (Parameter 'derivedKey')", ex.Message);
            }
        }

        [TestMethod]
        [DataRow(int.MaxValue, int.MaxValue)]
        [DataRow(0, int.MaxValue)]
        [DataRow(int.MaxValue, 0)]
        [DataRow(0, 2147483638 + 1)]
        [DataRow(2147483638 + 1, 0)]
        [DataRow(1, 2147483638)]
        [DataRow(2147483638, 1)]
        [DataRow(1073741819 + 1, 1073741819)]
        [DataRow(1073741819, 1073741819 + 1)]
        public unsafe void BadLabelOrContextLengthFail(int labelLength, int contextLength)
        {
            var keyOut = new byte[16];

            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.ThrowsException<ArgumentException>(() => HMACExtensions.DeriveKey(hmac, new ReadOnlySpan<byte>((void*)0, labelLength), new ReadOnlySpan<byte>((void*)0, contextLength), keyOut));

                Assert.AreEqual(null, ex.ParamName);

                Assert.AreEqual("The combined length of 'label' and 'context' cannot exceed 2147483638 bytes.", ex.Message);
            }
        }

        [TestMethod]
        [DataRow(int.MaxValue)]
        [DataRow(0)]
        [DataRow(int.MaxValue / 4 + 1)]
        public unsafe void BadDerivedKeyLengthFail(int derivedKeyLength)
        {
            var keyOut = new byte[16];

            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => HMACExtensions.DeriveKey(hmac, Span<byte>.Empty, Span<byte>.Empty, new Span<byte>((void*)0, derivedKeyLength)));

                Assert.AreEqual("derivedKey", ex.ParamName);

                Assert.AreEqual("The derived key length cannot be zero or exceed 536870911 bytes. (Parameter 'derivedKey')", ex.Message);
            }
        }
    }
}