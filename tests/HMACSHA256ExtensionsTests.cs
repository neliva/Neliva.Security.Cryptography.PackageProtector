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
    public class HMACSHA256ExtensionsTests
    {
        [TestMethod]
        public void ComputeHashBadArgsFail()
        {
            using (var hmac = new HMACSHA256())
            {
                Assert.ThrowsException<CryptographicUnexpectedOperationException>(() => hmac.ComputeHash(new byte[16], Array.Empty<byte>()));
                Assert.ThrowsException<CryptographicUnexpectedOperationException>(() => hmac.ComputeHash(new byte[16], new byte[31]));
            }
        }

        [TestMethod]
        public void ComputeHashPass()
        {
            using (var hmac = new HMACSHA256())
            {
                hmac.ComputeHash(Array.Empty<byte>(), new byte[32]);
                hmac.ComputeHash(new byte[5], new byte[33]);
            }
        }
    }
}
