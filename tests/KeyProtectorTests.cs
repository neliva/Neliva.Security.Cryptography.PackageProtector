// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    [TestClass]
    public class KeyProtectorTests
    {
        [TestMethod]
        public void RoundTripPass()
        {
            var password = "user-password";
            var iterations = 2;

            using var protector = new KeyProtector();

            var key = new byte[32];

            var protectedKey = new byte[key.Length + protector.Overhead];

            int protectedLength = protector.Protect(key, protectedKey, password, iterations);

            Assert.AreEqual(protectedKey.Length, protectedLength);

            var unprotectedKey = new byte[key.Length];

            int unprotectedLength = protector.Unprotect(protectedKey, unprotectedKey, password);

            Assert.AreEqual(unprotectedKey.Length, unprotectedLength);

            CollectionAssert.AreEquivalent(key, unprotectedKey);
        }
    }
}