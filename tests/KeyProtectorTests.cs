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
            var iterations = 1;

            using var protector = new KeyProtector();

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            int protectedLength = protector.Protect(content, package, password, iterations);

            Assert.AreEqual(package.Length, protectedLength);

            var unprotectedContent = new byte[content.Length];

            int unprotectedLength = protector.Unprotect(package, unprotectedContent, password);

            Assert.AreEqual(unprotectedContent.Length, unprotectedLength);

            CollectionAssert.AreEquivalent(content, unprotectedContent);
        }

        [TestMethod]
        public void IncorrectPasswordFails()
        {
            var iterations = 1;

            using var protector = new KeyProtector();

            var content = new byte[32].Fill(223);

            var package = new byte[content.Length + protector.Overhead];

            protector.Protect(content, package, "user-password", iterations);

            var unprotectedContent = new byte[content.Length].Fill(88);

            var ex = Assert.ThrowsException<CryptographicException>(() => protector.Unprotect(package, unprotectedContent, "bad-user-password"));
            Assert.AreEqual("The provided password is incorrect.", ex.Message);

            Assert.IsTrue(unprotectedContent.IsAllZeros(), "Destination not cleared on Protect() failure.");
        }

        [TestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(16)]
        [DataRow(31)]
        [DataRow(33)]
        [DataRow(47)]
        public void ProtectBadContentFails(int contentLength)
        {
            var password = "user-password";
            var iterations = 2;

            using var protector = new KeyProtector();

            var content = new byte[contentLength];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, iterations));

            Assert.AreEqual("content", ex.ParamName);
            Assert.AreEqual("Content length is invalid or not aligned on the required boundary. (Parameter 'content')", ex.Message);
        }

        [TestMethod]
        public void ProtectBadPackageSpaceFails()
        {
            var password = "user-password";
            var iterations = 2;

            using var protector = new KeyProtector();

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead - 1];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, iterations));

            Assert.AreEqual("package", ex.ParamName);
            Assert.AreEqual("Insufficient space for package output. (Parameter 'package')", ex.Message);
        }

        [TestMethod]
        [DataRow(int.MinValue)]
        [DataRow(-1)]
        [DataRow(0)]
        public void ProtectBadIterationsFails(int iterations)
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => protector.Protect(content, package, password, iterations));

            Assert.AreEqual("iterations", ex.ParamName);
        }

        [TestMethod]
        public void ProtectOverlapFails()
        {
            var password = "user-password";

            using var protector = new KeyProtector();

            var ex = Assert.ThrowsException<InvalidOperationException>(() =>
            {
                Span<byte> buf = new byte[32 + protector.Overhead + 32];

                var content = buf.Slice(32 + protector.Overhead, 32);

                var package = buf.Slice(1, 32 + protector.Overhead);

                protector.Protect(content, package, password, 1);
            });

            Assert.AreEqual("The 'package' must not overlap in memory with the 'content'.", ex.Message);
        }

        [TestMethod]
        public void ProtectUseAfterDisposeFail()
        {
            using var protector = new KeyProtector();

            protector.Dispose();

            var password = "user-password";
            var iterations = 2;

            var content = new byte[32];

            var package = new byte[content.Length + protector.Overhead];

            var ex = Assert.ThrowsException<ObjectDisposedException>(() => protector.Protect(content, package, password, iterations));
            Assert.AreEqual(typeof(KeyProtector).FullName, ex.ObjectName);
        }

        [TestMethod]
        public void ProtectClearOutputOnFailurePass()
        {
            var password = "user-password";
            var iterations = 1;

            const string exStr = "CRNG FAILED";
            byte[] rngVal = Array.Empty<byte>();

            RngFillAction rng = (Span<byte> data) =>
            {
                if (data.Length == 0 || rngVal.Length != 0)
                {
                    throw new AssertFailedException("Callback is not operating properly.");
                }

                Assert.AreEqual(40, data.Length);

                rngVal = new byte[data.Length].Fill((byte)data.Length);

                rngVal.AsSpan().CopyTo(data);

                throw new Exception(exStr);
            };

            using var protector = new KeyProtector(rng);

            var content = new byte[32].Fill(223);
            var package = new byte[32 + protector.Overhead].Fill(88);

            var ex = Assert.ThrowsException<Exception>(() => protector.Protect(content, package, password, iterations));
            Assert.AreEqual(exStr, ex.Message);

            Assert.IsTrue(package.IsAllZeros(), "Destination not cleared on Protect() failure.");
        }
    }
}