// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    [TestClass]
    public class BadPasswordExceptionTests
    {
        [TestMethod]
        public void CreateBadPasswordExceptionPass()
        {
            var customMsg = "My msg.";

            var ex = new BadPasswordException();
            Assert.AreNotEqual(null, ex.Message);

            ex = new BadPasswordException(customMsg);
            Assert.AreEqual(customMsg, ex.Message);

            ex = new BadPasswordException(null);
            Assert.AreNotEqual(null, ex.Message);

            var argEx = new ArgumentException();
            ex = new BadPasswordException(customMsg, argEx);
            Assert.AreEqual(customMsg, ex.Message);
            Assert.AreEqual(argEx, ex.InnerException);

            ex = new BadPasswordException(customMsg, null);
            Assert.AreEqual(customMsg, ex.Message);

            var argNullEx = new ArgumentNullException();
            ex = new BadPasswordException(null, argNullEx);
            Assert.AreNotEqual(null, ex.Message);
            Assert.AreEqual(argNullEx, ex.InnerException);
        }
    }
}