// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    [TestClass]
    public class BadPackageExceptionTests
    {
        [TestMethod]
        public void CreateBadPackageExceptionPass()
        {
            var customMsg = "My msg.";

            var ex = new BadPackageException();
            Assert.AreNotEqual(null, ex.Message);

            ex = new BadPackageException(customMsg);
            Assert.AreEqual(customMsg, ex.Message);

            ex = new BadPackageException(null);
            Assert.AreNotEqual(null, ex.Message);

            var argEx = new ArgumentException();
            ex = new BadPackageException(customMsg, argEx);
            Assert.AreEqual(customMsg, ex.Message);
            Assert.AreEqual(argEx, ex.InnerException);

            ex = new BadPackageException(customMsg, null);
            Assert.AreEqual(customMsg, ex.Message);

            var argNullEx = new ArgumentNullException();
            ex = new BadPackageException(null, argNullEx);
            Assert.AreNotEqual(null, ex.Message);
            Assert.AreEqual(argNullEx, ex.InnerException);
        }

        [TestMethod]
        public void BadPackageExceptionSerializePass()
        {
            var sourceEx = new BadPackageException("My custom message for serialization.");

            using (var stream = new MemoryStream())
            {
                try
                {
                    BinaryFormatter formatter = new BinaryFormatter(null, new StreamingContext(StreamingContextStates.File));
                    formatter.Serialize(stream, sourceEx);

                    stream.Position = 0; // rewind for reading

                    var deserializedException = (BadPackageException)formatter.Deserialize(stream);
                    throw deserializedException;
                }
                catch (BadPackageException ex)
                {
                    Assert.AreEqual(sourceEx.Message, ex.Message);
                }
            }
        }
    }
}