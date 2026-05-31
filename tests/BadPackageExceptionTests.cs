// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    public class BadPackageExceptionTests
    {
        [Fact]
        public void CreateBadPackageExceptionPass()
        {
            var customMsg = "My msg.";

            var ex = new BadPackageException();
            Assert.NotNull(ex.Message);

            ex = new BadPackageException(customMsg);
            Assert.Equal(customMsg, ex.Message);

            ex = new BadPackageException(null);
            Assert.NotNull(ex.Message);

            var argEx = new ArgumentException();
            ex = new BadPackageException(customMsg, argEx);
            Assert.Equal(customMsg, ex.Message);
            Assert.Equal(argEx, ex.InnerException);

            ex = new BadPackageException(customMsg, null);
            Assert.Equal(customMsg, ex.Message);

            var argNullEx = new ArgumentNullException();
            ex = new BadPackageException(null, argNullEx);
            Assert.NotNull(ex.Message);
            Assert.Equal(argNullEx, ex.InnerException);
        }

        [Fact]
        public void CreateBadPackageExceptionEmptyMessageUsesDefaultPass()
        {
            var defaultMsg = new BadPackageException().Message;

            var ex = new BadPackageException(string.Empty);
            Assert.Equal(defaultMsg, ex.Message);

            var argEx = new ArgumentException();
            ex = new BadPackageException(string.Empty, argEx);
            Assert.Equal(defaultMsg, ex.Message);
            Assert.Equal(argEx, ex.InnerException);
        }
    }
}
