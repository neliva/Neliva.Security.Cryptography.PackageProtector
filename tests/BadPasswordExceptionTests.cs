// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    public class BadPasswordExceptionTests
    {
        [Fact]
        public void CreateBadPasswordExceptionPass()
        {
            var customMsg = "My msg.";

            var ex = new BadPasswordException();
            Assert.NotNull(ex.Message);

            ex = new BadPasswordException(customMsg);
            Assert.Equal(customMsg, ex.Message);

            ex = new BadPasswordException(null);
            Assert.NotNull(ex.Message);

            var argEx = new ArgumentException();
            ex = new BadPasswordException(customMsg, argEx);
            Assert.Equal(customMsg, ex.Message);
            Assert.Equal(argEx, ex.InnerException);

            ex = new BadPasswordException(customMsg, null);
            Assert.Equal(customMsg, ex.Message);

            var argNullEx = new ArgumentNullException();
            ex = new BadPasswordException(null, argNullEx);
            Assert.NotNull(ex.Message);
            Assert.Equal(argNullEx, ex.InnerException);
        }

        [Fact]
        public void CreateBadPasswordExceptionEmptyMessageUsesDefaultPass()
        {
            var defaultMsg = new BadPasswordException().Message;

            var ex = new BadPasswordException(string.Empty);
            Assert.Equal(defaultMsg, ex.Message);

            var argEx = new ArgumentException();
            ex = new BadPasswordException(string.Empty, argEx);
            Assert.Equal(defaultMsg, ex.Message);
            Assert.Equal(argEx, ex.InnerException);
        }
    }
}
