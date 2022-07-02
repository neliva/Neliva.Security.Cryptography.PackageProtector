// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// The exception that is thrown when the provided password is incorrect.
    /// </summary>
    /// <seealso cref="KeyProtector.Unprotect(ReadOnlySpan{byte}, Span{byte}, ReadOnlySpan{char}, ReadOnlySpan{byte})"/>
    public sealed class BadPasswordException : CryptographicException
    {
        private static readonly string BadPasswordMsg = "The provided password is incorrect.";

        /// <summary>
        /// Initializes a new instance of the <see cref="BadPackageException"/> class
        /// with default properties.
        /// </summary>
        public BadPasswordException() 
            : base(BadPasswordMsg)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BadPackageException"/> class
        /// with a specified error message.
        /// </summary>
        /// <param name="message">
        /// The error message that explains the reason for the exception.
        /// </param>
        public BadPasswordException(string message)
            : base(string.IsNullOrEmpty(message) ? BadPasswordMsg : message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BadPackageException"/> class
        /// with a specified error message and a reference to the inner exception that
        /// is the cause of this exception.
        /// </summary>
        /// <param name="message">
        /// The error message that explains the reason for the exception.
        /// </param>
        /// <param name="inner">
        /// The exception that is the cause of the current exception.
        /// If the <paramref name="inner"/> parameter is not <c>null</c>,
        /// the current exception is raised in a <c>catch</c> block that
        /// handles the inner exception.
        /// </param>
        public BadPasswordException(string message, Exception inner)
            : base(string.IsNullOrEmpty(message) ? BadPasswordMsg : message, inner)
        {
        }
    }
}