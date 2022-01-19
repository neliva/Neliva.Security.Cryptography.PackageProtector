// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// The exception that is thrown when package decryption fails.
    /// </summary>
    /// <seealso cref="PackageProtector.UnprotectAsync(System.IO.Stream, System.IO.Stream, byte[], ArraySegment{byte}, System.Threading.CancellationToken)"/>
    /// <seealso cref="PackageProtector.Unprotect(ArraySegment{byte}, ArraySegment{byte}, byte[], long, ArraySegment{byte})"/>
    [Serializable]
    public sealed class BadPackageException : CryptographicException
    {
        private static readonly string BadPackageMsg = "Package is invalid or corrupted.";

        /// <summary>
        /// Initializes a new instance of the <see cref="BadPackageException"/> class
        /// with default properties.
        /// </summary>
        public BadPackageException() 
            : base(BadPackageMsg)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BadPackageException"/> class
        /// with a specified error message.
        /// </summary>
        /// <param name="message">
        /// The error message that explains the reason for the exception.
        /// </param>
        public BadPackageException(string message)
            : base(string.IsNullOrEmpty(message) ? BadPackageMsg : message)
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
        public BadPackageException(string message, Exception inner)
            : base(string.IsNullOrEmpty(message) ? BadPackageMsg : message, inner)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BadPackageException"/> class
        /// with serialized data.
        /// </summary>
        /// <param name="info">
        /// The object that holds the serialized object data.
        /// </param>
        /// <param name="context">
        /// The contextual information about the source or destination.
        /// </param>
        /// <remarks>
        /// This constructor is called during deserialization to reconstitute
        /// the exception object transmitted over a stream.
        /// </remarks>
        private BadPackageException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}