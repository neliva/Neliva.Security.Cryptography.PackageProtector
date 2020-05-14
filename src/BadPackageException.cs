// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    [Serializable]
    public sealed class BadPackageException : CryptographicException
    {
        private static readonly string BadPackageMsg = "Package is invalid or corrupted.";

        public BadPackageException() 
            : base(BadPackageMsg)
        {
        }

        public BadPackageException(string message)
            : base(string.IsNullOrEmpty(message) ? BadPackageMsg : message)
        {
        }

        public BadPackageException(string message, Exception inner)
            : base(string.IsNullOrEmpty(message) ? BadPackageMsg : message, inner)
        {
        }

        private BadPackageException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}