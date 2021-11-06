// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides extension methods for <see cref="HashAlgorithm"/> implementations.
    /// </summary>
    public static class HashAlgorithmExtensions
    {
        /// <summary>
        /// Computes the hash value for the specified <paramref name="source"/>.
        /// </summary>
        /// <param name="alg">
        /// The hash algorithm instance.
        /// </param>
        /// <param name="source">
        /// The input for which to compute the hash.
        /// </param>
        /// <param name="destination">
        /// The buffer to receive the hash value.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="alg"/> parameter is a <c>null</c> reference.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="destination"/> span does not have enough space to
        /// receive the computed hash.
        /// </exception>
        public static void ComputeHash(this HashAlgorithm alg, ReadOnlySpan<byte> source, Span<byte> destination)
        {
            if (alg == null)
            {
                throw new ArgumentNullException(nameof(alg));
            }

            if (!alg.TryComputeHash(source, destination, out int bytesWritten) || bytesWritten != (alg.HashSize / 8))
            {
                throw new ArgumentOutOfRangeException(nameof(destination));
            }
        }
    }
}
