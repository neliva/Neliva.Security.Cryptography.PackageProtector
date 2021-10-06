// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    internal static class HashAlgorithmExtensions
    {
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