// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    internal static class HMACSHA256Extensions
    {
        public static void ComputeHash(this HMACSHA256 hmac, ReadOnlySpan<byte> source, Span<byte> destination)
        {
            const int HashSize = 32;

            if (!hmac.TryComputeHash(source, destination, out int bytesWritten) || bytesWritten != HashSize)
            {
                throw new CryptographicUnexpectedOperationException();
            }
        }
    }
}