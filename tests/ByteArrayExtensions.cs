// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    internal static class ByteArrayExtensions
    {
        public static byte[] Fill(this byte[] array, byte value)
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            Array.Fill<byte>(array, value);

            return array;
        }
    }
}