// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides extension methods for the <see cref="Aes"/> class.
    /// </summary>
    internal static class AesExtensions
    {
        private const int BlockSize = 16;

        private static ReadOnlySpan<byte> ZeroIV => new byte[BlockSize] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        public static void EncryptCbcNoPadding(this Aes aes, ReadOnlySpan<byte> plaintext, Span<byte> destination, ReadOnlySpan<byte> iv = default)
        {
            ReadOnlySpan<byte> useIV = iv.IsEmpty ? ZeroIV : iv;

            aes.EncryptCbc(plaintext, useIV, destination, PaddingMode.None);
        }

        public static void DecryptCbcNoPadding(this Aes aes, ReadOnlySpan<byte> ciphertext, Span<byte> destination, ReadOnlySpan<byte> iv = default)
        {
            ReadOnlySpan<byte> useIV = iv.IsEmpty ? ZeroIV : iv;

            aes.DecryptCbc(ciphertext, useIV, destination, PaddingMode.None);
        }
    }
}
