// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides helper methods for package protection.
    /// </summary>
    internal static class Package
    {
        public const int MacSize = HMACSHA512.HashSizeInBytes / 2;
        public const int AesBlockSize = 16;

        private static ReadOnlySpan<byte> ZeroIV => new byte[AesBlockSize] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

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

        /// <summary>
        /// Validates the PKCS7 padding in the last block of <paramref name="data"/>
        /// and returns the number of padding bytes.
        /// </summary>
        /// <param name="blockSize">
        /// The block size, in bytes, that the padding is aligned to.
        /// Must be between 1 and <see cref="byte.MaxValue"/> inclusive.
        /// </param>
        /// <param name="data">
        /// The data whose final block contains the PKCS7 padding to validate.
        /// Its length must be a non-zero multiple of <paramref name="blockSize"/>.
        /// </param>
        /// <returns>
        /// The number of padding bytes (between 1 and <paramref name="blockSize"/>)
        /// when the padding is valid; otherwise, -1.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="blockSize"/> is less than 1 or greater than <see cref="byte.MaxValue"/>.
        /// - or -
        /// The <paramref name="data"/> is empty.
        /// - or -
        /// The <paramref name="data"/> length is not a multiple of <paramref name="blockSize"/>.
        /// </exception>
        /// <remarks>
        /// The padding is verified in constant time with respect to the data
        /// contents, so the execution time does not reveal whether the padding is
        /// valid or how many padding bytes are present.
        /// <para>
        /// The <paramref name="data"/> must be authenticated (for example, by a
        /// verified message authentication code) before this method is called.
        /// Although the verification is constant time, the return value itself
        /// reveals whether the padding is valid. Calling this method on
        /// unauthenticated, attacker-controlled data and exposing that outcome
        /// (through an exception, error code, or any observable behavior) creates a
        /// padding oracle that can be used to decrypt or forge data without the key.
        /// </para>
        /// </remarks>
        public static int GetPKCS7PaddingLength(int blockSize, ReadOnlySpan<byte> data)
        {
            if (blockSize <= 0 || blockSize > byte.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize), "Value must be between 1 and 255.");
            }

            int dataLength = data.Length;

            if (dataLength == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(data), "Span is empty.");
            }

            if ((dataLength % blockSize) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(data), "Span length is not a multiple of block size.");
            }

            uint padLength = data[dataLength - 1];
            uint mask = ConstantTimeGE((uint)blockSize, padLength) & ConstantTimeGE(padLength, 1);

            for (int i = 0; i < blockSize; i++)
            {
                uint bmask = ConstantTimeGE(padLength, (uint)i + 1);
                uint b = data[(dataLength - 1) - i];
                mask &= ~(bmask & (padLength ^ b));
            }

            mask &= mask >> 4;
            mask &= mask >> 2;
            mask &= mask >> 1;
            mask <<= 31;
            mask = ConstantTimeMsb(mask);

            int result = (int)((mask & padLength) | ~mask); // returns -1 on failure

            return result;
        }

        // Broadcasts the most significant bit (bit 31) of 'value' to every bit
        // position, producing 0xFFFFFFFF when bit 31 is set and 0x00000000 otherwise.
        //
        // The cast to int reinterprets the bits without changing them, and the
        // right shift on a signed int is an arithmetic (sign-extending) shift in C#,
        // which copies the sign bit into all lower bits. The shift amount of 31 is
        // always in range, so the result is well defined for every input.
        //
        // Constant time: no branches or data-dependent memory access; the timing is
        // independent of 'value'.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ConstantTimeMsb(uint value)
        {
            return (uint)((int)value >> 31);
        }

        // Returns 0xFFFFFFFF when left >= right; otherwise, 0x00000000.
        //
        // (left - right) is unchecked uint subtraction (modulo 2^32). Bit 31 of that
        // difference acts as the sign bit: it is 0 when left >= right and 1 when
        // left < right. Complementing the difference inverts that bit, so broadcasting
        // the MSB of ~(left - right) yields all ones exactly when left >= right.
        //
        // Corner case / precondition: this relies on bit 31 of (left - right) being a
        // valid sign indicator, which holds only when both operands are less than
        // 2^31. If either operand has bit 31 set, the difference can alias and the
        // result is unreliable. All call sites pass byte-range values (0..255), so the
        // precondition is always satisfied.
        //
        // Boundary behavior (within the supported range):
        //   left == right       -> difference 0,          result 0xFFFFFFFF (true)
        //   left == right + 1   -> difference 1,          result 0xFFFFFFFF (true)
        //   left == right - 1   -> difference 0xFFFFFFFF, result 0x00000000 (false)
        //
        // Constant time: no branches or data-dependent memory access; the timing is
        // independent of 'left' and 'right'.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ConstantTimeGE(uint left, uint right)
        {
            return ConstantTimeMsb(~(left - right));
        }
    }
}
