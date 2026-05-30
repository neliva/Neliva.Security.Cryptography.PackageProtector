// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides constant-time helpers for working with block cipher padding.
    /// </summary>
    internal static class BlockPadding
    {
        /// <summary>
        /// Validates the PKCS7 padding in the last block of <paramref name="buffer"/>
        /// and returns the number of padding bytes.
        /// </summary>
        /// <param name="blockSize">
        /// The block size, in bytes, that the padding is aligned to.
        /// Must be between 1 and <see cref="byte.MaxValue"/> inclusive.
        /// </param>
        /// <param name="buffer">
        /// The buffer whose final block contains the PKCS7 padding to validate.
        /// Its length must be a non-zero multiple of <paramref name="blockSize"/>.
        /// </param>
        /// <returns>
        /// The number of padding bytes (between 1 and <paramref name="blockSize"/>)
        /// when the padding is valid; otherwise, -1.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="blockSize"/> is less than 1 or greater than <see cref="byte.MaxValue"/>.
        /// - or -
        /// The <paramref name="buffer"/> is empty.
        /// - or -
        /// The <paramref name="buffer"/> length is not a multiple of <paramref name="blockSize"/>.
        /// </exception>
        /// <remarks>
        /// The padding is verified in constant time with respect to the buffer
        /// contents, so the execution time does not reveal whether the padding is
        /// valid or how many padding bytes are present.
        /// </remarks>
        public static int GetPKCS7PaddingLength(int blockSize, ReadOnlySpan<byte> buffer)
        {
            if (blockSize <= 0 || blockSize > byte.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be between 1 and 255.");
            }

            int bufferLength = buffer.Length;

            if (bufferLength == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(buffer), "Buffer is empty.");
            }

            if ((bufferLength % blockSize) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(buffer), "Buffer length is not a multiple of block size.");
            }

            uint padLength = buffer[bufferLength - 1];
            uint mask = ConstantTimeGE((uint)blockSize, padLength) & ConstantTimeGE(padLength, 1);

            for (int i = 0; i < blockSize; i++)
            {
                uint bmask = ConstantTimeGE(padLength, (uint)i + 1);
                uint b = buffer[(bufferLength - 1) - i];
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

        // Copies most significant bit to all other bits.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ConstantTimeMsb(uint value)
        {
            return (uint)((int)value >> 31);
        }

        // Returns 0xf..f if left >= right; otherwise, 0x0..0.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ConstantTimeGE(uint left, uint right)
        {
            return ConstantTimeMsb(~(left - right));
        }
    }
}