// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides methods to verify message block padding.
    /// </summary>
    internal static class BlockPadding
    {
        // Returns -1 on failure, or number of padding bytes on success.
        public static int GetPKCS7PaddingLength(int blockSize, ReadOnlySpan<byte> buffer)
        {
            if (blockSize <= 0 || blockSize > byte.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize));
            }

            int bufferLength = buffer.Length;

            if (bufferLength == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(buffer));
            }

            if ((bufferLength < blockSize) || ((bufferLength % blockSize) != 0))
            {
                throw new ArgumentOutOfRangeException(nameof(buffer), "Length is not a multiple of block size.");
            }

            uint padLength = buffer[bufferLength - 1];
            uint mask = ConstantTimeGE((uint)bufferLength, padLength) & ConstantTimeGE(padLength, 1);

            for (int i = 0; i < blockSize; i++)
            {
                uint bmask = ConstantTimeGE(padLength, (uint)i + 1);
                uint b = buffer[(bufferLength - 1) - i];
                mask &= ~(bmask & (padLength ^ b));
            }

            mask = (mask >> 4) & (mask >> 2) & (mask >> 1) & mask;
            mask <<= 31;
            mask = ConstantTimeMsb(mask);

            int result = (int)((mask & padLength) | (~mask & -1)); // returns -1 on failure

            return result;
        }

        // Copies most significant bit to all other bits.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ConstantTimeMsb(uint value)
        {
            return (uint)((int)value >> 31);

            // return 0 - (value >> 31);
        }

        // Returns 0xf..f if left >= right; otherwise, 0x0..0.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint ConstantTimeGE(uint left, uint right)
        {
            return ConstantTimeMsb(~(left - right));
        }
    }
}