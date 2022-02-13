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

        public static bool IsAllSameValue(this ReadOnlySpan<byte> span, byte value)
        {
            foreach (byte b in span)
            {
                if (b != value)
                {
                    return false;
                }
            }

            return true;
        }

        public static bool IsAllSameValue(this Span<byte> span, byte value)
        {
            return IsAllSameValue((ReadOnlySpan<byte>)span, value);
        }

        public static bool IsAllZeros(this ReadOnlySpan<byte> span)
        {
            return IsAllSameValue(span, 0);
        }

        public static bool IsAllZeros(this byte[] array)
        {
            return IsAllSameValue((ReadOnlySpan<byte>)array, 0);
        }

        public static bool IsAllZeros(this ArraySegment<byte> array)
        {
            return IsAllSameValue((ReadOnlySpan<byte>)array, 0);
        }
    }
}