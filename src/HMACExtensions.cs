// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides extension methods for <see cref="HMAC"/> implementations.
    /// </summary>
    public static class HMACExtensions
    {
        /// <summary>
        /// Derives a key using the KDF in Counter Mode as described in SP800-108.
        /// </summary>
        /// <param name="hmac">
        /// The <see cref="HMAC"/> instance that is already initialized with a master key.
        /// </param>
        /// <param name="label">
        /// A span that identifies the purpose for the derived keying material.
        /// </param>
        /// <param name="context">
        /// A span containing the information related to the derived keying
        /// material. It may include identities of parties who are deriving and/or using the
        /// derived keying material and, optionally, a nonce known by the parties who derive
        /// the keys. 
        /// </param>
        /// <param name="derivedKey">
        /// A span that receives the keying material output from the key derivation function.
        /// </param>
        public static void DeriveKey(this HMAC hmac, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, Span<byte> derivedKey)
        {
            if (hmac == null)
            {
                throw new ArgumentNullException(nameof(hmac));
            }

            const int CounterSpaceSize = sizeof(uint);
            const int SeparatorSpaceSize = 1; // 0x00 separator
            const int KeySpaceSize = sizeof(uint);

            const int MaxLabelAndContextLength = int.MaxValue - CounterSpaceSize - SeparatorSpaceSize - KeySpaceSize;

            if ((label.Length + context.Length) > MaxLabelAndContextLength)
            {
                throw new ArgumentException($"The combined length of '{nameof(label)}' and '{nameof(context)}' cannot exceed {MaxLabelAndContextLength} bytes.");
            }

            const int MaxDerivedKeyLength = int.MaxValue / 4;

            if (derivedKey.Length == 0 || derivedKey.Length > MaxDerivedKeyLength)
            {
                throw new ArgumentOutOfRangeException(nameof(derivedKey));
            }

            const int MaxStackAllocSize = 256;          

            // counter + label + separator + context + derivedKeyInBits
            int inputDataSize = CounterSpaceSize + label.Length + SeparatorSpaceSize + context.Length + KeySpaceSize;

            Span<byte> inputData = (inputDataSize < MaxStackAllocSize) ?
                stackalloc byte[inputDataSize] :
                new byte[inputDataSize];

            label.CopyTo(inputData.Slice(CounterSpaceSize));
            inputData[CounterSpaceSize + label.Length] = 0x00; // zero byte separator
            context.CopyTo(inputData.Slice(CounterSpaceSize + label.Length + SeparatorSpaceSize));

            Span<byte> derivedKeyInBits = inputData.Slice(inputData.Length - KeySpaceSize);

            uint lengthBits = (uint)derivedKey.Length * 8; // length of the derived key in bits

            derivedKeyInBits[0] = (byte)(lengthBits >> 24);
            derivedKeyInBits[1] = (byte)(lengthBits >> 16);
            derivedKeyInBits[2] = (byte)(lengthBits >> 8);
            derivedKeyInBits[3] = (byte)lengthBits;

            Span<byte> hash = stackalloc byte[hmac.HashSize / 8];

            for (uint counter = 1; ; counter++)
            {
                inputData[0] = (byte)(counter >> 24);
                inputData[1] = (byte)(counter >> 16);
                inputData[2] = (byte)(counter >> 8);
                inputData[3] = (byte)counter;

                if (!hmac.TryComputeHash(inputData, hash, out int bytesWritten) ||
                    bytesWritten != hash.Length)
                {
                    CryptographicOperations.ZeroMemory(hash);

                    throw new CryptographicUnexpectedOperationException();
                }

                int length = Math.Min(derivedKey.Length, bytesWritten);

                var fragment = hash.Slice(0, length);

                fragment.CopyTo(derivedKey);

                derivedKey = derivedKey.Slice(length);

                if (derivedKey.Length == 0)
                {
                    CryptographicOperations.ZeroMemory(hash);

                    break;
                }
            }
        }
    }
}