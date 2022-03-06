// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides extension methods for <see cref="KeyedHashAlgorithm"/> implementations.
    /// </summary>
    public static class KeyedHashAlgorithmExtensions
    {
        /// <summary>
        /// Derives a key using the SP800-108 KDF in Counter Mode.
        /// </summary>
        /// <param name="alg">
        /// The <see cref="KeyedHashAlgorithm "/> instance that is already initialized with a master key.
        /// </param>
        /// <param name="derivedKey">
        /// A span that receives the keying material output from the key derivation function.
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
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="alg"/> parameter is a <c>null</c> reference.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="derivedKey"/> length is zero or exceeds <c>536870911</c> bytes.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// The combined length of the <paramref name="label"/> and <paramref name="context"/>
        /// exceeds <c>2147483638</c> bytes.
        /// </exception>
        public static void DeriveKey(this KeyedHashAlgorithm alg, Span<byte> derivedKey, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context = default)
        {
            const int MaxDerivedKeyLength = int.MaxValue / 4;
            const int CounterSpaceSize = sizeof(uint);
            const int SeparatorSpaceSize = 1; // 0x00 separator
            const int KeySpaceSize = sizeof(uint);
            const uint MaxLabelAndContextLength = int.MaxValue - CounterSpaceSize - SeparatorSpaceSize - KeySpaceSize;
            const int MaxStackAllocSize = 320;

            if (alg == null)
            {
                throw new ArgumentNullException(nameof(alg));
            }

            if (derivedKey.Length == 0 || derivedKey.Length > MaxDerivedKeyLength)
            {
                throw new ArgumentOutOfRangeException(nameof(derivedKey), "The derived key length is zero or too large.");
            }

            if (((uint)label.Length + (uint)context.Length) > MaxLabelAndContextLength)
            {
                throw new ArgumentException($"The combined length of '{nameof(label)}' and '{nameof(context)}' is too large.");
            }

            // [counter + label + separator + context + derivedKeyInBits]
            int inputDataSize = label.Length + context.Length + (CounterSpaceSize + SeparatorSpaceSize + KeySpaceSize);

            int hashSize = alg.HashSize / 8;
            int bufferSize = hashSize + inputDataSize;

            byte[] rented = null;

            Span<byte> buffer = (bufferSize <= MaxStackAllocSize) ?
                stackalloc byte[bufferSize] :
                (rented = ArrayPool<byte>.Shared.Rent(bufferSize));

            Span<byte> hash = buffer.Slice(0, hashSize);
            Span<byte> inputData = buffer.Slice(hashSize);

            try
            {
                label.CopyTo(inputData.Slice(CounterSpaceSize));
                inputData[label.Length + CounterSpaceSize] = 0x00; // zero byte separator
                context.CopyTo(inputData.Slice(label.Length + (CounterSpaceSize + SeparatorSpaceSize)));

                BinaryPrimitives.WriteUInt32BigEndian(
                    inputData.Slice(inputDataSize - KeySpaceSize),
                    (uint)derivedKey.Length * 8u); // length of the derived key in bits

                for (uint counter = 1; ; counter++)
                {
                    BinaryPrimitives.WriteUInt32BigEndian(inputData, counter);

                    alg.ComputeHash(inputData, hash);

                    int length = Math.Min(derivedKey.Length, hashSize);

                    var fragment = hash.Slice(0, length);

                    fragment.CopyTo(derivedKey);

                    derivedKey = derivedKey.Slice(length);

                    if (derivedKey.Length == 0)
                    {
                        break;
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);

                if (rented != null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }
    }
}