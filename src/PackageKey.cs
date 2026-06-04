// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Derives keys from a master key using the SP800-108 HMAC-SHA512 KDF in Counter Mode.
    /// </summary>
    public sealed class PackageKey : IDisposable
    {
        const int MinKeySize = 32;
        const int MaxKeySize = 64;

        // The max number of message bytes that we can input into SHA512 to
        // be processed in a single block is 111 bytes, due to:
        // * 16 bytes for message length
        // * 1 byte for the mandatory 0x80 padding prefix
        //
        // SP800-108 KDF in Counter Mode requires 9 bytes reserved for
        // the structure overhead, due to:
        // * 4-byte counter
        // * 0x00 separator byte
        // * 4-byte length of the derived key
        //
        // The max length of the KDF Label+Context that keeps the entire HMAC message
        // inside one block is 102 bytes.
        const int MaxLabelContextLength = 102;

        private readonly SP800108HmacCounterKdf _kdf;

        /// <summary>
        /// Initializes a new instance of the <see cref="PackageKey"/> class.
        /// </summary>
        /// <param name="key">
        /// The master key used to derive keys. The length must be between 32 and 64 bytes.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="key"/> length is less than 32 bytes or greater than 64 bytes.
        /// </exception>
        public PackageKey(ReadOnlySpan<byte> key)
        {
            if (key.Length < MinKeySize || key.Length > MaxKeySize)
            {
                throw new ArgumentOutOfRangeException(nameof(key), "Key length must be between 32 and 64 bytes.");
            }

            this._kdf = new SP800108HmacCounterKdf(key, HashAlgorithmName.SHA512);
        }

        /// <summary>
        /// Derives keying material into the <paramref name="destination"/> span.
        /// </summary>
        /// <param name="label">
        /// A span that identifies the purpose for the derived keying material.
        /// </param>
        /// <param name="context">
        /// A span containing the information related to the derived keying material.
        /// It may include identities of parties who are deriving and/or using the
        /// derived keying material and, optionally, a nonce known by the parties who
        /// derive the keys.
        /// </param>
        /// <param name="destination">
        /// A span that receives the derived keying material.
        /// </param>
        /// <exception cref="ArgumentException">
        /// The combined length of <paramref name="label"/> and <paramref name="context"/>
        /// exceeds 102 bytes.
        /// </exception>
        public void DeriveKey(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, Span<byte> destination)
        {
            if (label.Length + context.Length > MaxLabelContextLength)
            {
                throw new ArgumentException($"The combined length of label and context is too long.");
            }

            this._kdf.DeriveKey(label, context, destination);
        }

        /// <summary>
        /// Releases all resources used by the current instance
        /// of the <see cref="PackageKey"/> class.
        /// </summary>
        public void Dispose()
        {
            this._kdf.Dispose();
        }
    }
}
