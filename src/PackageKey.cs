// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Derives keys from a master key using the SP800-108 HMAC-SHA512 KDF in Counter Mode.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A single instance is initialized with a master key and can derive multiple
    /// keys by varying the <c>label</c> and <c>context</c> inputs.
    /// </para>
    /// <para>
    /// The combined length of the <c>label</c> and <c>context</c> is limited to 102 bytes
    /// so the entire HMAC-SHA512 message fits within a single hash block.
    /// </para>
    /// </remarks>
    public sealed class PackageKey : IDisposable
    {
        private const int MinKeySize = HMACSHA512.HashSizeInBytes / 2;
        private const int MaxKeySize = HMACSHA512.HashSizeInBytes;

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
        private const int MaxLabelContextLength = 102;

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
        /// A non-empty span that identifies the purpose for the derived keying material.
        /// </param>
        /// <param name="context">
        /// A non-empty span containing the information related to the derived keying material.
        /// It may include identities of parties who are deriving and/or using the
        /// derived keying material and, optionally, a nonce known by the parties who
        /// derive the keys.
        /// </param>
        /// <param name="destination">
        /// A span that receives the derived keying material.
        /// The length must be between 32 and 64 bytes.
        /// </param>
        /// <exception cref="ArgumentException">
        /// The <paramref name="label"/> is empty.
        /// - or -
        /// The <paramref name="context"/> is empty.
        /// - or -
        /// The combined length of <paramref name="label"/> and <paramref name="context"/>
        /// exceeds 102 bytes.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="destination"/> length is less than 32 bytes or greater than 64 bytes.
        /// </exception>
        public void DeriveKey(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, Span<byte> destination)
        {
            if (label.IsEmpty)
            {
                throw new ArgumentException("Label must not be empty.", nameof(label));
            }

            if (context.IsEmpty)
            {
                throw new ArgumentException("Context must not be empty.", nameof(context));
            }

            if (label.Length > (MaxLabelContextLength - context.Length))
            {
                throw new ArgumentException("The combined length of label and context must not exceed 102 bytes.");
            }

            if (destination.Length < MinKeySize || destination.Length > MaxKeySize)
            {
                throw new ArgumentOutOfRangeException(nameof(destination), "Destination length must be between 32 and 64 bytes.");
            }

            this._kdf.DeriveKey(label, context, destination);
        }

        /// <summary>
        /// Derives a new <see cref="PackageKey"/> instance from the current master key.
        /// </summary>
        /// <param name="label">
        /// A non-empty span that identifies the purpose for the derived key.
        /// </param>
        /// <param name="context">
        /// A non-empty span containing the information related to the derived key.
        /// It may include identities of parties who are deriving and/or using the
        /// derived key and, optionally, a nonce known by the parties who derive the keys.
        /// </param>
        /// <returns>
        /// A new <see cref="PackageKey"/> derived from the current master key using a
        /// 64 byte derived value. The caller owns the returned instance and is
        /// responsible for disposing it.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// The <paramref name="label"/> is empty.
        /// - or -
        /// The <paramref name="context"/> is empty.
        /// - or -
        /// The combined length of <paramref name="label"/> and <paramref name="context"/>
        /// exceeds 102 bytes.
        /// </exception>
        /// <remarks>
        /// The derived key material is held only by the returned <see cref="PackageKey"/>;
        /// the intermediate buffer used to construct it is cleared before this method
        /// returns. Dispose the returned instance when it is no longer needed to release
        /// the underlying key.
        /// </remarks>
        public PackageKey DeriveKey(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context)
        {
            Span<byte> destination = stackalloc byte[MaxKeySize];

            try
            {
                this.DeriveKey(label, context, destination);

                return new PackageKey(destination);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(destination);
            }
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
