﻿// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Represents pad-then-mac-then-encrypt chunked data protection using
    /// the HMAC-SHA256 and AES256-CBC algorithms.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="PackageProtector"/> allows 0, 16, or 32 byte IVs. Max content size
    /// per package depends on the IV size.
    /// </para>
    /// <para>
    /// For the 16 byte IV, the package layout is the following:
    /// <code>
    /// |                   package, 64 bytes - (16MiB - 16 bytes)                           |
    /// +------------------------------------------------------------------------------------+
    /// | KDF IV      | MAC(content || pad)    | chunk content             | PKCS7 pad       |
    /// +-------------+------------------------+---------------------------+-----------------+
    /// | 16 bytes    | 32 bytes               | 0 - (16MiB - 65 bytes)    | 1 - 16 bytes    |
    /// +-------------+----------------------------------------------------------------------+
    /// |             |                       encrypted (no padding)                         |
    /// </code>
    /// </para>
    /// </remarks>
    public sealed partial class PackageProtector : IDisposable
    {
        private const int BlockSize = 16; // AES block size.
        private const int HashSize = 32;  // HMAC-SHA256 hash and key size, AES256 key size.

        private readonly int _IvSize;
        private readonly int _IvAndHashSize;
        private readonly int _MaxPackageSize;
        private readonly int _MinPackageSize;
        private readonly int _MaxContentSize;
        private readonly int _MaxAssociatedDataSize;

        private readonly byte[] _AesZeroIV;

        private readonly Aes _Aes;

        private readonly RngFillAction _rngFill;

        private bool _IsDisposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="PackageProtector"/> class.
        /// </summary>
        /// <param name="ivSize">
        /// The KDF IV size in bytes.
        /// The valid values are 0, 16 and 32 bytes.
        /// </param>
        /// <param name="packageSize">
        /// The package size in bytes which must be a multiple of 16 bytes.
        /// The minimum is (<paramref name="ivSize"/> + 48)
        /// and the maximum is <c>16777206</c>.
        /// </param>
        /// <param name="rngFill">
        /// A callback to fill a span with cryptographically strong random bytes.
        /// When not provided, a default <see cref="RandomNumberGenerator.Fill"/>
        /// implementation is used for non-zero <paramref name="ivSize"/> value.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="ivSize"/> parameter is not 0, 16 or 32 bytes.
        /// - or -
        /// The <paramref name="packageSize"/> parameter is less than
        /// (<paramref name="ivSize"/> + 48) bytes or greater than <c>16777206</c> bytes.
        /// </exception>
        public PackageProtector(int ivSize = BlockSize, int packageSize = 64 * 1024, RngFillAction rngFill = null)
        {
            switch (ivSize)
            {
                case 0:
                case BlockSize:
                case BlockSize + BlockSize:
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(ivSize));
            }

            int minPackageSize = ivSize + HashSize + BlockSize;

            const int KdfMaxPackageSize = (16 * 1024 * 1024) - BlockSize; // Our KDF imposes this limit.

            if (packageSize < minPackageSize || packageSize > KdfMaxPackageSize || IsNotAlignedBlock(packageSize))
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize));
            }

            // Overhead is the minimum number of bytes added to content
            // during package protection.
            int overhead = ivSize + HashSize + 1; // One byte for padding.

            this._IvSize = ivSize;
            this._IvAndHashSize = ivSize + HashSize;
            this._MaxPackageSize = packageSize;
            this._MinPackageSize = minPackageSize;
            this._MaxContentSize = packageSize - overhead;
            this._MaxAssociatedDataSize = BlockSize + BlockSize - ivSize;

            this._AesZeroIV = new byte[BlockSize];

            this._rngFill = ivSize == 0 ?
                null : // No need for RNG when IV size is zero.
                rngFill ?? new RngFillAction(RandomNumberGenerator.Fill);

            this._Aes = Aes.Create();

            this._Aes.Padding = PaddingMode.None; // Padding is done manually.
            this._Aes.Mode = CipherMode.CBC;
        }

        /// <summary>
        /// Gets the max content length in bytes that can be protected by the
        /// <see cref="Protect(ArraySegment{byte}, ArraySegment{byte}, byte[], long, ArraySegment{byte})"/>
        /// method.
        /// </summary>
        public int MaxContentSize => this._MaxContentSize;

        /// <summary>
        /// Gets the max package length in bytes that can be produced by the
        /// <see cref="Protect(ArraySegment{byte}, ArraySegment{byte}, byte[], long, ArraySegment{byte})"/>
        /// method.
        /// </summary>
        public int MaxPackageSize => this._MaxPackageSize;

        /// <summary>
        /// Protects the <paramref name="content"/> into the <paramref name="package"/> destination.
        /// </summary>
        /// <param name="content">
        /// The content to protect.
        /// </param>
        /// <param name="package">
        /// The destination to receive the protected <paramref name="content"/>.
        /// </param>
        /// <param name="key">
        /// The secret key used to protect the <paramref name="content"/>.
        /// </param>
        /// <param name="packageNumber">
        /// The package number in a series of packages, which must match the value
        /// provided during unprotection.
        /// </param>
        /// <param name="associatedData">
        /// The extra data associated with the <paramref name="content"/>, which must match the value
        /// provided during unprotection.
        /// </param>
        /// <returns>
        /// The number of bytes written to the <paramref name="package"/> destination.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="key"/> parameter is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="key"/> length is less than 32 bytes or greater than 64 bytes.
        /// - or -
        /// The <paramref name="content"/> length is greater than <see cref="MaxContentSize"/>.
        /// - or -
        /// The <paramref name="package"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="packageNumber"/> is less than zero.
        /// - or -
        /// The <paramref name="associatedData"/> length is too large.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The <paramref name="content"/> and <paramref name="package"/> overlap in memory.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// The <see cref="PackageProtector"/> object has already been disposed.
        /// </exception>
        public int Protect(ArraySegment<byte> content, ArraySegment<byte> package, byte[] key, long packageNumber, ArraySegment<byte> associatedData = default)
        {
            if (content.Count > this._MaxContentSize)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Content length is too large.");
            }

            int outputPackageSize = this._IvAndHashSize + AlignBlock(content.Count);

            if (package.Count < outputPackageSize)
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Insufficient space for package output.");
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (IsInvalidKeySize(key.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(key));
            }

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber));
            }

            if (associatedData.Count > this._MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData));
            }

            if (MemoryExtensions.Overlaps<byte>(content, package.Slice(0, outputPackageSize)))
            {
                throw new InvalidOperationException($"The '{nameof(package)}' must not overlap in memory with the '{nameof(content)}'.");
            }

            if (this._IsDisposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            var data = package.Slice(this._IvAndHashSize, outputPackageSize - this._IvAndHashSize);  // content + padding
            var kdfIV = package.Slice(0, this._IvSize);

            try
            {
                this._rngFill?.Invoke(kdfIV);

                // If ArraySegment is 'default' or 'null' then Array property will be 'null'.
                if (content.Array != null)
                {
                    // Copy plain text to output buffer (after iv and hash).
                    content.CopyTo(data);
                }

                // Pad data using PKCS7 scheme.
                for (int pos = content.Count,
                    padLength = BlockSize - (pos % BlockSize),
                    padEnd = pos + padLength
                    ; pos < padEnd; pos++)
                {
                    data[pos] = (byte)padLength;
                }

                byte[] encKey = new byte[HashSize];
                byte[] signKey = new byte[HashSize];

                Span<byte> encKeySpan = encKey;
                Span<byte> signKeySpan = signKey;

                try
                {
                    using (var hmac = new HMACSHA256(key))
                    {
                        DeriveKeys(hmac, packageNumber, this._MaxPackageSize, kdfIV, associatedData, encKeySpan, signKeySpan);

                        hmac.Key = signKey;

                        // Sign plaintext and padding, then prepend hash to padded plaintext.
                        hmac.ComputeHash(data, package.Slice(this._IvSize, HashSize));
                    }

                    using (var enc = this._Aes.CreateEncryptor(encKey, this._AesZeroIV))
                    {
                        // Encrypt buffer in place.
                        enc.TransformBlock(
                            package.Array,
                            package.Offset + this._IvSize,
                            outputPackageSize - this._IvSize,
                            package.Array,
                            package.Offset + this._IvSize);
                    }

                    return outputPackageSize;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(encKeySpan);
                    CryptographicOperations.ZeroMemory(signKeySpan);
                }
            }
            catch
            {
                Array.Clear(package.Array, package.Offset, outputPackageSize);

                throw;
            }
        }

        /// <summary>
        /// Unprotects the <paramref name="package"/> into the <paramref name="content"/> destination.
        /// </summary>
        /// <param name="package">
        /// The package to unprotect.
        /// </param>
        /// <param name="content">
        /// The destination to receive the unprotected <paramref name="package"/>.
        /// </param>
        /// <param name="key">
        /// The secret key used to unprotect the <paramref name="package"/>.
        /// </param>
        /// <param name="packageNumber">
        /// The package number in a series of packages, which must match the value
        /// provided during protection.
        /// </param>
        /// <param name="associatedData">
        /// The extra data associated with the <paramref name="package"/>, which must match the value
        /// provided during protection.
        /// </param>
        /// <returns>
        /// The number of bytes written to the <paramref name="content"/> destination.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="key"/> parameter is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="package"/> length is not correct.
        /// - or -
        /// The <paramref name="key"/> length is less than 32 bytes or greater than 64 bytes.
        /// - or -
        /// The <paramref name="content"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="packageNumber"/> is less than zero.
        /// - or -
        /// The <paramref name="associatedData"/> length is too large.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The <paramref name="package"/> and <paramref name="content"/> overlap in memory.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// The <see cref="PackageProtector"/> object has already been disposed.
        /// </exception>
        /// <exception cref="BadPackageException">
        /// Package is invalid or corrupted.
        /// - or -
        /// The <paramref name="key"/>, <paramref name="packageNumber"/>,
        /// or <paramref name="associatedData"/> parameter is not valid
        /// for the provided <paramref name="package"/>.
        /// </exception>
        /// <remarks>
        /// If the <paramref name="package"/> cannot be validated
        /// then the <paramref name="content"/> is cleared.
        /// </remarks>
        public int Unprotect(ArraySegment<byte> package, ArraySegment<byte> content, byte[] key, long packageNumber, ArraySegment<byte> associatedData = default)
        {
            if (this.IsInvalidPackageSize(package.Count))
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Package length is invalid or not aligned on the required boundary.");
            }

            int dataLength = package.Count - this._IvAndHashSize;

            if (content.Count < dataLength)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Insufficient space for content output.");
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (IsInvalidKeySize(key.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(key));
            }

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber));
            }

            if (associatedData.Count > this._MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData));
            }

            var data = content.Slice(0, dataLength); // content + padding

            if (MemoryExtensions.Overlaps<byte>(package, data))
            {
                throw new InvalidOperationException($"The '{nameof(content)}' must not overlap in memory with the '{nameof(package)}'.");
            }

            if (this._IsDisposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            byte[] tmpA = new byte[HashSize]; // Used for encKey and decrypted hash
            byte[] tmpB = new byte[HashSize]; // Used for signKey and computed hash

            Span<byte> tmpASpan = tmpA;
            Span<byte> tmpBSpan = tmpB;

            try
            {
                try
                {
                    using (var hmac = new HMACSHA256(key))
                    {
                        var kdfIV = package.Slice(0, this._IvSize);

                        DeriveKeys(hmac, packageNumber, this._MaxPackageSize, kdfIV, associatedData, tmpASpan, tmpBSpan);

                        using (var dec = this._Aes.CreateDecryptor(tmpA, this._AesZeroIV))
                        {
                            // Decrypt package hash
                            dec.TransformBlock(
                                package.Array,
                                package.Offset + this._IvSize,
                                HashSize,
                                tmpA,
                                0);

                            // Decrypt (content + padding) directly into output.
                            // IV for the block comes from the previous invocation of the method.
                            dec.TransformBlock(
                                package.Array,
                                package.Offset + this._IvAndHashSize,
                                package.Count - this._IvAndHashSize,
                                content.Array,
                                content.Offset);
                        }

                        hmac.Key = tmpB;

                        // Sign plaintext and padding.
                        hmac.ComputeHash(data, tmpBSpan);
                    }

                    if (!CryptographicOperations.FixedTimeEquals(tmpASpan, tmpBSpan))
                    {
                        throw new BadPackageException();
                    }

                    int padLength = BlockPadding.GetPKCS7PaddingLength(BlockSize, data);

                    if (padLength == -1)
                    {
                        throw new BadPackageException();
                    }

                    return data.Count - padLength;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(tmpASpan);
                    CryptographicOperations.ZeroMemory(tmpBSpan);
                }
            }
            catch
            {
                Array.Clear(data.Array, data.Offset, data.Count);

                throw;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsNotAlignedBlock(int value)
        {
            const int align = BlockSize;

            return value % align != 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int AlignBlock(int value)
        {
            // Aligns the value on the "align" byte boundary.
            // If the value is already aligned or zero,
            // extends the value by extra "align" bytes.

            const int align = BlockSize;

            return value + (align - (value % align));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool IsInvalidPackageSize(int value)
        {
            return value < this._MinPackageSize || value > this._MaxPackageSize || IsNotAlignedBlock(value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsInvalidKeySize(int value)
        {
            const int MinKeySize = 32;
            const int MaxKeySize = 64;

            return value < MinKeySize || value > MaxKeySize;
        }

        internal static void DeriveKeys(HMACSHA256 hmac, long packageNumber, int packageSize, ReadOnlySpan<byte> ivArg1, ReadOnlySpan<byte> ivArg2, Span<byte> encryptionKey, Span<byte> signingKey)
        {
            Span<byte> data = stackalloc byte[55]; // Max available space before hmac padding.

            const byte SignPurpose = 0x00;
            const byte EncryptPurpose = 0xff;

            const uint counter = 1; // KDF in Counter Mode as described in SP800-108.
            const uint derivedKeyLengthInBits = 256;

            data[0] = (byte)(counter >> 24);
            data[1] = (byte)(counter >> 16);
            data[2] = (byte)(counter >> 8);
            data[3] = (byte)counter;

            data[4] = EncryptPurpose;
            data[5] = (byte)ivArg1.Length;
            data[6] = (byte)ivArg2.Length;

            data[7] = 0; // SP800-108 label and context separator.

            data[8] = (byte)(packageNumber >> 56);
            data[9] = (byte)(packageNumber >> 48);
            data[10] = (byte)(packageNumber >> 40);
            data[11] = (byte)(packageNumber >> 32);
            data[12] = (byte)(packageNumber >> 24);
            data[13] = (byte)(packageNumber >> 16);
            data[14] = (byte)(packageNumber >> 8);
            data[15] = (byte)packageNumber;

            var ivArgs = data.Slice(16, 32);

            ivArg1.CopyTo(ivArgs);

            ivArg2.CopyTo(ivArgs.Slice(ivArg1.Length));

            ivArgs.Slice(ivArg1.Length + ivArg2.Length).Clear();

            data[48] = (byte)(packageSize >> 16);
            data[49] = (byte)(packageSize >> 8);
            data[50] = (byte)packageSize;

            data[51] = (byte)(derivedKeyLengthInBits >> 24);
            data[52] = (byte)(derivedKeyLengthInBits >> 16);
            data[53] = (byte)(derivedKeyLengthInBits >> 8);
            data[54] = (byte)(derivedKeyLengthInBits & 0xff);

            hmac.ComputeHash(data, encryptionKey);

            data[4] = SignPurpose;

            hmac.ComputeHash(data, signingKey);
        }

        /// <summary>
        /// Releases all resources used by the current instance
        /// of the <see cref="PackageProtector"/> class.
        /// </summary>
        public void Dispose()
        {
            bool isDisposed = this._IsDisposed;

            this._IsDisposed = true;

            if (!isDisposed)
            {
                var aes = this._Aes;

                if (aes != null)
                {
                    aes.Dispose();
                }
            }
        }
    }
}