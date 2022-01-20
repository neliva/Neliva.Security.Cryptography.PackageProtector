// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Represents pad-then-mac-then-encrypt chunked data protection using
    /// AES256-CBC and HMAC-SHA256 algorithms.
    /// </summary>
    public sealed partial class PackageProtector : IDisposable
    {
        private const int BlockSize = 16; // AES256 block size
        private const int HashSize = 32; // HMAC-SHA256 hash size, HMAC key size, AES256 key size.

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
        /// Gets the max number of bytes that can be protected by the
        /// <see cref="Protect(ArraySegment{byte}, ArraySegment{byte}, byte[], long, ArraySegment{byte})"/>
        /// method.
        /// </summary>
        public int MaxContentSize { get => this._MaxContentSize; }

        /// <summary>
        /// Gets the max package size in bytes that can be produced by the
        /// <see cref="Protect(ArraySegment{byte}, ArraySegment{byte}, byte[], long, ArraySegment{byte})"/>
        /// method.
        /// </summary>
        public int MaxPackageSize { get => this._MaxPackageSize; }

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
        /// Extra data associated with the <paramref name="content"/>, which must match the value
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
        /// The <paramref name="packageNumber"/> parameter is less than zero.
        /// - or -
        /// The <paramref name="associatedData"/> parameter length is too large.
        /// </exception>
        public int Protect(ArraySegment<byte> content, ArraySegment<byte> package, byte[] key, long packageNumber, ArraySegment<byte> associatedData)
        {
            if (content.Count > this._MaxContentSize)
            {
                throw new ArgumentOutOfRangeException(nameof(content), $"Content cannot be larger than '{this._MaxContentSize}' bytes.");
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

            if (this._IsDisposed)
            {
                throw new ObjectDisposedException(nameof(PackageProtector));
            }

            var data = package.Slice(this._IvAndHashSize, outputPackageSize - this._IvAndHashSize);  // content + padding
            var randomData = package.Slice(0, this._IvSize);

            this._rngFill?.Invoke(randomData);

            // If ArraySegment is 'default' or 'null' then Array property will be 'null'.
            if (content.Array != null)
            {
                // Copy plain text to output buffer (after random bytes and hash).
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

            using (var hmac = new HMACSHA256(key))
            {
                DeriveKeys(hmac, packageNumber, this._MaxPackageSize, randomData, associatedData, encKey, signKey);

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
        /// Extra data associated with the <paramref name="package"/>, which must match the value
        /// provided during protection.
        /// </param>
        /// <returns>
        /// The number of bytes written to the <paramref name="content"/> destination.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="key"/> parameter is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="key"/> length is less than 32 bytes or greater than 64 bytes.
        /// - or -
        /// The <paramref name="content"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="packageNumber"/> parameter is less than zero.
        /// - or -
        /// The <paramref name="associatedData"/> parameter length is too large.
        /// </exception>
        /// <exception cref="BadPackageException">
        /// Package is invalid or corrupted.
        /// - or -
        /// The <paramref name="package"/> length is not correct.
        /// - or -
        /// The <paramref name="key"/>, <paramref name="packageNumber"/>,
        /// or <paramref name="associatedData"/> parameter is not valid.
        /// </exception>
        public int Unprotect(ArraySegment<byte> package, ArraySegment<byte> content, byte[] key, long packageNumber, ArraySegment<byte> associatedData)
        {
            bool isInvalidPackage = this.IsInvalidPackageSize(package.Count);

            if (!isInvalidPackage && content.Count < package.Count)
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

            if (this._IsDisposed)
            {
                throw new ObjectDisposedException(nameof(PackageProtector));
            }

            if (isInvalidPackage)
            {
                string badPackageMsg = this._MinPackageSize == this._MaxPackageSize ?
                    $"Package size must be {this._MinPackageSize} bytes." :
                    $"Package size must be between {this._MinPackageSize} and {this._MaxPackageSize} bytes and aligned on a {BlockSize} byte boundary.";

                throw new BadPackageException(badPackageMsg);
            }

            var data = content.Slice(0, package.Count - this._IvAndHashSize); // content + padding

            Span<byte> computedHash = stackalloc byte[HashSize];

            byte[] encKey = new byte[HashSize];
            byte[] signKey = new byte[HashSize];

            byte[] packageHash = new byte[HashSize];

            using (var hmac = new HMACSHA256(key))
            {
                var randomData = package.Slice(0, this._IvSize);

                DeriveKeys(hmac, packageNumber, this._MaxPackageSize, randomData, associatedData, encKey, signKey);

                using (var dec = this._Aes.CreateDecryptor(encKey, this._AesZeroIV))
                {
                    // Decrypt package hash
                    dec.TransformBlock(
                        package.Array,
                        package.Offset + this._IvSize,
                        HashSize,
                        packageHash,
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

                hmac.Key = signKey;

                // Sign plaintext and padding.
                hmac.ComputeHash(data, computedHash);
            }

            if (!CryptographicOperations.FixedTimeEquals(computedHash, packageHash))
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsNotAlignedBlock(int value)
        {
            const int align = BlockSize;

            return value % align != 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int AlignBlock(int value)
        {
            // Aligns the value on BlockSize byte boundary.
            // If value is already aligned or zero,
            // extends the value by extra BlockSize bytes.

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