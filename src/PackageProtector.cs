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
    public static class PackageProtector
    {
        private const int BlockSize = 16; // AES256 block size, IV size, max associated data size.

        private const int HashSize = 32; // HMAC-SHA256 hash size, HMAC key size, AES256 key size.

        /// <summary>
        /// The minimum number of bytes added to content
        /// during package protection.
        /// </summary>
        public const int Overhead = BlockSize + HashSize + 1; // One byte for padding.

        private const int MinPackageSize = BlockSize + BlockSize + HashSize;

        private const int MaxPackageSize = (16 * 1024 * 1024) - BlockSize;

        private const int MaxContentSize = MaxPackageSize - Overhead;

        private static byte[] ZeroIV = new byte[BlockSize];

        private static Aes aes = CreateAes();
        
        private static Aes CreateAes()
        {
            var aes = Aes.Create();

            aes.Padding = PaddingMode.None; // Padding is done manually.
            aes.Mode = CipherMode.CBC;

            return aes;
        }

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
        /// <param name="packageSize">
        /// The package size in bytes, which must match the value
        /// provided during unprotection.</param>
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
        /// The <paramref name="content"/> length is greater than (<paramref name="packageSize"/> - <see cref="Overhead"/>).
        /// - or -
        /// The <paramref name="package"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="packageNumber"/> parameter is less than zero.
        /// - or -
        /// The <paramref name="packageSize"/> parameter is less than <c>64 bytes</c>,
        /// or greater than <c>16MiB - 16 bytes</c>, or not a multiple of <c>16 bytes</c>.
        /// - or -
        /// The <paramref name="associatedData"/> parameter length is greater than <c>16 bytes</c>.
        /// </exception>
        public static int Protect(ArraySegment<byte> content, ArraySegment<byte> package, byte[] key, long packageNumber, int packageSize, ArraySegment<byte> associatedData)
        {
            bool isInvalidPackageSizeParam = IsInvalidPackageSize(packageSize);
            int maxAllowedContentSize = isInvalidPackageSizeParam ? MaxContentSize : packageSize - Overhead;

            if (content.Count > maxAllowedContentSize)
            {
                throw new ArgumentOutOfRangeException(nameof(content), $"Content cannot be larger than '{maxAllowedContentSize}' bytes.");
            }

            int outputPackageSize = BlockSize + HashSize + AlignBlock(content.Count);

            if (package.Count < outputPackageSize)
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Insufficient space for package output.");
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (IsInvalidKeySize(key))
            {
                throw new ArgumentOutOfRangeException(nameof(key));
            }

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber));
            }

            if (isInvalidPackageSizeParam)
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize));
            }

            if (IsInvalidAssociatedData(associatedData))
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData));
            }

            var data = package.Slice(BlockSize + HashSize, outputPackageSize - BlockSize - HashSize);  // content + padding
            var randomData = package.Slice(0, BlockSize);

            RandomNumberGenerator.Fill(randomData);

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
                DeriveKeys(hmac, packageNumber, packageSize, randomData, associatedData, encKey, signKey);

                hmac.Key = signKey;

                // Sign plaintext and padding, then prepend hash to padded plaintext.
                hmac.ComputeHash(data, package.Slice(BlockSize, HashSize));
            }

            using (var enc = aes.CreateEncryptor(encKey, ZeroIV))
            {
                // Encrypt buffer in place.
                enc.TransformBlock(
                    package.Array,
                    package.Offset + BlockSize,
                    outputPackageSize - BlockSize,
                    package.Array,
                    package.Offset + BlockSize);
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
        /// <param name="packageSize">
        /// The package size in bytes, which must match the value
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
        /// The <paramref name="packageSize"/> parameter is less than <c>64 bytes</c>,
        /// or greater than <c>16MiB - 16 bytes</c>, or not a multiple of <c>16 bytes</c>.
        /// - or -
        /// The <paramref name="associatedData"/> parameter length is greater than <c>16 bytes</c>.
        /// </exception>
        /// <exception cref="BadPackageException">
        /// Package is invalid or corrupted.
        /// - or -
        /// The <paramref name="package"/> length is less than <c>64 bytes</c>,
        /// or greater than <c>16MiB - 16 bytes</c>, or not a multiple of <c>16 bytes</c>.
        /// - or -
        /// The <paramref name="key"/>, <paramref name="packageNumber"/>, <paramref name="packageSize"/>,
        /// or <paramref name="associatedData"/> parameter is not valid.
        /// </exception>
        public static int Unprotect(ArraySegment<byte> package, ArraySegment<byte> content, byte[] key, long packageNumber, int packageSize, ArraySegment<byte> associatedData)
        {
            bool isInvalidPackageSizeParam = IsInvalidPackageSize(packageSize);
            bool isInvalidPackage = IsInvalidPackageSize(package.Count) || package.Count > packageSize;

            if ((!isInvalidPackageSizeParam && !isInvalidPackage) &&
                content.Count < package.Count)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Insufficient space for content output.");
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (IsInvalidKeySize(key))
            {
                throw new ArgumentOutOfRangeException(nameof(key));
            }

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber));
            }

            if (isInvalidPackageSizeParam)
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize));
            }

            if (IsInvalidAssociatedData(associatedData))
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData));
            }

            if (isInvalidPackage)
            {
                int maxComputedPackageSize = Math.Min(MaxPackageSize, packageSize);

                string badPackageMsg = MinPackageSize == maxComputedPackageSize ?
                    $"Package size must be {MinPackageSize} bytes." :
                    $"Package size must be between {MinPackageSize} and {maxComputedPackageSize} bytes and aligned on a {BlockSize} byte boundary.";

                throw new BadPackageException(badPackageMsg);
            }

            var data = content.Slice(0, package.Count - BlockSize - HashSize); // content + padding

            Span<byte> computedHash = stackalloc byte[HashSize];

            byte[] encKey = new byte[HashSize];
            byte[] signKey = new byte[HashSize];

            byte[] packageHash = new byte[HashSize];

            using (var hmac = new HMACSHA256(key))
            {
                var randomData = package.Slice(0, BlockSize);

                DeriveKeys(hmac, packageNumber, packageSize, randomData, associatedData, encKey, signKey);

                using (var dec = aes.CreateDecryptor(encKey, ZeroIV))
                {
                    // Decrypt package hash
                    dec.TransformBlock(
                        package.Array,
                        package.Offset + BlockSize,
                        HashSize,
                        packageHash,
                        0);

                    // Decrypt (content + padding) directly into output.
                    // IV for the block comes from the previous invocation of the method.
                    dec.TransformBlock(
                        package.Array,
                        package.Offset + BlockSize + HashSize,
                        package.Count - BlockSize - HashSize,
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
        internal static bool IsInvalidPackageSize(int value)
        {
            return value < MinPackageSize || value > MaxPackageSize || IsNotAlignedBlock(value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static bool IsInvalidAssociatedData(ArraySegment<byte> value)
        {
            return value.Count > BlockSize;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static bool IsInvalidKeySize(byte[] value)
        {
            const int MinKeySize = 32;
            const int MaxKeySize = 64;

            var length = value.Length;

            return length < MinKeySize || length > MaxKeySize;
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
    }
}