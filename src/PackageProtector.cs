// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    public static class PackageProtector
    {
        /// <summary>
        /// AES256 block size, IV size, max associated data size, salt size.
        /// </summary>
        internal const int BlockSize = 16;

        /// <summary>
        /// HMAC-SHA256 hash size, HMAC key size, AES256 key size.
        /// </summary>
        private const int HashSize = 32;

        /// <summary>
        /// The minimum number of bytes added to content
        /// during package protection.
        /// </summary>
        public const int Overhead = BlockSize + HashSize + 1; // One byte for padding.

        private const int MinPackageSize = BlockSize + BlockSize + HashSize;

        private const int MaxPackageSize = (16 * 1024 * 1024) - BlockSize;

        private const int MaxContentSize = MaxPackageSize - Overhead;

        private static Aes aes = CreateAes();
        
        private static Aes CreateAes()
        {
            var aes = Aes.Create();

            aes.Padding = PaddingMode.None; // Padding is done manually.
            aes.Mode = CipherMode.CBC;

            return aes;
        }

        public static int Protect(ArraySegment<byte> content, ArraySegment<byte> package, byte[] key, long packageNumber, int packageSize, ArraySegment<byte> associatedData)
        {
            bool isInvalidPackageSizeParam = IsInvalidPackageSize(packageSize);
            int maxAllowedContentSize = isInvalidPackageSizeParam ? MaxContentSize : packageSize - Overhead;

            if (content.Count > maxAllowedContentSize)
            {
                throw new ArgumentOutOfRangeException(nameof(content), $"Content cannot be larger than '{maxAllowedContentSize}' bytes.");
            }

            int outputPackageSize = BlockSize + AlignBlock(content.Count) + HashSize;

            if (package.Count < outputPackageSize)
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Insufficiet space for package output.");
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber));
            }

            if (isInvalidPackageSizeParam)
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize));
            }

            if (associatedData.Count > BlockSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData));
            }

            var data = package.Slice(BlockSize, outputPackageSize - BlockSize - HashSize);  // content + padding
            var randomData = package.Slice(0, BlockSize);

            RandomNumberGenerator.Fill(randomData);

            // If ArraySegment is 'default' or 'null' then Array property will be 'null'.
            if (content.Array != null)
            {
                // Copy plain text to output buffer (after random bytes).
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

                // Sign plaintext and padding, then append hash to padded plaintext.
                hmac.ComputeHash(data, package.Slice(outputPackageSize - HashSize, HashSize));
            }

            using (var enc = aes.CreateEncryptor(encKey, randomData.ToArray()))
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

        public static int Unprotect(ArraySegment<byte> package, ArraySegment<byte> content, byte[] key, long packageNumber, int packageSize, ArraySegment<byte> associatedData)
        {
            bool isInvalidPackageSizeParam = IsInvalidPackageSize(packageSize);
            bool isInvalidPackage = IsInvalidPackageSize(package.Count) || package.Count > packageSize;

            if ((!isInvalidPackageSizeParam && !isInvalidPackage) &&
                content.Count < package.Count)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Insufficiet space for content output.");
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber));
            }

            if (isInvalidPackageSizeParam)
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize));
            }

            if (associatedData.Count > BlockSize)
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

            using (var hmac = new HMACSHA256(key))
            {
                var randomData = package.Slice(0, BlockSize);

                DeriveKeys(hmac, packageNumber, packageSize, randomData, associatedData, encKey, signKey);

                using (var dec = aes.CreateDecryptor(encKey, randomData.ToArray()))
                {
                    dec.TransformBlock(
                        package.Array,
                        package.Offset + BlockSize,
                        package.Count - BlockSize,
                        content.Array,
                        content.Offset);
                }

                hmac.Key = signKey;

                // Sign plaintext and padding.
                hmac.ComputeHash(data, computedHash);
            }

            if (!CryptographicOperations.FixedTimeEquals(computedHash, content.Slice(data.Count, HashSize)))
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

        /// <summary>
        /// Aligns the <paramref name="value"/> on <see cref="BlockSize"/> byte boundary.
        /// If <paramref name="value"/> is already aligned or zero,
        /// extends the value by extra <see cref="BlockSize"/> bytes.
        /// </summary>
        /// <param name="value">
        /// The value to align or extend.
        /// </param>
        /// <returns>
        /// The aligned <paramref name="value"/>.
        /// </returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int AlignBlock(int value)
        {
            const int align = BlockSize;

            return value + (align - (value % align));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static bool IsInvalidPackageSize(int value)
        {
            return value < MinPackageSize || value > MaxPackageSize || IsNotAlignedBlock(value);
        }

        internal static void DeriveKeys(HMACSHA256 hmac, long packageNumber, int packageSize, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> associatedData, Span<byte> encryptionKey, Span<byte> signingKey)
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

            data[4] = 0; // Reserved for future use.
            data[5] = EncryptPurpose;
            data[6] = (byte)associatedData.Length;            

            data[7] = 0; // SP800-108 label and context separator.

            data[8] = (byte)(packageNumber >> 56);
            data[9] = (byte)(packageNumber >> 48);
            data[10] = (byte)(packageNumber >> 40);
            data[11] = (byte)(packageNumber >> 32);
            data[12] = (byte)(packageNumber >> 24);
            data[13] = (byte)(packageNumber >> 16);
            data[14] = (byte)(packageNumber >> 8);
            data[15] = (byte)packageNumber;

            salt.CopyTo(data.Slice(16, BlockSize)); // Salt must be always equal to block size.

            var destAD = data.Slice(32, BlockSize);
            destAD.Clear();

            associatedData.CopyTo(destAD);

            data[48] = (byte)(packageSize >> 16);
            data[49] = (byte)(packageSize >> 8);
            data[50] = (byte)packageSize;

            data[51] = (byte)(derivedKeyLengthInBits >> 24);
            data[52] = (byte)(derivedKeyLengthInBits >> 16);
            data[53] = (byte)(derivedKeyLengthInBits >> 8);
            data[54] = (byte)(derivedKeyLengthInBits & 0xff);

            hmac.ComputeHash(data, encryptionKey);

            data[5] = SignPurpose;

            hmac.ComputeHash(data, signingKey);
        }
    }
}