// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides support to wrap keys with the PBKDF2-HMAC-SHA512 password protection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="KeyProtector"/> uses HMAC-SHA512 and AES256-CBC to sign-then-encrypt
    /// the provided key data.
    /// </para>
    /// <para>
    /// The package layout for the protected key data is the following:
    /// <code>
    /// +-----------+--------------+--------+--------+-------------+------------+
    /// |  Version  |  Iterations  |  Salt  |  HMAC  |  Key Data   |  Checksum  |
    /// +-----------+--------------+--------+--------+-------------+------------+
    /// |  4        |  4           |  40    |  32    |  32..65424  |  16        |
    /// +-----------+--------------+--------+--------+-------------+------------+
    /// |                                   |      encrypted       |            |    
    /// </code>
    /// </para>
    /// <para>
    /// The <c>Checksum</c> is an unkeyed SHA-512 digest that provides integrity only.
    /// It detects accidental corruption and allows a fast fail before the expensive
    /// key derivation runs, but it offers no protection against deliberate tampering.
    /// Authenticity is provided solely by the encrypted <c>HMAC</c>.
    /// </para>
    /// </remarks>
    public class KeyProtector
    {
        private const int SaltSize = 40;
        private const int VersionSize = sizeof(uint);
        private const int IterCounterSize = sizeof(uint);
        private const int MacSize = 32;
        private const int BlockSize = 16;
        private const int ChecksumSize = 16;
        private const int OverheadSize = VersionSize + IterCounterSize + SaltSize + MacSize + ChecksumSize;
        private const int MinContentSize = 32;
        private const int MaxContentSize = ((ushort.MaxValue - OverheadSize) / BlockSize) * BlockSize;
        private const int MinPackageSize = MinContentSize + OverheadSize;
        private const int MaxPackageSize = MaxContentSize + OverheadSize;
        private const int MaxAssociatedDataSize = 64;

        private const uint Version = ((uint)'P' << 24) | ((uint)'B' << 16) | ((uint)'2' << 8) | (uint)'K';

        private static readonly UTF8Encoding SafeEncoding = new UTF8Encoding(false, true);

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyProtector"/> class.
        /// </summary>
        public KeyProtector()
        {
        }

        /// <summary>
        /// Gets the number of bytes added to content during protection.
        /// </summary>
        public int Overhead => OverheadSize;

        /// <summary>
        /// Fills the provided <paramref name="data"/> span with
        /// cryptographically strong random bytes.
        /// </summary>
        /// <param name="data">
        /// The span to fill with cryptographically strong random bytes.
        /// </param>
        protected virtual void FillRandom(Span<byte> data) => RandomNumberGenerator.Fill(data);

        /// <summary>
        /// Protects the <paramref name="content"/> into the <paramref name="package"/> destination.
        /// </summary>
        /// <param name="content">
        /// The content to protect. Max content length is 65424 bytes.
        /// </param>
        /// <param name="package">
        /// The destination to receive the protected <paramref name="content"/>.
        /// </param>
        /// <param name="password">
        /// The password used to protect the <paramref name="content"/>.
        /// </param>
        /// <param name="iterations">
        /// The number of iterations for a key derivation operation.
        /// </param>
        /// <param name="associatedData">
        /// The extra data associated with the <paramref name="content"/>, which must match the value
        /// provided during unprotection.
        /// </param>
        /// <returns>
        /// The number of bytes written to the <paramref name="package"/> destination.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="content"/> length is too large.
        /// - or -
        /// The <paramref name="package"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="iterations"/> is not a positive value.
        /// - or -
        /// The <paramref name="associatedData"/> length is too large.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The <paramref name="content"/> and <paramref name="package"/> overlap in memory.
        /// </exception>
        public int Protect(ReadOnlySpan<byte> content, Span<byte> package, ReadOnlySpan<char> password, int iterations, ReadOnlySpan<byte> associatedData = default)
        {
            if (content.Length < MinContentSize || content.Length > MaxContentSize || (content.Length % BlockSize) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Content length is invalid or not aligned to the required boundary.");
            }

            int outputPackageSize = content.Length + OverheadSize;

            if (package.Length < outputPackageSize)
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Insufficient space for package output.");
            }

            if (iterations <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be a positive value.");
            }

            if (associatedData.Length > MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var output = package.Slice(0, outputPackageSize);

            if (output.Overlaps(content))
            {
                throw new InvalidOperationException($"The '{nameof(package)}' must not overlap in memory with the '{nameof(content)}'.");
            }

            try
            {
                BinaryPrimitives.WriteUInt32BigEndian(output, Version);
                BinaryPrimitives.WriteUInt32BigEndian(output.Slice(VersionSize), (uint)iterations);

                var salt = output.Slice(VersionSize + IterCounterSize, SaltSize);

                this.FillRandom(salt);

                Span<byte> buf = stackalloc byte[64 + 32];

                Span<byte> tmp64 = buf.Slice(0, 64);
                Span<byte> tmp32 = buf.Slice(64, 32);

                try
                {
                    PrehashPassword(password, salt: output.Slice(0, VersionSize + IterCounterSize + SaltSize), associatedData, destination: tmp64);

                    PrehashedPbkdf2(prehashedPassword: tmp64, destination: tmp64, iterations);

                    DeriveKeys(key: tmp64, encryptionKey: tmp32, signingKey: tmp64);

                    HMACSHA512.HashData(key: tmp64, source: content, destination: tmp64);

                    using (var aes = Aes.Create())
                    {
                        aes.SetKey(tmp32);

                        aes.EncryptCbcNoPadding(
                            tmp64.Slice(0, MacSize),
                            output.Slice(VersionSize + IterCounterSize + SaltSize));

                        aes.EncryptCbcNoPadding(
                            content,
                            output.Slice(VersionSize + IterCounterSize + SaltSize + MacSize),
                            output.Slice(VersionSize + IterCounterSize + SaltSize + MacSize - BlockSize, BlockSize));
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buf);
                }

                int checksumOffset = outputPackageSize - ChecksumSize;

                SHA512.HashData(output.Slice(0, checksumOffset), tmp64);

                tmp64.Slice(0, ChecksumSize).CopyTo(output.Slice(checksumOffset));

                return outputPackageSize;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(output);

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
        /// <param name="password">
        /// The password used to unprotect the <paramref name="package"/>.
        /// </param>
        /// <param name="associatedData">
        /// The extra data associated with the <paramref name="package"/>, which must match the value
        /// provided during protection.
        /// </param>
        /// <returns>
        /// The number of bytes written to the <paramref name="content"/> destination.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="package"/> length is not correct.
        /// - or -
        /// The <paramref name="content"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="associatedData"/> length is too large.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The <paramref name="package"/> and <paramref name="content"/> overlap in memory.
        /// </exception>
        /// <exception cref="BadPackageException">
        /// The <paramref name="package"/> version is invalid.
        /// - or -
        /// The <paramref name="package"/> iterations count is invalid.
        /// - or -
        /// The <paramref name="package"/> checksum is invalid.
        /// </exception>
        /// <exception cref="BadPasswordException">
        /// The provided <paramref name="password"/> is incorrect.
        /// </exception>
        public int Unprotect(ReadOnlySpan<byte> package, Span<byte> content, ReadOnlySpan<char> password, ReadOnlySpan<byte> associatedData = default)
        {
            if (package.Length < MinPackageSize || package.Length > MaxPackageSize || (package.Length % BlockSize) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Package length is invalid or not aligned to the required boundary.");
            }

            int outputContentSize = package.Length - OverheadSize;

            if (content.Length < outputContentSize)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Insufficient space for content output.");
            }

            if (associatedData.Length > MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var output = content.Slice(0, outputContentSize);

            if (output.Overlaps(package))
            {
                throw new InvalidOperationException($"The '{nameof(content)}' must not overlap in memory with the '{nameof(package)}'.");
            }

            if (BinaryPrimitives.ReadUInt32BigEndian(package) != Version)
            {
                throw new BadPackageException("The package version is invalid.");
            }

            int iterations = (int)BinaryPrimitives.ReadUInt32BigEndian(package.Slice(VersionSize));

            if (iterations <= 0)
            {
                throw new BadPackageException("The package iteration count is invalid.");
            }

            Span<byte> buf = stackalloc byte[64 + 32];

            Span<byte> tmp64 = buf.Slice(0, 64);
            Span<byte> tmp32 = buf.Slice(64, 32);

            int checksumOffset = package.Length - ChecksumSize;

            SHA512.HashData(package.Slice(0, checksumOffset), tmp64);

            if (!CryptographicOperations.FixedTimeEquals(package.Slice(checksumOffset), tmp64.Slice(0, ChecksumSize)))
            {
                throw new BadPackageException("The package checksum is invalid.");
            }

            try
            {
                try
                {
                    PrehashPassword(password, salt: package.Slice(0, VersionSize + IterCounterSize + SaltSize), associatedData, destination: tmp64);

                    PrehashedPbkdf2(prehashedPassword: tmp64, destination: tmp64, iterations);

                    DeriveKeys(key: tmp64, encryptionKey: tmp32, signingKey: tmp64);

                    using (var aes = Aes.Create())
                    {
                        aes.SetKey(tmp32);

                        aes.DecryptCbcNoPadding(
                            package.Slice(VersionSize + IterCounterSize + SaltSize, MacSize),
                            tmp32);

                        aes.DecryptCbcNoPadding(
                            package.Slice(VersionSize + IterCounterSize + SaltSize + MacSize, outputContentSize),
                            output,
                            package.Slice(VersionSize + IterCounterSize + SaltSize + MacSize - BlockSize, BlockSize));
                    }

                    HMACSHA512.HashData(key: tmp64, source: output, destination: tmp64);

                    if (!CryptographicOperations.FixedTimeEquals(tmp64.Slice(0, MacSize), tmp32))
                    {
                        throw new BadPasswordException();
                    }

                    return outputContentSize;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buf);
                }
            }
            catch
            {
                CryptographicOperations.ZeroMemory(output);

                throw;
            }
        }

        private static void DeriveKeys(ReadOnlySpan<byte> key, Span<byte> encryptionKey, Span<byte> signingKey)
        {
            ReadOnlySpan<byte> encLabel = new byte[] { (byte)'A', (byte)'E', (byte)'S', (byte)'2', (byte)'5', (byte)'6', (byte)'-', (byte)'C', (byte)'B', (byte)'C' };
            ReadOnlySpan<byte> macLabel = new byte[] { (byte)'H', (byte)'M', (byte)'A', (byte)'C', (byte)'-', (byte)'S', (byte)'H', (byte)'A', (byte)'5', (byte)'1', (byte)'2', (byte)'-', (byte)'2', (byte)'5', (byte)'6' };

            ReadOnlySpan<byte> versionContext = new byte[] { (byte)'P', (byte)'B', (byte)'2', (byte)'K' };

            using (var kdf = new PackageKey(key))
            {
                kdf.DeriveKey(label: encLabel, context: versionContext, destination: encryptionKey);
                kdf.DeriveKey(label: macLabel, context: versionContext, destination: signingKey);
            }
        }

        private static void PrehashPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> associatedData, Span<byte> destination)
        {
            const byte BLOCK_SIZE = 128; // The HMACSHA512 recommended key size
            const byte HASH_SIZE = 64; // The HMACSHA512 output hash size

            int pswBytesCapacity = SafeEncoding.GetMaxByteCount(password.Length);
            int bufSize = BLOCK_SIZE + pswBytesCapacity;

            byte[] bufArray = ArrayPool<byte>.Shared.Rent(bufSize);

            Span<byte> buf = bufArray;

            try
            {
                int pswBytesCount = SafeEncoding.GetBytes(password, buf.Slice(BLOCK_SIZE));

                // The combined size of the key and the UTF8 password bytes.
                buf = buf.Slice(0, BLOCK_SIZE + pswBytesCount);

                var key = buf.Slice(0, BLOCK_SIZE);

                key.Clear();

                key[0] = 1; // format version
                key[1] = HASH_SIZE; // requested hash output size
                key[2] = (byte)salt.Length;
                key[3] = (byte)associatedData.Length;

                salt.CopyTo(key.Slice(sizeof(uint)));
                associatedData.CopyTo(key.Slice(sizeof(uint) + salt.Length));

                var pswBytes = buf.Slice(BLOCK_SIZE);

                HMACSHA512.HashData(key, pswBytes, destination);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buf);

                ArrayPool<byte>.Shared.Return(bufArray);
            }
        }

        private static void PrehashedPbkdf2(ReadOnlySpan<byte> prehashedPassword, Span<byte> destination, int iterations)
        {
            // PREHASHED PASSWORD ALREADY INCLUDES SALT AND ASSOCIATED DATA
            ReadOnlySpan<byte> salt = new byte[60]
            {
                (byte)'P', (byte)'R', (byte)'E', (byte)'H', (byte)'A', (byte)'S', (byte)'H', (byte)'E', (byte)'D', (byte)' ',
                (byte)'P', (byte)'A', (byte)'S', (byte)'S', (byte)'W', (byte)'O', (byte)'R', (byte)'D', (byte)' ', (byte)'A',
                (byte)'L', (byte)'R', (byte)'E', (byte)'A', (byte)'D', (byte)'Y', (byte)' ', (byte)'I', (byte)'N', (byte)'C',
                (byte)'L', (byte)'U', (byte)'D', (byte)'E', (byte)'S', (byte)' ', (byte)'S', (byte)'A', (byte)'L', (byte)'T',
                (byte)' ', (byte)'A', (byte)'N', (byte)'D', (byte)' ', (byte)'A', (byte)'S', (byte)'S', (byte)'O', (byte)'C',
                (byte)'I', (byte)'A', (byte)'T', (byte)'E', (byte)'D', (byte)' ', (byte)'D', (byte)'A', (byte)'T', (byte)'A'
            };

            Rfc2898DeriveBytes.Pbkdf2(prehashedPassword, salt, destination, iterations, HashAlgorithmName.SHA512);
        }
    }
}
