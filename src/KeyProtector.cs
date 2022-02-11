// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides support to wrap keys with the PBKDF2-HMAC-SHA512 password protection.
    /// </summary>
    /// <remarks>
    /// <code>
    /// +-----------+----------------+--------+--------+-------------+------------+
    /// |  Version  |  Iter Counter  |  Salt  |  HMAC  |  Key Data   |  Checksum  |
    /// +-----------+----------------+--------+--------+-------------+------------+
    /// |  4        |  4             |  40    |  32    |  32..65439  |  16        |
    /// +-----------+----------------+--------+--------+-------------+------------+
    /// |                                     |      encrypted       |            |    
    /// </code>
    /// </remarks>
    public sealed class KeyProtector : IDisposable
    {
        private const int SaltSize = 40;
        private const int VersionSize = sizeof(uint);
        private const int IterCounterSize = sizeof(uint);
        private const int MacSize = 32;
        private const int BlockSize = 16;
        private const int ChecksumSize = 16;
        private const int OverheadSize = VersionSize + IterCounterSize + SaltSize + MacSize + ChecksumSize;
        private const int MinContentSize = 32;
        private const int MaxContentSize = ushort.MaxValue - OverheadSize;
        private const int MinPackageSize = MinContentSize + OverheadSize;
        private const int MaxPackageSize = MaxContentSize + OverheadSize;

        private const uint Version = ((uint)'p' << 24) | ((uint)'b' << 16) | ((uint)'2' << 8) | (uint)'k';

        private readonly RngFillAction _rngFill;

        private bool _IsDisposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyProtector"/> class.
        /// </summary>
        /// <param name="rngFill">
        /// A callback to fill a span with cryptographically strong random bytes.
        /// When not provided, a default <see cref="RandomNumberGenerator.Fill"/>
        /// implementation is used.
        /// </param>
        public KeyProtector(RngFillAction rngFill = null)
        {
            this._rngFill = rngFill ?? new RngFillAction(RandomNumberGenerator.Fill);
        }

        private static ReadOnlySpan<byte> EncLabel => new byte[] { (byte)'A', (byte)'E', (byte)'S', (byte)'2', (byte)'5', (byte)'6', (byte)'-', (byte)'C', (byte)'B', (byte)'C' };

        private static ReadOnlySpan<byte> MacLabel => new byte[] { (byte)'H', (byte)'M', (byte)'A', (byte)'C', (byte)'-', (byte)'S', (byte)'H', (byte)'A', (byte)'5', (byte)'1', (byte)'2' };

        private static ReadOnlySpan<byte> ZeroIV => new byte[BlockSize] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        /// <summary>
        /// Gets the number of bytes added to content during protection.
        /// </summary>
        public int Overhead => OverheadSize;

        /// <summary>
        /// Protects the <paramref name="content"/> into the <paramref name="package"/> destination.
        /// </summary>
        /// <param name="content">
        /// The content to protect.
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
        /// <returns>
        /// The number of bytes written to the <paramref name="package"/> destination.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="content"/> length is too large.
        /// - or -
        /// The <paramref name="package"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="iterations"/> is not a positive value.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The <paramref name="content"/> and <paramref name="package"/> overlap in memory.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// The <see cref="KeyProtector"/> object has already been disposed.
        /// </exception>
        public int Protect(ReadOnlySpan<byte> content, Span<byte> package, ReadOnlySpan<char> password, int iterations)
        {
            if (content.Length < MinContentSize || content.Length > MaxContentSize || (content.Length % BlockSize) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Content length is invalid or not aligned on the required boundary.");
            }

            int outputPackageSize = content.Length + OverheadSize;

            if (package.Length < outputPackageSize)
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Insufficient space for package output.");
            }

            if (iterations <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations));
            }

            var output = package.Slice(0, outputPackageSize);

            if (output.Overlaps(content))
            {
                throw new InvalidOperationException($"The '{nameof(package)}' must not overlap in memory with the '{nameof(content)}'.");
            }

            if (this._IsDisposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            try
            {
                BinaryPrimitives.WriteUInt32BigEndian(output, Version);
                BinaryPrimitives.WriteUInt32BigEndian(output.Slice(VersionSize), (uint)iterations);

                var salt = output.Slice(VersionSize + IterCounterSize, SaltSize);

                this._rngFill(salt);

                byte[] tmp64 = new byte[64];
                byte[] tmp32 = new byte[32];

                Span<byte> tmp64Span = tmp64;

                Rfc2898DeriveBytes.Pbkdf2(password, salt, tmp64Span, iterations, HashAlgorithmName.SHA512);

                using (var hmac = new HMACSHA512(tmp64))
                {
                    hmac.DeriveKey(EncLabel, null, tmp32);
                    hmac.DeriveKey(MacLabel, null, tmp64Span);

                    hmac.Key = tmp64;

                    hmac.ComputeHash(content, tmp64Span);
                }

                using (var aes = Aes.Create())
                {
                    aes.Key = tmp32;

                    aes.EncryptCbc(
                        tmp64Span.Slice(0, MacSize),
                        ZeroIV,
                        output.Slice(VersionSize + IterCounterSize + SaltSize),
                        PaddingMode.None);

                    aes.EncryptCbc(
                        content,
                        output.Slice(VersionSize + IterCounterSize + SaltSize + MacSize - BlockSize, BlockSize),
                        output.Slice(VersionSize + IterCounterSize + SaltSize + MacSize),
                        PaddingMode.None);
                }

                int checksumOffset = outputPackageSize - ChecksumSize;

                SHA512.HashData(output.Slice(0, checksumOffset), tmp64Span);

                tmp64Span.Slice(0, ChecksumSize).CopyTo(output.Slice(checksumOffset));

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
        /// <returns>
        /// The number of bytes written to the <paramref name="content"/> destination.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="package"/> length is not correct.
        /// - or -
        /// The <paramref name="content"/> destination space is insufficient.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The <paramref name="package"/> and <paramref name="content"/> overlap in memory.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// The <see cref="KeyProtector"/> object has already been disposed.
        /// </exception>
        /// <exception cref="BadPackageException">
        /// The <paramref name="package"/> version is invalid.
        /// - or -
        /// The <paramref name="package"/> iterations count is invalid.
        /// - or -
        /// The <paramref name="package"/> checksum is invalid.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The provided <paramref name="password"/> is incorrect.
        /// </exception>
        public int Unprotect(ReadOnlySpan<byte> package, Span<byte> content, ReadOnlySpan<char> password)
        {
            if (package.Length < MinPackageSize || package.Length > MaxPackageSize || (package.Length % BlockSize) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Package length is invalid or not aligned on the required boundary.");
            }

            int outputContentSize = package.Length - Overhead;

            if (content.Length < outputContentSize)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Insufficient space for content output.");
            }

            var output = content.Slice(0, outputContentSize);

            if (output.Overlaps(package))
            {
                throw new InvalidOperationException($"The '{nameof(content)}' must not overlap in memory with the '{nameof(package)}'.");
            }

            if (this._IsDisposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            if (BinaryPrimitives.ReadUInt32BigEndian(package) != Version)
            {
                throw new BadPackageException("The package version is invalid.");
            }

            uint iterations = BinaryPrimitives.ReadUInt32BigEndian(package.Slice(VersionSize));

            if (iterations > int.MaxValue)
            {
                throw new BadPackageException("The package iterations count is invalid.");
            }

            byte[] tmp64 = new byte[64];
            byte[] tmp32 = new byte[32];

            Span<byte> tmp64Span = tmp64;
            Span<byte> tmp32Span = tmp32;

            int checksumOffset = package.Length - ChecksumSize;

            SHA512.HashData(package.Slice(0, checksumOffset), tmp64Span);

            if (!CryptographicOperations.FixedTimeEquals(package.Slice(checksumOffset), tmp64Span.Slice(0, ChecksumSize)))
            {
                throw new BadPackageException("The package checksum is invalid.");
            }

            try
            {
                Rfc2898DeriveBytes.Pbkdf2(password, package.Slice(VersionSize + IterCounterSize, SaltSize), tmp64Span, (int)iterations, HashAlgorithmName.SHA512);

                using (var hmac = new HMACSHA512(tmp64))
                {
                    hmac.DeriveKey(EncLabel, null, tmp32);
                    hmac.DeriveKey(MacLabel, null, tmp64Span);

                    using (var aes = Aes.Create())
                    {
                        aes.Key = tmp32;

                        aes.DecryptCbc(
                            package.Slice(VersionSize + IterCounterSize + SaltSize, MacSize),
                            ZeroIV,
                            tmp32Span,
                            PaddingMode.None);

                        aes.DecryptCbc(
                            package.Slice(VersionSize + IterCounterSize + SaltSize + MacSize, outputContentSize),
                            package.Slice(VersionSize + IterCounterSize + SaltSize + MacSize - BlockSize, BlockSize),
                            output,
                            PaddingMode.None);
                    }

                    hmac.Key = tmp64;

                    hmac.ComputeHash(output, tmp64Span);
                }

                if (!CryptographicOperations.FixedTimeEquals(tmp64Span.Slice(0, MacSize), tmp32Span))
                {
                    throw new CryptographicException("The provided password is incorrect.");
                }

                return outputContentSize;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(output);

                throw;
            }
        }

        /// <summary>
        /// Releases all resources used by the current instance
        /// of the <see cref="KeyProtector"/> class.
        /// </summary>
        public void Dispose()
        {
            this._IsDisposed = true;
        }
    }
}