// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Represents pad-then-mac-then-encrypt chunked data protection using
    /// the HMAC-SHA512 and AES256-CBC algorithms.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="PackageProtector"/> allows 0, 16, or 32 byte IVs. Max content size
    /// per package depends on the IV size.
    /// </para>
    /// <para>
    /// For the 16 byte IV, the package layout is the following:
    /// <code>
    /// |                             package, 64 bytes - 1GiB                              |
    /// +-----------------------------------------------------------------------------------+
    /// | KDF IV      | MAC(content || pad)    | chunk content            | PKCS7 pad       |
    /// +-------------+------------------------+--------------------------+-----------------+
    /// | 16 bytes    | 32 bytes               | 0 - (1GiB - 49 bytes)    | 1 - 16 bytes    |
    /// +-------------+---------------------------------------------------------------------+
    /// |             |                       encrypted (no padding)                        |
    /// </code>
    /// </para>
    /// <para>
    /// The <c>MAC</c> is the leading 32 bytes of an HMAC-SHA512 computed over the
    /// chunk content and PKCS7 padding. Per-package encryption and signing keys are
    /// derived from the supplied <see cref="PackageKey"/> using the IV, package
    /// number, associated data, and package size.
    /// </para>
    /// </remarks>
    public abstract class PackageProtector
    {
        private const int MacSize = Package.MacSize;
        private const int BlockSize = Package.AesBlockSize;
        private const int MaxKdfArgsSize = 80;

        /// <summary>
        /// Gets the system <see cref="PackageProtector"/> implementation, which uses
        /// <see cref="RandomNumberGenerator.Fill(Span{byte})"/> for
        /// cryptographically strong randomness.
        /// </summary>
        /// <remarks>
        /// The instance is configured with a 32 byte <see cref="IvSize"/> and a
        /// 64 KiB (65536 byte) <see cref="MaxPackageSize"/>. These defaults yield a
        /// <see cref="MinPackageSize"/> of 80 bytes, a <see cref="MaxContentSize"/>
        /// of 65471 bytes, and a <see cref="MaxAssociatedDataSize"/> of 48 bytes.
        /// </remarks>
        public static PackageProtector System { get; } = new SystemPackageProtector();

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
        /// and the maximum is <c>1073741824</c>.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="ivSize"/> parameter is not 0, 16 or 32 bytes.
        /// - or -
        /// The <paramref name="packageSize"/> parameter is less than
        /// (<paramref name="ivSize"/> + 48) bytes or greater than <c>1073741824</c> bytes.
        /// </exception>
        protected PackageProtector(int ivSize, int packageSize)
        {
            switch (ivSize)
            {
                case 0:
                case BlockSize:
                case BlockSize + BlockSize:
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(ivSize), "IV size must be 0, 16, or 32 bytes.");
            }

            int minPackageSize = ivSize + MacSize + BlockSize;

            // The package size is capped at 1 GiB.
            const int maxPackageSize = 1024 * 1024 * 1024;

            if (packageSize < minPackageSize || packageSize > maxPackageSize || IsNotAlignedBlock(packageSize))
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize), "Package size must be a multiple of 16 bytes, at least (ivSize + 48), and no greater than 1073741824 bytes.");
            }

            // Overhead is the minimum number of bytes added to content
            // during package protection.
            int overhead = ivSize + MacSize + 1; // One byte for padding.

            this.IvSize = ivSize;
            this.MaxPackageSize = packageSize;
            this.MinPackageSize = minPackageSize;
            this.MaxContentSize = packageSize - overhead;
            this.MaxAssociatedDataSize = MaxKdfArgsSize - ivSize;
        }

        /// <summary>
        /// Gets the KDF IV size in bytes.
        /// </summary>
        /// <remarks>
        /// The value is one of <c>0</c>, <c>16</c>, or <c>32</c> bytes, as specified
        /// when the <see cref="PackageProtector"/> instance was constructed.
        /// </remarks>
        public int IvSize { get; }

        /// <summary>
        /// Gets the max content length in bytes that can be protected by the
        /// <see cref="Protect(ReadOnlySpan{byte}, Span{byte}, PackageKey, long, ReadOnlySpan{byte})"/>
        /// method.
        /// </summary>
        public int MaxContentSize { get; }

        /// <summary>
        /// Gets the min package length in bytes that can be produced by the
        /// <see cref="Protect(ReadOnlySpan{byte}, Span{byte}, PackageKey, long, ReadOnlySpan{byte})"/>
        /// method.
        /// </summary>
        /// <remarks>
        /// The minimum package holds empty content and is equal to
        /// (<see cref="IvSize"/> + 48) bytes.
        /// </remarks>
        public int MinPackageSize { get; }

        /// <summary>
        /// Gets the max package length in bytes that can be produced by the
        /// <see cref="Protect(ReadOnlySpan{byte}, Span{byte}, PackageKey, long, ReadOnlySpan{byte})"/>
        /// method.
        /// </summary>
        public int MaxPackageSize { get; }

        /// <summary>
        /// Gets the max associated data length in bytes that can be used with the
        /// <see cref="Protect(ReadOnlySpan{byte}, Span{byte}, PackageKey, long, ReadOnlySpan{byte})"/>
        /// and <see cref="Unprotect(ReadOnlySpan{byte}, Span{byte}, PackageKey, long, ReadOnlySpan{byte})"/>
        /// methods.
        /// </summary>
        /// <remarks>
        /// The associated data shares the KDF argument region with the IV, so the
        /// value is equal to (80 - <see cref="IvSize"/>) bytes.
        /// </remarks>
        public int MaxAssociatedDataSize { get; }

        /// <summary>
        /// Fills the provided span with cryptographically strong random bytes.
        /// Override to customize the randomness source.
        /// </summary>
        /// <param name="data">
        /// The span to fill with cryptographically strong random bytes.
        /// </param>
        protected virtual void FillRandom(Span<byte> data) => RandomNumberGenerator.Fill(data);

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
        /// The <see cref="PackageKey"/> used to derive the keys that protect the
        /// <paramref name="content"/>.
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
        /// The <paramref name="content"/> length is greater than <see cref="MaxContentSize"/>.
        /// - or -
        /// The <paramref name="package"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="packageNumber"/> is less than zero.
        /// - or -
        /// The <paramref name="associatedData"/> length is greater than <see cref="MaxAssociatedDataSize"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The <paramref name="content"/> and <paramref name="package"/> overlap in memory.
        /// </exception>
        public int Protect(ReadOnlySpan<byte> content, Span<byte> package, PackageKey key, long packageNumber, ReadOnlySpan<byte> associatedData = default)
        {
            if (content.Length > this.MaxContentSize)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Content length is too large.");
            }

            int ivAndMacSize = this.IvSize + MacSize;
            int outputPackageSize = ivAndMacSize + AlignBlock(content.Length);

            if (package.Length < outputPackageSize)
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Insufficient space for package output.");
            }

            ArgumentNullException.ThrowIfNull(key);

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber), "Package number must not be negative.");
            }

            if (associatedData.Length > this.MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var output = package.Slice(0, outputPackageSize);

            if (content.Overlaps(output))
            {
                throw new InvalidOperationException($"The '{nameof(package)}' must not overlap in memory with the '{nameof(content)}'.");
            }

            var data = package.Slice(ivAndMacSize, outputPackageSize - ivAndMacSize);  // content + padding
            var kdfIV = package.Slice(0, this.IvSize);

            try
            {
                this.FillRandom(kdfIV);

                // Copy plain text to output buffer (after iv and mac).
                content.CopyTo(data);

                // Pad data using PKCS7 scheme.
                for (int pos = content.Length,
                    padLength = BlockSize - (pos % BlockSize),
                    padEnd = pos + padLength
                    ; pos < padEnd; pos++)
                {
                    data[pos] = (byte)padLength;
                }

                Span<byte> buf = stackalloc byte[64 + 32];

                Span<byte> tmp64 = buf.Slice(0, 64);
                Span<byte> tmp32 = buf.Slice(64, 32);

                try
                {
                    DeriveKeys(key, packageNumber, this.MaxPackageSize, kdfIV, associatedData, encKey: tmp32, macKey: tmp64);

                    // Sign plaintext and padding.
                    HMACSHA512.HashData(key: tmp64, source: data, destination: tmp64);

                    // Prepend the mac (truncated to 32 bytes) to the padded plaintext.
                    tmp64.Slice(0, MacSize).CopyTo(package.Slice(this.IvSize));

                    using (var aes = Aes.Create())
                    {
                        aes.SetKey(tmp32);

                        // Encrypt buffer in place.
                        aes.EncryptCbcNoPadding(package.Slice(this.IvSize, outputPackageSize - this.IvSize), package.Slice(this.IvSize));
                    }

                    return outputPackageSize;
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
        /// The <see cref="PackageKey"/> used to derive the keys that unprotect the
        /// <paramref name="package"/>.
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
        /// The <paramref name="content"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="packageNumber"/> is less than zero.
        /// - or -
        /// The <paramref name="associatedData"/> length is greater than <see cref="MaxAssociatedDataSize"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The <paramref name="package"/> and <paramref name="content"/> overlap in memory.
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
        public int Unprotect(ReadOnlySpan<byte> package, Span<byte> content, PackageKey key, long packageNumber, ReadOnlySpan<byte> associatedData = default)
        {
            if (this.IsInvalidPackageSize(package.Length))
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Package length is invalid or not aligned to the required boundary.");
            }

            int ivAndMacSize = this.IvSize + MacSize;
            int dataLength = package.Length - ivAndMacSize;

            if (content.Length < dataLength)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Insufficient space for content output.");
            }

            ArgumentNullException.ThrowIfNull(key);

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber), "Package number must not be negative.");
            }

            if (associatedData.Length > this.MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var data = content.Slice(0, dataLength); // content + padding

            if (package.Overlaps(data))
            {
                throw new InvalidOperationException($"The '{nameof(content)}' must not overlap in memory with the '{nameof(package)}'.");
            }

            Span<byte> buf = stackalloc byte[64 + 32];

            Span<byte> tmp64 = buf.Slice(0, 64);
            Span<byte> tmp32 = buf.Slice(64, 32);

            try
            {
                try
                {
                    var kdfIV = package.Slice(0, this.IvSize);

                    DeriveKeys(key, packageNumber, this.MaxPackageSize, kdfIV, associatedData, encKey: tmp32, macKey: tmp64);

                    using (var aes = Aes.Create())
                    {
                        aes.SetKey(tmp32);

                        // Decrypt package mac
                        aes.DecryptCbcNoPadding(
                            package.Slice(this.IvSize, MacSize),
                            tmp32);

                        // Decrypt (content + padding) directly into output.
                        aes.DecryptCbcNoPadding(
                            package.Slice(ivAndMacSize),
                            data,
                            package.Slice(ivAndMacSize - BlockSize, BlockSize));
                    }

                    HMACSHA512.HashData(key: tmp64, source: data, destination: tmp64);

                    if (!CryptographicOperations.FixedTimeEquals(tmp32, tmp64.Slice(0, MacSize)))
                    {
                        throw new BadPackageException();
                    }

                    int padLength = Package.GetPKCS7PaddingLength(BlockSize, data);

                    if (padLength == -1)
                    {
                        throw new BadPackageException();
                    }

                    return data.Length - padLength;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buf);
                }
            }
            catch
            {
                CryptographicOperations.ZeroMemory(data);

                throw;
            }
        }

        /// <summary>
        /// Protects the <paramref name="content"/> stream into the
        /// <paramref name="package"/> destination stream.
        /// </summary>
        /// <param name="content">
        /// The content to protect.
        /// </param>
        /// <param name="package">
        /// The destination to receive the protected <paramref name="content"/>.
        /// </param>
        /// <param name="key">
        /// The <see cref="PackageKey"/> used to derive the keys that protect the
        /// <paramref name="content"/>.
        /// </param>
        /// <param name="associatedData">
        /// The extra data associated with the <paramref name="content"/>, which must match the value
        /// provided during unprotection.
        /// </param>
        /// <param name="cancellationToken">
        /// The token to monitor for cancellation requests.
        /// </param>
        /// <returns>
        /// The number of bytes written to the <paramref name="package"/> destination.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="content"/>, <paramref name="package"/>, or <paramref name="key"/>
        /// parameter is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="associatedData"/> parameter length is greater than <see cref="MaxAssociatedDataSize"/>.
        /// </exception>
        public async Task<long> ProtectAsync(Stream content, Stream package, PackageKey key, ReadOnlyMemory<byte> associatedData = default, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(content);
            ArgumentNullException.ThrowIfNull(package);
            ArgumentNullException.ThrowIfNull(key);

            if (associatedData.Length > this.MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var pool = ArrayPool<byte>.Shared;

            long totalOutputSize = 0L;

            var contentBuffer = new ArraySegment<byte>(pool.Rent(this.MaxPackageSize), 0, this.MaxContentSize);
            var packageBuffer = new ArraySegment<byte>(pool.Rent(this.MaxPackageSize), 0, this.MaxPackageSize);

            long packageNumber = 0L;

            int bytesRead;
            int lastPackageContentSize = this.MaxContentSize;

            try
            {
                do
                {
                    int offset = 0;

                    do
                    {
                        bytesRead = await content.ReadAsync(contentBuffer.Slice(offset, this.MaxContentSize - offset), cancellationToken).ConfigureAwait(false);

                        if (bytesRead == 0)
                        {
                            break;
                        }

                        offset += bytesRead;
                    }
                    while (offset < this.MaxContentSize);

                    if (offset > 0)
                    {
                        int bytesProtected = this.Protect(contentBuffer.Slice(0, offset), packageBuffer, key, packageNumber, associatedData.Span);

                        await package.WriteAsync(packageBuffer.Slice(0, bytesProtected), cancellationToken).ConfigureAwait(false);

                        packageNumber++;
                        lastPackageContentSize = offset;

                        totalOutputSize = checked(totalOutputSize + bytesProtected);
                    }
                }
                while (bytesRead > 0);

                // If last package has only one padding byte,
                // write end of stream (empty) package marker.
                // For empty content write end of stream marker.
                if (lastPackageContentSize == this.MaxContentSize)
                {
                    int bytesProtected = this.Protect(default, packageBuffer, key, packageNumber, associatedData.Span);

                    await package.WriteAsync(packageBuffer.Slice(0, bytesProtected), cancellationToken).ConfigureAwait(false);

                    totalOutputSize = checked(totalOutputSize + bytesProtected);
                }
            }
            finally
            {
                pool.Return(contentBuffer.Array, true);
                pool.Return(packageBuffer.Array);
            }

            return totalOutputSize;
        }

        /// <summary>
        /// Unprotects the <paramref name="package"/> stream into the
        /// <paramref name="content"/> destination stream.
        /// </summary>
        /// <param name="package">
        /// The package to unprotect.
        /// </param>
        /// <param name="content">
        /// The destination to receive the unprotected <paramref name="package"/>.
        /// </param>
        /// <param name="key">
        /// The <see cref="PackageKey"/> used to derive the keys that unprotect the
        /// <paramref name="package"/>.
        /// </param>
        /// <param name="associatedData">
        /// The extra data associated with the <paramref name="package"/>, which must match the value
        /// provided during protection.
        /// </param>
        /// <param name="cancellationToken">
        /// The token to monitor for cancellation requests.
        /// </param>
        /// <returns>
        /// The number of bytes written to the <paramref name="content"/> destination.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="package"/>, <paramref name="content"/>, or <paramref name="key"/>
        /// parameter is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="associatedData"/> parameter length is greater than <see cref="MaxAssociatedDataSize"/>.
        /// </exception>
        /// <exception cref="InvalidDataException">
        /// Unexpected data after end of stream marker.
        /// - or -
        /// Invalid package length. Stream is truncated or corrupted.
        /// - or -
        /// Missing end of stream marker. Stream is truncated or corrupted.
        /// </exception>
        /// <exception cref="BadPackageException">
        /// Package is invalid or corrupted.
        /// - or -
        /// The <paramref name="key"/>,
        /// or <paramref name="associatedData"/> parameter is not valid.
        /// </exception>
        public async Task<long> UnprotectAsync(Stream package, Stream content, PackageKey key, ReadOnlyMemory<byte> associatedData = default, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(package);
            ArgumentNullException.ThrowIfNull(content);
            ArgumentNullException.ThrowIfNull(key);

            if (associatedData.Length > this.MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var pool = ArrayPool<byte>.Shared;

            long totalOutputSize = 0L;

            var packageBuffer = new ArraySegment<byte>(pool.Rent(this.MaxPackageSize), 0, this.MaxPackageSize);
            var contentBuffer = new ArraySegment<byte>(pool.Rent(this.MaxPackageSize), 0, this.MaxPackageSize);

            long packageNumber = 0L;

            int bytesRead;
            int lastPackageContentSize = this.MaxContentSize;

            try
            {
                do
                {
                    int offset = 0;

                    do
                    {
                        bytesRead = await package.ReadAsync(packageBuffer.Slice(offset, this.MaxPackageSize - offset), cancellationToken).ConfigureAwait(false);

                        if (bytesRead == 0)
                        {
                            break;
                        }

                        offset += bytesRead;
                    }
                    while (offset < this.MaxPackageSize);

                    if (offset > 0)
                    {
                        if (lastPackageContentSize < this.MaxContentSize)
                        {
                            // No more packages are allowed once
                            // 'end of stream' is detected.
                            throw new InvalidDataException("Unexpected data after the end-of-stream marker.");
                        }

                        if (this.IsInvalidPackageSize(offset))
                        {
                            throw new InvalidDataException("Invalid package length. The stream is truncated or corrupted.");
                        }

                        int bytesUnprotected = this.Unprotect(packageBuffer.Slice(0, offset), contentBuffer, key, packageNumber, associatedData.Span);

                        if (bytesUnprotected != 0)
                        {
                            await content.WriteAsync(contentBuffer.Slice(0, bytesUnprotected), cancellationToken).ConfigureAwait(false);
                        }

                        packageNumber++;
                        lastPackageContentSize = bytesUnprotected;

                        totalOutputSize = checked(totalOutputSize + bytesUnprotected);
                    }
                }
                while (bytesRead > 0);

                if (lastPackageContentSize == this.MaxContentSize)
                {
                    // Stream must always have 'end of stream' marker which
                    // is an empty package, or not fully populated package.
                    throw new InvalidDataException("Missing end-of-stream marker. The stream is truncated or corrupted.");
                }
            }
            finally
            {
                pool.Return(contentBuffer.Array, true);
                pool.Return(packageBuffer.Array);
            }

            return totalOutputSize;
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
            return value < this.MinPackageSize || value > this.MaxPackageSize || IsNotAlignedBlock(value);
        }

        private static void DeriveKeys(PackageKey key, long packageNumber, int packageSize, ReadOnlySpan<byte> ivArg1, ReadOnlySpan<byte> ivArg2, Span<byte> encKey, Span<byte> macKey)
        {
            ReadOnlySpan<byte> encLabel = "ENC"u8;
            ReadOnlySpan<byte> macLabel = "MAC"u8;

            Span<byte> context = stackalloc byte[99];

            BinaryPrimitives.WriteUInt64BigEndian(context, (ulong)packageNumber);

            var ivArgs = context.Slice(8, MaxKdfArgsSize);

            ivArg1.CopyTo(ivArgs);
            ivArg2.CopyTo(ivArgs.Slice(ivArg1.Length));

            ivArgs.Slice(ivArg1.Length + ivArg2.Length).Clear();

            context[88] = (byte)ivArg1.Length;
            context[89] = (byte)ivArg2.Length;
            context[90] = 0; // Reserved for future use (e.g. ivArg3 length).
            context[91] = BlockSize; // Package padding size in bytes.

            BinaryPrimitives.WriteUInt32BigEndian(context.Slice(92), (uint)packageSize);

            context[96] = 0; // Reserved for future use.
            context[97] = 0; // Reserved for future use.
            context[98] = 1; // Format version number.

            key.DeriveKey(encLabel, context, encKey);
            key.DeriveKey(macLabel, context, macKey);
        }

        /// <summary>
        /// System default package protector implementation that uses
        /// a 32 byte IV and a 64 KiB package size.
        /// </summary>
        private sealed class SystemPackageProtector : PackageProtector
        {
            public SystemPackageProtector() : base(ivSize: 32, packageSize: 64 * 1024)
            {
            }
        }
    }
}