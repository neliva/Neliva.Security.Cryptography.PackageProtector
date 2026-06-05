// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

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
    public abstract class PackageProtector
    {
        private const int BlockSize = 16; // AES block size.
        private const int HashSize = 32;  // HMAC-SHA256 hash and key size, AES256 key size.

        private readonly int _IvSize;
        private readonly int _IvAndHashSize;
        private readonly int _MaxPackageSize;
        private readonly int _MinPackageSize;
        private readonly int _MaxContentSize;
        private readonly int _MaxAssociatedDataSize;

        /// <summary>
        /// Gets the system <see cref="PackageProtector"/> implementation, which uses
        /// <see cref="RandomNumberGenerator.Fill(Span{byte})"/> for
        /// cryptographically strong randomness.
        /// </summary>
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
        /// and the maximum is <c>16777200</c>.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="ivSize"/> parameter is not 0, 16 or 32 bytes.
        /// - or -
        /// The <paramref name="packageSize"/> parameter is less than
        /// (<paramref name="ivSize"/> + 48) bytes or greater than <c>16777200</c> bytes.
        /// </exception>
        protected PackageProtector(int ivSize = BlockSize, int packageSize = 64 * 1024)
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

            int minPackageSize = ivSize + HashSize + BlockSize;

            const int KdfMaxPackageSize = (16 * 1024 * 1024) - BlockSize; // Our KDF imposes this limit.

            if (packageSize < minPackageSize || packageSize > KdfMaxPackageSize || IsNotAlignedBlock(packageSize))
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize), "Package size must be a multiple of 16 bytes, at least (ivSize + 48), and no greater than 16777200 bytes.");
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
        }

        /// <summary>
        /// Gets the max content length in bytes that can be protected by the
        /// <see cref="Protect(ReadOnlySpan{byte}, Span{byte}, PackageKey, long, ReadOnlySpan{byte})"/>
        /// method.
        /// </summary>
        public int MaxContentSize => this._MaxContentSize;

        /// <summary>
        /// Gets the max package length in bytes that can be produced by the
        /// <see cref="Protect(ReadOnlySpan{byte}, Span{byte}, PackageKey, long, ReadOnlySpan{byte})"/>
        /// method.
        /// </summary>
        public int MaxPackageSize => this._MaxPackageSize;

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
        public int Protect(ReadOnlySpan<byte> content, Span<byte> package, PackageKey key, long packageNumber, ReadOnlySpan<byte> associatedData = default)
        {
            if (content.Length > this._MaxContentSize)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Content length is too large.");
            }

            int outputPackageSize = this._IvAndHashSize + AlignBlock(content.Length);

            if (package.Length < outputPackageSize)
            {
                throw new ArgumentOutOfRangeException(nameof(package), "Insufficient space for package output.");
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber), "Package number must not be negative.");
            }

            if (associatedData.Length > this._MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var output = package.Slice(0, outputPackageSize);

            if (content.Overlaps(output))
            {
                throw new InvalidOperationException($"The '{nameof(package)}' must not overlap in memory with the '{nameof(content)}'.");
            }

            var data = package.Slice(this._IvAndHashSize, outputPackageSize - this._IvAndHashSize);  // content + padding
            var kdfIV = package.Slice(0, this._IvSize);

            try
            {
                this.FillRandom(kdfIV);

                // Copy plain text to output buffer (after iv and hash).
                content.CopyTo(data);

                // Pad data using PKCS7 scheme.
                for (int pos = content.Length,
                    padLength = BlockSize - (pos % BlockSize),
                    padEnd = pos + padLength
                    ; pos < padEnd; pos++)
                {
                    data[pos] = (byte)padLength;
                }

                Span<byte> buf = stackalloc byte[HashSize + HashSize];

                Span<byte> encKey = buf.Slice(0, HashSize);
                Span<byte> signKey = buf.Slice(HashSize, HashSize);

                try
                {
                    DeriveKeys(key, packageNumber, this._MaxPackageSize, kdfIV, associatedData, encKey, signKey);

                    // Sign plaintext and padding, then prepend hash to padded plaintext.
                    HMACSHA256.HashData(signKey, data, package.Slice(this._IvSize, HashSize));

                    using (var aes = Aes.Create())
                    {
                        aes.SetKey(encKey);

                        // Encrypt buffer in place.
                        aes.EncryptCbcNoPadding(package.Slice(this._IvSize, outputPackageSize - this._IvSize), package.Slice(this._IvSize));
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
        /// The <paramref name="content"/> destination space is insufficient.
        /// - or -
        /// The <paramref name="packageNumber"/> is less than zero.
        /// - or -
        /// The <paramref name="associatedData"/> length is too large.
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

            int dataLength = package.Length - this._IvAndHashSize;

            if (content.Length < dataLength)
            {
                throw new ArgumentOutOfRangeException(nameof(content), "Insufficient space for content output.");
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (packageNumber < 0L)
            {
                throw new ArgumentOutOfRangeException(nameof(packageNumber), "Package number must not be negative.");
            }

            if (associatedData.Length > this._MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var data = content.Slice(0, dataLength); // content + padding

            if (package.Overlaps(data))
            {
                throw new InvalidOperationException($"The '{nameof(content)}' must not overlap in memory with the '{nameof(package)}'.");
            }

            Span<byte> buf = stackalloc byte[HashSize + HashSize];

            Span<byte> tmpASpan = buf.Slice(0, HashSize); // Used for encKey and decrypted hash
            Span<byte> tmpBSpan = buf.Slice(HashSize, HashSize); // Used for signKey and computed hash

            try
            {
                try
                {
                    var kdfIV = package.Slice(0, this._IvSize);

                    DeriveKeys(key, packageNumber, this._MaxPackageSize, kdfIV, associatedData, tmpASpan, tmpBSpan);

                    using (var aes = Aes.Create())
                    {
                        aes.SetKey(tmpASpan);

                        // Decrypt package hash
                        aes.DecryptCbcNoPadding(
                            package.Slice(this._IvSize, HashSize),
                            tmpASpan);

                        // Decrypt (content + padding) directly into output.
                        aes.DecryptCbcNoPadding(
                            package.Slice(this._IvAndHashSize),
                            data,
                            package.Slice(this._IvAndHashSize - BlockSize, BlockSize));
                    }

                    HMACSHA256.HashData(tmpBSpan, data, tmpBSpan);

                    if (!CryptographicOperations.FixedTimeEquals(tmpASpan, tmpBSpan))
                    {
                        throw new BadPackageException();
                    }

                    int padLength = BlockPadding.GetPKCS7PaddingLength(BlockSize, data);

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
        /// The secret key used to protect the <paramref name="content"/>.
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
        /// The <paramref name="associatedData"/> parameter length is too large.
        /// </exception>
        public async Task<long> ProtectAsync(Stream content, Stream package, PackageKey key, ReadOnlyMemory<byte> associatedData = default, CancellationToken cancellationToken = default)
        {
            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }

            if (package == null)
            {
                throw new ArgumentNullException(nameof(package));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (associatedData.Length > this._MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var pool = ArrayPool<byte>.Shared;

            long totalOutputSize = 0L;

            var contentBuffer = new ArraySegment<byte>(pool.Rent(this._MaxPackageSize), 0, this._MaxContentSize);
            var packageBuffer = new ArraySegment<byte>(pool.Rent(this._MaxPackageSize), 0, this._MaxPackageSize);

            long packageNumber = 0L;

            int bytesRead;
            int lastPackageContentSize = this._MaxContentSize;

            try
            {
                do
                {
                    int offset = 0;

                    do
                    {
                        bytesRead = await content.ReadAsync(contentBuffer.Slice(offset, this._MaxContentSize - offset), cancellationToken).ConfigureAwait(false);

                        if (bytesRead == 0)
                        {
                            break;
                        }

                        offset += bytesRead;
                    }
                    while (offset < this._MaxContentSize);

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
                if (lastPackageContentSize == this._MaxContentSize)
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
        /// The secret key used to unprotect the <paramref name="package"/>.
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
        /// The <paramref name="associatedData"/> parameter length is too large.
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
            if (package == null)
            {
                throw new ArgumentNullException(nameof(package));
            }

            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (associatedData.Length > this._MaxAssociatedDataSize)
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData), "Associated data length is too large.");
            }

            var pool = ArrayPool<byte>.Shared;

            long totalOutputSize = 0L;

            var packageBuffer = new ArraySegment<byte>(pool.Rent(this._MaxPackageSize), 0, this._MaxPackageSize);
            var contentBuffer = new ArraySegment<byte>(pool.Rent(this._MaxPackageSize), 0, this._MaxPackageSize);

            long packageNumber = 0L;

            int bytesRead;
            int lastPackageContentSize = this._MaxContentSize;

            try
            {
                do
                {
                    int offset = 0;

                    do
                    {
                        bytesRead = await package.ReadAsync(packageBuffer.Slice(offset, this._MaxPackageSize - offset), cancellationToken).ConfigureAwait(false);

                        if (bytesRead == 0)
                        {
                            break;
                        }

                        offset += bytesRead;
                    }
                    while (offset < this._MaxPackageSize);

                    if (offset > 0)
                    {
                        if (lastPackageContentSize < this._MaxContentSize)
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

                if (lastPackageContentSize == this._MaxContentSize)
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
            return value < this._MinPackageSize || value > this._MaxPackageSize || IsNotAlignedBlock(value);
        }

        internal static void DeriveKeys(PackageKey packageKey, long packageNumber, int packageSize, ReadOnlySpan<byte> ivArg1, ReadOnlySpan<byte> ivArg2, Span<byte> encryptionKey, Span<byte> signingKey)
        {
            const byte SignPurpose = 0x00;
            const byte EncryptPurpose = 0xff;

            Span<byte> label = stackalloc byte[3];
            Span<byte> context = stackalloc byte[43];

            label[0] = EncryptPurpose;
            label[1] = (byte)ivArg1.Length;
            label[2] = (byte)ivArg2.Length;

            context[0] = (byte)(packageNumber >> 56);
            context[1] = (byte)(packageNumber >> 48);
            context[2] = (byte)(packageNumber >> 40);
            context[3] = (byte)(packageNumber >> 32);
            context[4] = (byte)(packageNumber >> 24);
            context[5] = (byte)(packageNumber >> 16);
            context[6] = (byte)(packageNumber >> 8);
            context[7] = (byte)packageNumber;

            var ivArgs = context.Slice(8, 32);

            ivArg1.CopyTo(ivArgs);

            ivArg2.CopyTo(ivArgs.Slice(ivArg1.Length));

            ivArgs.Slice(ivArg1.Length + ivArg2.Length).Clear();

            context[40] = (byte)(packageSize >> 16);
            context[41] = (byte)(packageSize >> 8);
            context[42] = (byte)packageSize;;

            packageKey.DeriveKey(label, context, encryptionKey);

            label[0] = SignPurpose;

            packageKey.DeriveKey(label, context, signingKey);
        }

        /// <summary>
        /// System default package protector implementation.
        /// </summary>
        private sealed class SystemPackageProtector : PackageProtector
        {
        }
    }
}