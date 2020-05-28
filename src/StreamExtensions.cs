// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Provides extension methods to protect and unprotect streams using
    /// the underlying <see cref="PackageProtector"/> algorithm.
    /// </summary>
    public static class StreamExtensions
    {
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
        /// <param name="packageSize">
        /// The package size in bytes, which must match the value
        /// provided during unprotection.</param>
        /// <param name="associatedData">
        /// Extra data associated with the <paramref name="content"/>, which must match the value
        /// provided during unprotection.
        /// </param>
        /// <param name="cancellationToken"></param>
        /// <returns>
        /// The number of bytes written to the <paramref name="package"/> destination.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="content"/>, <paramref name="package"/>, or <paramref name="key"/>
        /// parameter is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="key"/> length is less than 32 bytes or greater than 64 bytes.
        /// - or -
        /// The <paramref name="packageSize"/> parameter is less than <c>64 bytes</c>,
        /// or greater than <c>16MiB - 16 bytes</c>, or not a multiple of <c>16 bytes</c>.
        /// - or -
        /// The <paramref name="associatedData"/> parameter length is greater than <c>16 bytes</c>.
        /// </exception>
        public static async Task<long> ProtectAsync(this Stream content, Stream package, byte[] key, int packageSize = 64 * 1024, ArraySegment<byte> associatedData = default, CancellationToken cancellationToken = default)
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

            if (PackageProtector.IsInvalidKeySize(key))
            {
                throw new ArgumentOutOfRangeException(nameof(key));
            }

            if (PackageProtector.IsInvalidPackageSize(packageSize))
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize));
            }

            if (PackageProtector.IsInvalidAssociatedData(associatedData))
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData));
            }

            var pool = ArrayPool<byte>.Shared;            

            int maxContentSize = packageSize - PackageProtector.Overhead;
            long totalOutputSize = 0L;

            var contentBuffer = new ArraySegment<byte>(pool.Rent(packageSize), 0, maxContentSize);
            var packageBuffer = new ArraySegment<byte>(pool.Rent(packageSize), 0, packageSize);

            long packageNumber = 0L;

            int bytesRead;
            int lastPackageContentSize = maxContentSize;

            try
            {
                do
                {
                    int offset = 0;

                    do
                    {
                        bytesRead = await content.ReadAsync(contentBuffer.Slice(offset, maxContentSize - offset), cancellationToken).ConfigureAwait(false);

                        if (bytesRead == 0)
                        {
                            break;
                        }

                        offset += bytesRead;
                    }
                    while (offset < maxContentSize);

                    if (offset > 0)
                    {
                        int bytesProtected = PackageProtector.Protect(contentBuffer.Slice(0, offset), packageBuffer, key, packageNumber, packageSize, associatedData);

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
                if (lastPackageContentSize == maxContentSize)
                {
                    int bytesProtected = PackageProtector.Protect(default, packageBuffer, key, packageNumber, packageSize, associatedData);

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
        /// <param name="packageSize">
        /// The package size in bytes, which must match the value
        /// provided during protection.
        /// </param>
        /// <param name="associatedData">
        /// Extra data associated with the <paramref name="package"/>, which must match the value
        /// provided during protection.
        /// </param>
        /// <param name="cancellationToken"></param>
        /// <returns>
        /// The number of bytes written to the <paramref name="content"/> destination.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="package"/>, <paramref name="content"/>, or <paramref name="key"/>
        /// parameter is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="key"/> length is less than 32 bytes or greater than 64 bytes.
        /// - or -
        /// The <paramref name="packageSize"/> parameter is less than <c>64 bytes</c>,
        /// or greater than <c>16MiB - 16 bytes</c>, or not a multiple of <c>16 bytes</c>.
        /// - or -
        /// The <paramref name="associatedData"/> parameter length is greater than <c>16 bytes</c>.
        /// </exception>
        /// <exception cref="InvalidDataException">
        /// Unexpected data after end of stream marker.
        /// - or -
        /// Unexpected stream length. Stream is truncated or corrupted.
        /// - or -
        /// Unexpected end of stream. Stream is truncated or corrupted.
        /// </exception>
        /// <exception cref="BadPackageException">
        /// Package is invalid or corrupted.
        /// - or -
        /// The <paramref name="key"/>, <paramref name="packageSize"/>,
        /// or <paramref name="associatedData"/> parameter is not valid.
        /// </exception>
        public static async Task<long> UnprotectAsync(this Stream package, Stream content, byte[] key, int packageSize = 64 * 1024, ArraySegment<byte> associatedData = default, CancellationToken cancellationToken = default)
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

            if (PackageProtector.IsInvalidKeySize(key))
            {
                throw new ArgumentOutOfRangeException(nameof(key));
            }

            if (PackageProtector.IsInvalidPackageSize(packageSize))
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize));
            }

            if (PackageProtector.IsInvalidAssociatedData(associatedData))
            {
                throw new ArgumentOutOfRangeException(nameof(associatedData));
            }

            var pool = ArrayPool<byte>.Shared;

            int maxContentSize = packageSize - PackageProtector.Overhead;
            long totalOutputSize = 0L;

            var packageBuffer = new ArraySegment<byte>(pool.Rent(packageSize), 0, packageSize);
            var contentBuffer = new ArraySegment<byte>(pool.Rent(packageSize), 0, packageSize);

            long packageNumber = 0L;

            int bytesRead;
            int lastPackageContentSize = maxContentSize;

            try
            {
                do
                {
                    int offset = 0;

                    do
                    {
                        bytesRead = await package.ReadAsync(packageBuffer.Slice(offset, packageSize - offset), cancellationToken).ConfigureAwait(false);

                        if (bytesRead == 0)
                        {
                            break;
                        }

                        offset += bytesRead;
                    }
                    while (offset < packageSize);

                    if (offset > 0)
                    {
                        if (lastPackageContentSize < maxContentSize)
                        {
                            // No more packages are allowed once
                            // 'end of stream' is detected.
                            throw new InvalidDataException("Unexpected data after end of stream marker.");
                        }

                        if (PackageProtector.IsInvalidPackageSize(offset))
                        {
                            throw new InvalidDataException($"Unexpected stream length. Stream is truncated or corrupted.");
                        }

                        int bytesUnprotected = PackageProtector.Unprotect(packageBuffer.Slice(0, offset), contentBuffer, key, packageNumber, packageSize, associatedData);

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

                if (lastPackageContentSize == maxContentSize)
                {
                    // Stream must always have 'end of stream' marker which
                    // is an empty package, or not fully populated package.
                    throw new InvalidDataException("Unexpected end of stream. Stream is truncated or corrupted.");
                }
            }
            finally
            {
                pool.Return(contentBuffer.Array, true);
                pool.Return(packageBuffer.Array);
            }

            return totalOutputSize;
        }
    }
}