// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Neliva.Security.Cryptography
{
    public static class StreamExtensions
    {
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

            if (PackageProtector.IsInvalidPackageSize(packageSize))
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize));
            }

            if (associatedData.Count > PackageProtector.BlockSize)
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
                        totalOutputSize += bytesProtected;
                        lastPackageContentSize = offset;
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

                    totalOutputSize += bytesProtected;
                }
            }
            finally
            {
                pool.Return(contentBuffer.Array, true);
                pool.Return(packageBuffer.Array);
            }

            return totalOutputSize;
        }

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

            if (PackageProtector.IsInvalidPackageSize(packageSize))
            {
                throw new ArgumentOutOfRangeException(nameof(packageSize));
            }

            if (associatedData.Count > PackageProtector.BlockSize)
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
                        totalOutputSize += bytesUnprotected;
                        lastPackageContentSize = bytesUnprotected;
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