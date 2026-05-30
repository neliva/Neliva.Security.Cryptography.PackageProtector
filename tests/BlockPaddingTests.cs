// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    public class BlockPaddingTests
    {
        [Fact]
        public void PKCS7PKCS7PaddingLengthBadArgumentFail()
        {
            ArgumentException ex;

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(4, null));
            Assert.Equal("buffer", ex.ParamName);
            Assert.Equal("Buffer is empty. (Parameter 'buffer')", ex.Message);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(4, default));
            Assert.Equal("buffer", ex.ParamName);
            Assert.Equal("Buffer is empty. (Parameter 'buffer')", ex.Message);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(4, Span<byte>.Empty));
            Assert.Equal("buffer", ex.ParamName);
            Assert.Equal("Buffer is empty. (Parameter 'buffer')", ex.Message);


            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(-1, new byte[16]));
            Assert.Equal("blockSize", ex.ParamName);
            Assert.Equal("Block size must be between 1 and 255. (Parameter 'blockSize')", ex.Message);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(0, new byte[16]));
            Assert.Equal("blockSize", ex.ParamName);
            Assert.Equal("Block size must be between 1 and 255. (Parameter 'blockSize')", ex.Message);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(byte.MaxValue + 1, new byte[16]));
            Assert.Equal("blockSize", ex.ParamName);
            Assert.Equal("Block size must be between 1 and 255. (Parameter 'blockSize')", ex.Message);


            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(15, new byte[16]));
            Assert.Equal("buffer", ex.ParamName);
            Assert.Equal("Buffer length is not a multiple of block size. (Parameter 'buffer')", ex.Message);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(17, new byte[32]));
            Assert.Equal("buffer", ex.ParamName);
            Assert.Equal("Buffer length is not a multiple of block size. (Parameter 'buffer')", ex.Message);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(16, new byte[15]));
            Assert.Equal("buffer", ex.ParamName);
            Assert.Equal("Buffer length is not a multiple of block size. (Parameter 'buffer')", ex.Message);

            // Inner boundaries of the valid blockSize range must not throw.
            Assert.Equal(1, BlockPadding.GetPKCS7PaddingLength(1, new byte[] { 1 }));
            Assert.Equal(byte.MaxValue, BlockPadding.GetPKCS7PaddingLength(byte.MaxValue, CreateBuffer(byte.MaxValue, byte.MaxValue)));
        }

        // Verifies that a zero declared padding length (last byte is zero) is
        // rejected for every block size from 1 to the maximum allowed, across single
        // and multi block buffers.
        [Fact]
        public void PKCS7PaddingFullRangeZeroPadLengthFail()
        {
            for (int blockSize = 1; blockSize <= byte.MaxValue; blockSize++)
            {
                for (int blocks = 1; blocks <= 3; blocks++)
                {
                    byte[] b = CreateBuffer(blockSize * blocks, 0);

                    Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(blockSize, b));
                }
            }
        }

        // Verifies that correctly formed PKCS7 padding is accepted and the padding
        // length is returned for every block size from 1 to the maximum allowed, for
        // every valid padding length, across single and multi block buffers.
        [Fact]
        public void PKCS7PaddingFullRangeValidPass()
        {
            for (int blockSize = 1; blockSize <= byte.MaxValue; blockSize++)
            {
                for (int padLength = 1; padLength <= blockSize; padLength++)
                {
                    for (int blocks = 1; blocks <= 3; blocks++)
                    {
                        byte[] b = CreateBuffer(blockSize * blocks, (byte)padLength);

                        Assert.Equal(padLength, BlockPadding.GetPKCS7PaddingLength(blockSize, b));
                    }
                }
            }
        }

        // Verifies that a single corrupted padding byte is rejected for every block
        // size from 1 to the maximum allowed, for every valid padding length, and for
        // every corrupted bit position within that byte.
        [Fact]
        public void PKCS7PaddingFullRangeCorruptedByteFail()
        {
            for (int blockSize = 1; blockSize <= byte.MaxValue; blockSize++)
            {
                for (int padLength = 2; padLength <= blockSize; padLength++)
                {
                    int corruptIndex = blockSize - padLength;

                    for (int bit = 0; bit < 8; bit++)
                    {
                        byte[] b = CreateBuffer(blockSize, (byte)padLength);

                        b[corruptIndex] = (byte)(padLength ^ (1 << bit));

                        Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(blockSize, b));
                    }
                }
            }
        }

        // Verifies that a declared padding length greater than the block size is
        // rejected for every block size, for both single block buffers and multi
        // block buffers large enough to hold the oversized padding length up to the
        // maximum byte value.
        [Fact]
        public void PKCS7PaddingFullRangeOversizedPadLengthFail()
        {
            for (int blockSize = 1; blockSize < byte.MaxValue; blockSize++)
            {
                for (int padLength = blockSize + 1; padLength <= byte.MaxValue; padLength++)
                {
                    byte[] single = CreateBuffer(blockSize, (byte)padLength);

                    Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(blockSize, single));

                    int blocks = (padLength + blockSize - 1) / blockSize;
                    byte[] multi = CreateBuffer(blockSize * blocks, (byte)padLength);

                    Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(blockSize, multi));
                }
            }
        }

        private static byte[] CreateBuffer(int length, byte value)
        {
            byte[] b = new byte[length];

            for (int i = 0; i < b.Length; i++)
            {
                b[i] = value;
            }

            return b;
        }
    }
}
