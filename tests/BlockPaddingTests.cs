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

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(4, default));
            Assert.Equal("buffer", ex.ParamName);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(4, Span<byte>.Empty));
            Assert.Equal("buffer", ex.ParamName);


            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(-1, new byte[16]));
            Assert.Equal("blockSize", ex.ParamName);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(0, new byte[16]));
            Assert.Equal("blockSize", ex.ParamName);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(byte.MaxValue + 1, new byte[16]));
            Assert.Equal("blockSize", ex.ParamName);


            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(15, new byte[16]));
            Assert.Equal("buffer", ex.ParamName);
            Assert.Equal("Length is not a multiple of block size. (Parameter 'buffer')", ex.Message);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(17, new byte[32]));
            Assert.Equal("buffer", ex.ParamName);
            Assert.Equal("Length is not a multiple of block size. (Parameter 'buffer')", ex.Message);

            ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(16, new byte[15]));
            Assert.Equal("buffer", ex.ParamName);
            Assert.Equal("Length is not a multiple of block size. (Parameter 'buffer')", ex.Message);
        }

        [Fact]
        public void PKCS7PaddingLengthValidBlockPass()
        {
            for (byte i = 1; i < 16; i++)
            {
                const int blockSize = 16;
                Assert.Equal(i, BlockPadding.GetPKCS7PaddingLength(blockSize, CreateBlock(blockSize, i)));
            }

            for (byte i = 1; i < 16; i++)
            {
                const int blockSize = 16;
                Assert.Equal(i, BlockPadding.GetPKCS7PaddingLength(blockSize, CreateBlock(blockSize * 2, i)));
            }

            for (byte i = 1; i < byte.MaxValue; i++)
            {
                const int blockSize = 255;
                Assert.Equal(i, BlockPadding.GetPKCS7PaddingLength(blockSize, CreateBlock(blockSize, i)));
            }
        }

        [Fact]
        public void PKCS7PaddingInvalidBlockFail()
        {
            const int blockSize16 = 16;

            for (byte i = 1; i < blockSize16; i++)
            {
                byte[] b = CreateBlock(blockSize16, i);
                b[blockSize16 - i] = (byte)(i + 17);

                Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(blockSize16, b));
            }

            const int blockSize255 = byte.MaxValue;

            for (byte i = 1; i < blockSize255; i++)
            {
                byte[] b = CreateBlock(blockSize255, i);
                b[blockSize255 - i] = (byte)(i - 1);

                Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(blockSize255, b));
            }
        }

        [Fact]
        public void PKCS7PaddingLastByteZeroFail()
        {
            byte[] buf = new byte[16];
            Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(16, buf));
        }

        [Fact]
        public void PKCS7PaddingPadLengthGreaterThanBlockSizeFail()
        {
            byte[] buf = new byte[16];
            for (int i = 0; i < buf.Length; i++) buf[i] = 17;
            Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(16, buf));
        }

        [Fact]
        public void PKCS7PaddingBlockSizeOnePass()
        {
            byte[] buf = new byte[] { 1 };
            Assert.Equal(1, BlockPadding.GetPKCS7PaddingLength(1, buf));
        }

        [Fact]
        public void PKCS7PaddingFullBlockPaddingPass()
        {
            byte[] buf = new byte[16];
            for (int i = 0; i < buf.Length; i++) buf[i] = 16;
            Assert.Equal(16, BlockPadding.GetPKCS7PaddingLength(16, buf));
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
                        byte[] b = CreateBlock(blockSize, (byte)padLength);

                        b[corruptIndex] = (byte)(padLength ^ (1 << bit));

                        Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(blockSize, b));
                    }
                }
            }
        }

        // Verifies that a declared padding length greater than the block size is
        // rejected for every block size, using multi block buffers large enough to
        // hold the oversized padding length up to the maximum byte value.
        [Fact]
        public void PKCS7PaddingFullRangeOversizedPadLengthFail()
        {
            for (int blockSize = 1; blockSize < byte.MaxValue; blockSize++)
            {
                for (int padLength = blockSize + 1; padLength <= byte.MaxValue; padLength++)
                {
                    int blocks = (padLength + blockSize - 1) / blockSize;
                    int bufferLength = blockSize * blocks;

                    byte[] b = CreateBuffer(bufferLength, (byte)padLength);

                    Assert.Equal(-1, BlockPadding.GetPKCS7PaddingLength(blockSize, b));
                }
            }
        }

        private static byte[] CreateBlock(int blockSize, byte padLength)
        {
            byte[] b = new byte[blockSize];

            for (int i = b.Length - 1; i >= 0; i--)
            {
                b[i] = padLength;
            }

            return b;
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
