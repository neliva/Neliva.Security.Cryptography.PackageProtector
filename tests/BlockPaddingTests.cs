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

        private static byte[] CreateBlock(int blockSize, byte padLength)
        {
            byte[] b = new byte[blockSize];

            for (int i = b.Length - 1; i >= 0; i--)
            {
                b[i] = padLength;
            }

            return b;
        }
    }
}
