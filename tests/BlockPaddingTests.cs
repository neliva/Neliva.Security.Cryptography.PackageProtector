// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverageAttribute]
    [TestClass]
    public class BlockPaddingTests
    {
        [TestMethod]
        public void PKCS7PKCS7PaddingLengthBadArgumentFail()
        {
            ArgumentException ex;

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(null, 4));
            Assert.AreEqual<string>("buffer", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(default, 4));
            Assert.AreEqual<string>("buffer", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(Span<byte>.Empty, 4));
            Assert.AreEqual<string>("buffer", ex.ParamName);


            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(new byte[16], -1));
            Assert.AreEqual<string>("blockSize", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(new byte[16], 0));
            Assert.AreEqual<string>("blockSize", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => BlockPadding.GetPKCS7PaddingLength(new byte[16], byte.MaxValue + 1));
            Assert.AreEqual<string>("blockSize", ex.ParamName);


            ex = Assert.ThrowsException<ArgumentException>(() => BlockPadding.GetPKCS7PaddingLength(new byte[16], 15));
            Assert.AreEqual<string>("buffer", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentException>(() => BlockPadding.GetPKCS7PaddingLength(new byte[32], 17));
            Assert.AreEqual<string>("buffer", ex.ParamName);

            ex = Assert.ThrowsException<ArgumentException>(() => BlockPadding.GetPKCS7PaddingLength(new byte[15], 16));
            Assert.AreEqual<string>("buffer", ex.ParamName);
        }

        [TestMethod]
        public void PKCS7PaddingLengthValidBlockPass()
        {
            for (byte i = 1; i < 16; i++)
            {
                const int blockSize = 16;
                Assert.AreEqual(i, BlockPadding.GetPKCS7PaddingLength(CreateBlock(blockSize, i), blockSize));
            }

            for (byte i = 1; i < 16; i++)
            {
                const int blockSize = 16;
                Assert.AreEqual(i, BlockPadding.GetPKCS7PaddingLength(CreateBlock(blockSize * 2, i), blockSize));
            }

            for (byte i = 1; i < byte.MaxValue; i++)
            {
                const int blockSize = 255;
                Assert.AreEqual(i, BlockPadding.GetPKCS7PaddingLength(CreateBlock(blockSize, i), blockSize));
            }
        }

        [TestMethod]
        public void PKCS7PaddingInvalidBlockFail()
        {
            const int blockSize16 = 16;

            for (byte i = 1; i < blockSize16; i++)
            {
                byte[] b = CreateBlock(blockSize16, i);
                b[blockSize16 - i] = (byte)(i + 17);

                Assert.AreEqual<int>(-1, BlockPadding.GetPKCS7PaddingLength(b, blockSize16));
            }

            const int blockSize255 = byte.MaxValue;

            for (byte i = 1; i < blockSize255; i++)
            {
                byte[] b = CreateBlock(blockSize255, i);
                b[blockSize255 - i] = (byte)(i - 1);

                Assert.AreEqual<int>(-1, BlockPadding.GetPKCS7PaddingLength(b, blockSize255));
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