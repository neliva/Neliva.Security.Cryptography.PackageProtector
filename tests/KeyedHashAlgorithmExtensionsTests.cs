// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    [TestClass]
    public class KeyedHashAlgorithmExtensionsTests
    {
        [TestMethod]
        public void NullHmacFail()
        {
            var keyOut = new byte[32];

            var ex = Assert.ThrowsException<ArgumentNullException>(() => KeyedHashAlgorithmExtensions.DeriveKey(null, Span<byte>.Empty, Span<byte>.Empty, keyOut));

            Assert.AreEqual("alg", ex.ParamName);
        }

        [TestMethod]
        public void EmptyDerivedKeyFail()
        {
            var keyOut = new byte[0];

            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => KeyedHashAlgorithmExtensions.DeriveKey(hmac, Span<byte>.Empty, Span<byte>.Empty, keyOut));

                Assert.AreEqual("derivedKey", ex.ParamName);

                Assert.AreEqual("The derived key length cannot be zero or exceed 536870911 bytes. (Parameter 'derivedKey')", ex.Message);
            }
        }

        [TestMethod]
        [DataRow(int.MaxValue, int.MaxValue)]
        [DataRow(0, int.MaxValue)]
        [DataRow(int.MaxValue, 0)]
        [DataRow(0, 2147483638 + 1)]
        [DataRow(2147483638 + 1, 0)]
        [DataRow(1, 2147483638)]
        [DataRow(2147483638, 1)]
        [DataRow(1073741819 + 1, 1073741819)]
        [DataRow(1073741819, 1073741819 + 1)]
        public unsafe void BadLabelOrContextLengthFail(int labelLength, int contextLength)
        {
            var keyOut = new byte[16];

            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.ThrowsException<ArgumentException>(() => KeyedHashAlgorithmExtensions.DeriveKey(hmac, new ReadOnlySpan<byte>((void*)0, labelLength), new ReadOnlySpan<byte>((void*)0, contextLength), keyOut));

                Assert.AreEqual(null, ex.ParamName);

                Assert.AreEqual("The combined length of 'label' and 'context' cannot exceed 2147483638 bytes.", ex.Message);
            }
        }

        [TestMethod]
        [DataRow(1, 1)]
        [DataRow(247, 0)]
        [DataRow(0, 247)]
        [DataRow(247, 1)]
        [DataRow(1, 247)]
        public void LabelOrContextVariousLengthPass(int labelLength, int contextLength)
        {
            var masterKey = new byte[32].Fill(11);

            var label = new byte[labelLength].Fill(55);

            var context = new byte[contextLength].Fill(88);

            var derivedKey = new byte[32];

            using (var hmac = new HMACSHA256(masterKey))
            {
                KeyedHashAlgorithmExtensions.DeriveKey(hmac, label, context, derivedKey);
            }
        }

        [TestMethod]
        [DataRow(int.MaxValue)]
        [DataRow(0)]
        [DataRow(int.MaxValue / 4 + 1)]
        public unsafe void BadDerivedKeyLengthFail(int derivedKeyLength)
        {
            var keyOut = new byte[16];

            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.ThrowsException<ArgumentOutOfRangeException>(() => KeyedHashAlgorithmExtensions.DeriveKey(hmac, Span<byte>.Empty, Span<byte>.Empty, new Span<byte>((void*)0, derivedKeyLength)));

                Assert.AreEqual("derivedKey", ex.ParamName);

                Assert.AreEqual("The derived key length cannot be zero or exceed 536870911 bytes. (Parameter 'derivedKey')", ex.Message);
            }
        }

        [TestMethod]
        [DataRow(512 / 8 - 1, "V47WmHzPSkdC2vkLAomIjCzZlDOAetll3yJLcSvon7LJFjJpEN+KnSNp+gIpeydKMsENkflbrIZ/3s6GkEaH")]
        [DataRow(512 / 8 + 0, "mVaFM4deXLl610CmnCteNzxgbM/VkmKznAlPauHcDBn0le06uOjAKLHx0LfoU2/Ttq9nd78Y6Nk6wArmdwJgJg==")]
        [DataRow(512 / 8 + 1, "GaHPeqdUxriFpjRtkYQYWr5/iqneD/+hPhVJQt4rXblxSpB1UUqGqL00DMU/FJkX0iMCfqUjQXtXyfks+p++Ev4=")]
        public void DeriveKeyPass(int derivedKeyLength, string expectedDerivedKey)
        {
            byte[] derivedKey = new byte[derivedKeyLength];

            byte[] kdk = Encoding.UTF8.GetBytes("kdk");
            byte[] label = Encoding.UTF8.GetBytes("label");
            byte[] context = Encoding.UTF8.GetBytes("contextHeadercontext");

            using (var hmac = new HMACSHA512(kdk))
            {
                hmac.DeriveKey(label, context, derivedKey);
            }

            string actual = Convert.ToBase64String(derivedKey);

            Assert.AreEqual(expectedDerivedKey, actual);
        }

        [TestMethod]
        [DataRow(512 / 8 - 1, "rt2hM6kkQ8hAXmkHx0TU4o3Q+S7fie6b3S1LAq107k++P9v8uSYA2G+WX3pJf9ZkpYrTKD7WUIoLkgA1R9lk")]
        [DataRow(512 / 8 + 0, "RKiXmHSrWq5gkiRSyNZWNJrMR0jDyYHJMt9odOayRAE5wLSX2caINpQmfzTH7voJQi3tbn5MmD//dcspghfBiw==")]
        [DataRow(512 / 8 + 1, "KedXO0zAIZ3AfnPqY1NnXxpC3HDHIxefG4bwD3g6nWYEc5+q7pjbam71Yqj0zgHMNC9Z7BX3wS1/tajFocRWZUk=")]
        public void DeriveKeyWithLongMasterKeyPass(int derivedKeyLength, string expectedDerivedKey)
        {
            byte[] derivedKey = new byte[derivedKeyLength];

            byte[] kdk = new byte[50000];

            for (int i = 0; i < kdk.Length; i++)
            {
                kdk[i] = (byte)i;
            }

            byte[] label = Encoding.UTF8.GetBytes("label");
            byte[] context = Encoding.UTF8.GetBytes("contextHeadercontext");

            using (var hmac = new HMACSHA512(kdk))
            {
                hmac.DeriveKey(label, context, derivedKey);
            }

            string actual = Convert.ToBase64String(derivedKey);

            Assert.AreEqual(expectedDerivedKey, actual);
        }

    }
}