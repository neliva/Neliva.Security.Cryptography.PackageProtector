// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Neliva.Security.Cryptography.Tests
{
    [ExcludeFromCodeCoverage]
    public class KeyedHashAlgorithmExtensionsTests
    {
        [Fact]
        public void NullHmacFail()
        {
            var keyOut = new byte[32];

            var ex = Assert.Throws<ArgumentNullException>(() => KeyedHashAlgorithmExtensions.DeriveKey(null, keyOut, Span<byte>.Empty, Span<byte>.Empty));

            Assert.Equal("alg", ex.ParamName);
        }

        [Fact]
        public void EmptyDerivedKeyFail()
        {
            var keyOut = new byte[0];

            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.Throws<ArgumentOutOfRangeException>(() => KeyedHashAlgorithmExtensions.DeriveKey(hmac, keyOut, Span<byte>.Empty, Span<byte>.Empty));

                Assert.Equal("derivedKey", ex.ParamName);

                Assert.Equal("The derived key length is zero or too large. (Parameter 'derivedKey')", ex.Message);
            }
        }

        [Theory]
        [InlineData(int.MaxValue, int.MaxValue)]
        [InlineData(0, int.MaxValue)]
        [InlineData(int.MaxValue, 0)]
        [InlineData(0, 2147483638 + 1)]
        [InlineData(2147483638 + 1, 0)]
        [InlineData(1, 2147483638)]
        [InlineData(2147483638, 1)]
        [InlineData(1073741819 + 1, 1073741819)]
        [InlineData(1073741819, 1073741819 + 1)]
        public unsafe void BadLabelOrContextLengthFail(int labelLength, int contextLength)
        {
            var keyOut = new byte[16];

            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.Throws<ArgumentException>(() => KeyedHashAlgorithmExtensions.DeriveKey(hmac, keyOut, new ReadOnlySpan<byte>((void*)0, labelLength), new ReadOnlySpan<byte>((void*)0, contextLength)));

                Assert.Null(ex.ParamName);

                Assert.Equal("The combined length of 'label' and 'context' is too large.", ex.Message);
            }
        }

        [Theory]
        [InlineData(1, 1)]
        [InlineData(311, 0)]
        [InlineData(0, 311)]
        [InlineData(311, 1)]
        [InlineData(1, 311)]
        public void LabelOrContextVariousLengthPass(int labelLength, int contextLength)
        {
            var masterKey = new byte[32].Fill(11);

            var label = new byte[labelLength].Fill(55);

            var context = new byte[contextLength].Fill(88);

            var derivedKey = new byte[32];

            using (var hmac = new HMACSHA256(masterKey))
            {
                KeyedHashAlgorithmExtensions.DeriveKey(hmac, derivedKey, label, context);
            }
        }

        [Theory]
        [InlineData(int.MaxValue)]
        [InlineData(0)]
        [InlineData(int.MaxValue / 4 + 1)]
        public unsafe void BadDerivedKeyLengthFail(int derivedKeyLength)
        {
            var keyOut = new byte[16];

            using (var hmac = new HMACSHA256())
            {
                var ex = Assert.Throws<ArgumentOutOfRangeException>(() => KeyedHashAlgorithmExtensions.DeriveKey(hmac, new Span<byte>((void*)0, derivedKeyLength), Span<byte>.Empty, Span<byte>.Empty));

                Assert.Equal("derivedKey", ex.ParamName);

                Assert.Equal("The derived key length is zero or too large. (Parameter 'derivedKey')", ex.Message);
            }
        }

        // Test vectors taken from https://github.com/aspnet/DataProtection/blob/release/2.0/test/Microsoft.AspNetCore.DataProtection.Test/SP800_108/SP800_108Tests.cs
        [Theory]
        [InlineData(512 / 8 - 1, "V47WmHzPSkdC2vkLAomIjCzZlDOAetll3yJLcSvon7LJFjJpEN+KnSNp+gIpeydKMsENkflbrIZ/3s6GkEaH")]
        [InlineData(512 / 8 + 0, "mVaFM4deXLl610CmnCteNzxgbM/VkmKznAlPauHcDBn0le06uOjAKLHx0LfoU2/Ttq9nd78Y6Nk6wArmdwJgJg==")]
        [InlineData(512 / 8 + 1, "GaHPeqdUxriFpjRtkYQYWr5/iqneD/+hPhVJQt4rXblxSpB1UUqGqL00DMU/FJkX0iMCfqUjQXtXyfks+p++Ev4=")]
        public void DeriveKeyPass(int derivedKeyLength, string expectedDerivedKey)
        {
            byte[] derivedKey = new byte[derivedKeyLength];

            byte[] masterKey = Encoding.UTF8.GetBytes("kdk");

            byte[] label = Encoding.UTF8.GetBytes("label");
            byte[] context = Encoding.UTF8.GetBytes("contextHeadercontext");

            using (var hmac = new HMACSHA512(masterKey))
            {
                hmac.DeriveKey(derivedKey, label, context);
            }

            string actual = Convert.ToBase64String(derivedKey);

            Assert.Equal(expectedDerivedKey, actual);
        }

        // Test vectors taken from https://github.com/aspnet/DataProtection/blob/release/2.0/test/Microsoft.AspNetCore.DataProtection.Test/SP800_108/SP800_108Tests.cs
        [Theory]
        [InlineData(512 / 8 - 1, "rt2hM6kkQ8hAXmkHx0TU4o3Q+S7fie6b3S1LAq107k++P9v8uSYA2G+WX3pJf9ZkpYrTKD7WUIoLkgA1R9lk")]
        [InlineData(512 / 8 + 0, "RKiXmHSrWq5gkiRSyNZWNJrMR0jDyYHJMt9odOayRAE5wLSX2caINpQmfzTH7voJQi3tbn5MmD//dcspghfBiw==")]
        [InlineData(512 / 8 + 1, "KedXO0zAIZ3AfnPqY1NnXxpC3HDHIxefG4bwD3g6nWYEc5+q7pjbam71Yqj0zgHMNC9Z7BX3wS1/tajFocRWZUk=")]
        public void DeriveKeyWithLongMasterKeyPass(int derivedKeyLength, string expectedDerivedKey)
        {
            byte[] derivedKey = new byte[derivedKeyLength];

            byte[] masterKey = new byte[50000];

            for (int i = 0; i < masterKey.Length; i++)
            {
                masterKey[i] = (byte)i;
            }

            byte[] label = Encoding.UTF8.GetBytes("label");
            byte[] context = Encoding.UTF8.GetBytes("contextHeadercontext");

            using (var hmac = new HMACSHA512(masterKey))
            {
                hmac.DeriveKey(derivedKey, label, context);
            }

            string actual = Convert.ToBase64String(derivedKey);

            Assert.Equal(expectedDerivedKey, actual);
        }

        [Fact]
        public void DeriveKeyEmptyLabelAndContextPass()
        {
            using var hmac = new HMACSHA256(new byte[32]);
            var derived = new byte[32];
            hmac.DeriveKey(derived, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);

            Assert.Contains(derived, b => b != 0);
        }

        [Fact]
        public void DeriveKeySHA256MultiBlockOutputPass()
        {
            // 65 bytes forces the counter loop to iterate (32 + 32 + 1).
            using var hmac = new HMACSHA256(new byte[32].Fill(7));
            var derived = new byte[65];
            hmac.DeriveKey(derived, new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });

            Assert.Contains(derived, b => b != 0);
        }
    }
}
