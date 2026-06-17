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

            using (var hmac = new HMACSHA512())
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

            using (var hmac = new HMACSHA512())
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

            using (var hmac = new HMACSHA512(masterKey))
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

            using (var hmac = new HMACSHA512())
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
            using var hmac = new HMACSHA512(new byte[32]);
            var derived = new byte[32];
            hmac.DeriveKey(derived, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);

            Assert.Contains(derived, b => b != 0);
        }

        [Fact]
        public void DeriveKeySHA512MultiBlockOutputPass()
        {
            // 65 bytes forces the counter loop to iterate (64 + 1).
            using var hmac = new HMACSHA512(new byte[32].Fill(7));
            var derived = new byte[65];
            hmac.DeriveKey(derived, new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 });

            Assert.Contains(derived, b => b != 0);
        }

        // Verifies the byte-exact output against an independent reference
        // implementation of the SP800-108 counter mode KDF using HMAC-SHA512.
        // Covers single and multi block output, truncated final blocks (lengths not
        // a multiple of the 64 byte hash size), empty label/context, and the
        // ArrayPool rented buffer path (large label/context exceeding the 320 byte
        // stackalloc threshold).
        [Theory]
        [InlineData("SHA512", 1, 5, 20)]
        [InlineData("SHA512", 63, 5, 20)]
        [InlineData("SHA512", 64, 0, 0)]
        [InlineData("SHA512", 65, 5, 20)]
        [InlineData("SHA512", 128, 5, 20)]
        [InlineData("SHA512", 129, 5, 20)]
        [InlineData("SHA512", 96, 300, 300)] // rented buffer path
        [InlineData("SHA512", 200, 0, 512)]  // rented buffer path
        [InlineData("SHA512", 100, 400, 0)]  // rented buffer path
        public void DeriveKeyMatchesReferencePass(string algName, int derivedKeyLength, int labelLength, int contextLength)
        {
            var masterKey = new byte[40].Fill(11);
            var label = new byte[labelLength].Fill(55);
            var context = new byte[contextLength].Fill(88);

            var derivedKey = new byte[derivedKeyLength];

            using (var hmac = CreateHmac(algName, masterKey))
            {
                hmac.DeriveKey(derivedKey, label, context);
            }

            var expected = ComputeReference(algName, masterKey, derivedKeyLength, label, context);

            Assert.Equal(expected, derivedKey);
        }

        [Fact]
        public void DeriveKeyIsDeterministicPass()
        {
            var masterKey = new byte[32].Fill(3);
            var label = new byte[] { 1, 2, 3 };
            var context = new byte[] { 4, 5, 6 };

            var first = new byte[80];
            var second = new byte[80];

            using (var hmac = new HMACSHA512(masterKey))
            {
                hmac.DeriveKey(first, label, context);
            }

            using (var hmac = new HMACSHA512(masterKey))
            {
                hmac.DeriveKey(second, label, context);
            }

            Assert.Equal(first, second);
        }

        [Fact]
        public void DeriveKeyOutputBoundToRequestedLengthPass()
        {
            // The requested key length is encoded (in bits) into the KDF input, so
            // the first hashSize bytes of a short derivation must differ from the
            // first hashSize bytes of a longer derivation with identical inputs.
            var masterKey = new byte[32].Fill(9);
            var label = new byte[] { 1, 2, 3 };
            var context = new byte[] { 4, 5, 6 };

            var shortKey = new byte[32];
            var longKey = new byte[64];

            using (var hmac = new HMACSHA512(masterKey))
            {
                hmac.DeriveKey(shortKey, label, context);
            }

            using (var hmac = new HMACSHA512(masterKey))
            {
                hmac.DeriveKey(longKey, label, context);
            }

            Assert.NotEqual(shortKey, longKey.AsSpan(0, 32).ToArray());
        }

        [Fact]
        public void DeriveKeyLabelContextBoundaryProducesDistinctKeysPass()
        {
            // The 0x00 separator between label and context must make the boundary
            // unambiguous, so distributing the same bytes differently across label
            // and context must yield distinct keys.
            var masterKey = new byte[32].Fill(13);

            byte[] Derive(byte[] label, byte[] context)
            {
                var key = new byte[32];

                using var hmac = new HMACSHA512(masterKey);

                hmac.DeriveKey(key, label, context);

                return key;
            }

            var ab_empty = Derive(new byte[] { 0x41, 0x42 }, Array.Empty<byte>());
            var a_b = Derive(new byte[] { 0x41 }, new byte[] { 0x42 });
            var empty_ab = Derive(Array.Empty<byte>(), new byte[] { 0x41, 0x42 });
            var a_empty = Derive(new byte[] { 0x41 }, Array.Empty<byte>());
            var empty_a = Derive(Array.Empty<byte>(), new byte[] { 0x41 });

            var keys = new[] { ab_empty, a_b, empty_ab, a_empty, empty_a };

            for (int i = 0; i < keys.Length; i++)
            {
                for (int j = i + 1; j < keys.Length; j++)
                {
                    Assert.NotEqual(keys[i], keys[j]);
                }
            }
        }

        // Verifies byte-exact compatibility with the .NET built-in SP800-108
        // counter mode KDF (SP800108HmacCounterKdf). Both must produce identical
        // output for identical key/label/context/length using HMAC-SHA512, across
        // single and multi block output, truncated final blocks, empty label/context,
        // and the ArrayPool rented buffer path (large label/context).
        [Theory]
        [InlineData("SHA512", 1, 0, 0)]
        [InlineData("SHA512", 63, 5, 20)]
        [InlineData("SHA512", 64, 5, 20)]
        [InlineData("SHA512", 65, 5, 20)]
        [InlineData("SHA512", 128, 5, 20)]
        [InlineData("SHA512", 129, 5, 20)]
        [InlineData("SHA512", 96, 300, 300)] // rented buffer path
        [InlineData("SHA512", 200, 0, 512)]  // rented buffer path
        [InlineData("SHA512", 300, 0, 500)]  // rented buffer path
        public void DeriveKeyMatchesBuiltInSP800108Pass(string algName, int derivedKeyLength, int labelLength, int contextLength)
        {
            var masterKey = new byte[40].Fill(11);
            var label = new byte[labelLength].Fill(55);
            var context = new byte[contextLength].Fill(88);

            var derivedKey = new byte[derivedKeyLength];

            using (var hmac = CreateHmac(algName, masterKey))
            {
                hmac.DeriveKey(derivedKey, label, context);
            }

            var expected = SP800108HmacCounterKdf.DeriveBytes(masterKey, HashName(algName), label, context, derivedKeyLength);

            Assert.Equal(expected, derivedKey);
        }

        private static HashAlgorithmName HashName(string algName)
        {
            return algName switch
            {
                "SHA512" => HashAlgorithmName.SHA512,
                _ => throw new ArgumentOutOfRangeException(nameof(algName)),
            };
        }

        private static KeyedHashAlgorithm CreateHmac(string algName, byte[] key)
        {
            return algName switch
            {
                "SHA512" => new HMACSHA512(key),
                _ => throw new ArgumentOutOfRangeException(nameof(algName)),
            };
        }

        // Independent SP800-108 counter mode KDF used as a test oracle. The
        // construction is validated against the published aspnet test vectors in
        // DeriveKeyPass / DeriveKeyWithLongMasterKeyPass.
        private static byte[] ComputeReference(string algName, byte[] key, int derivedKeyLength, byte[] label, byte[] context)
        {
            int hashSize;

            using (var probe = CreateHmac(algName, key))
            {
                hashSize = probe.HashSize / 8;
            }

            int inputSize = sizeof(uint) + label.Length + 1 + context.Length + sizeof(uint);

            var input = new byte[inputSize];

            Buffer.BlockCopy(label, 0, input, sizeof(uint), label.Length);
            input[sizeof(uint) + label.Length] = 0x00;
            Buffer.BlockCopy(context, 0, input, sizeof(uint) + label.Length + 1, context.Length);

            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(inputSize - sizeof(uint)), (uint)derivedKeyLength * 8u);

            var result = new byte[derivedKeyLength];

            int offset = 0;

            using var alg = CreateHmac(algName, key);

            for (uint counter = 1; offset < derivedKeyLength; counter++)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(input, counter);

                var hash = alg.ComputeHash(input);

                int take = Math.Min(hashSize, derivedKeyLength - offset);

                Buffer.BlockCopy(hash, 0, result, offset, take);

                offset += take;
            }

            return result;
        }
    }
}
