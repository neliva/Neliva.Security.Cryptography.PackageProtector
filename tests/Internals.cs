// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Reflection;

namespace Neliva.Security.Cryptography.Tests
{
    /// <summary>
    /// Bridges to internal production members so they can be exercised by tests
    /// without the production assembly exposing them through
    /// <see cref="System.Runtime.CompilerServices.InternalsVisibleToAttribute"/>.
    /// </summary>
    /// <remarks>
    /// The target methods accept <see cref="Span{T}"/> / <see cref="ReadOnlySpan{T}"/>
    /// parameters. Such ref struct values cannot be boxed, so
    /// <see cref="MethodBase.Invoke(object, object[])"/> cannot be used. Each method
    /// is instead located via reflection and bound to a strongly typed delegate,
    /// which supports ref struct parameters and propagates exceptions directly
    /// (without wrapping them in a <see cref="TargetInvocationException"/>).
    /// </remarks>
    internal static class Internals
    {
        private delegate int GetPKCS7PaddingLengthDelegate(int blockSize, ReadOnlySpan<byte> data);

        private delegate void DeriveKeysDelegate(PackageKey packageKey, long packageNumber, int packageSize, ReadOnlySpan<byte> ivArg1, ReadOnlySpan<byte> ivArg2, Span<byte> encryptionKey, Span<byte> signingKey);

        private static readonly GetPKCS7PaddingLengthDelegate GetPKCS7PaddingLengthImpl =
            typeof(PackageProtector).Assembly
                .GetType("Neliva.Security.Cryptography.Package", throwOnError: true)!
                .GetMethod("GetPKCS7PaddingLength", BindingFlags.Public | BindingFlags.Static)!
                .CreateDelegate<GetPKCS7PaddingLengthDelegate>();

        private static readonly DeriveKeysDelegate DeriveKeysImpl =
            typeof(PackageProtector)
                .GetMethod("DeriveKeys", BindingFlags.NonPublic | BindingFlags.Static)!
                .CreateDelegate<DeriveKeysDelegate>();

        /// <summary>
        /// Invokes the internal <c>Package.GetPKCS7PaddingLength</c> method.
        /// </summary>
        public static int GetPKCS7PaddingLength(int blockSize, ReadOnlySpan<byte> data)
        {
            return GetPKCS7PaddingLengthImpl(blockSize, data);
        }

        /// <summary>
        /// Invokes the internal <c>PackageProtector.DeriveKeys</c> method.
        /// </summary>
        public static void DeriveKeys(PackageKey packageKey, long packageNumber, int packageSize, ReadOnlySpan<byte> ivArg1, ReadOnlySpan<byte> ivArg2, Span<byte> encryptionKey, Span<byte> signingKey)
        {
            DeriveKeysImpl(packageKey, packageNumber, packageSize, ivArg1, ivArg2, encryptionKey, signingKey);
        }
    }
}
