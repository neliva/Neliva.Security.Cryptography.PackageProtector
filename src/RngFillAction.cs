// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;

namespace Neliva.Security.Cryptography
{
    /// <summary>
    /// Encapsulates a method that fills a span with
    /// cryptographically strong random bytes.
    /// </summary>
    /// <param name="data">
    /// The span to fill with cryptographically strong random bytes.
    /// </param>
    public delegate void RngFillAction(Span<byte> data);
}