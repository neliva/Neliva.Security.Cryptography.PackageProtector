// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using System;

namespace Neliva.Security.Cryptography
{
    public delegate void RngFillAction(Span<byte> data);
}