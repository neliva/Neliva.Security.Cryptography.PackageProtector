// This is free and unencumbered software released into the public domain.
// See the UNLICENSE file in the project root for more information.

using Microsoft.VisualStudio.TestTools.UnitTesting;

[assembly: Parallelize(Workers = 0, Scope = ExecutionScope.MethodLevel)]