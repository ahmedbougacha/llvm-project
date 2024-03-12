//===--- StableHash.h - An ABI-stable string hash ---------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// The interface to an ABI-stable string hash algorithm.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ADT_STABLEHASH_H
#define LLVM_ADT_STABLEHASH_H

#include <cstdint>

namespace llvm {
class StringRef;

/// Compute a stable 64-bit hash of the given string.
///
/// The exact algorithm is the little-endian interpretation of the
/// non-doubled (i.e. 64-bit) result of applying a SipHash-2-4 using
/// a specific key value which can be found in the source.
///
/// By "stable" we mean that the result of this hash algorithm will
/// the same across different compiler versions and target platforms.
uint64_t getStableStringHash(StringRef S);

/// Compute a pointer-auth extra discriminator for the given string,
/// suitable for various uses specified in the target ABI.
///
/// The result of this hash will be the same across different compiler
/// versions but may vary between targets due to differences in the
/// range of discriminators desired by the target.
uint64_t getPointerAuthStringDiscriminator(StringRef S);

} // end namespace llvm

#endif
