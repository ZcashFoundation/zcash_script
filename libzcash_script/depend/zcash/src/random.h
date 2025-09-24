// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_RANDOM_H
#define BITCOIN_RANDOM_H

#include "crypto/chacha20.h"
#include "crypto/common.h"
#include "uint256.h"

#include <functional>
#include <limits>

#include "int128.h"

/** @file
 * Functions to gather random data via the rand_core OsRng
 */

/** Fill the buffer buf of length num with random unformly distributed bytes, via the rand_core OsRng. */
void GetRandBytes(unsigned char* buf, size_t num);

/**
 * Return a random value of type I uniformly distributed on [0, nMax), unless nMax is 0 in which case return 0.
 * I must be an unsigned numeric type.
 */
template <typename I>
I GetRandGeneric(I nMax)
{
    static_assert(std::numeric_limits<I>::min() == 0);
    // I() for primitive integer types returns 0.
    if (nMax == I())
        return I();

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    I nRange = (std::numeric_limits<I>::max() / nMax) * nMax;
    I nRand = I();
    do {
        GetRandBytes((unsigned char*)&nRand, sizeof(nRand));
    } while (nRand >= nRange);
    return (nRand % nMax);
}

/** Return a random uint128_t uniformly distributed on [0, nMax), unless nMax is 0 in which case return 0. */
uint128_t GetRandUInt128(uint128_t nMax);
/** Return a random int128_t uniformly distributed on [0, nMax), unless nMax is 0 in which case return 0. nMax must be >= 0. */
int128_t GetRandInt128(int128_t nMax);
/** Return a random uint64_t uniformly distributed on [0, nMax), unless nMax is 0 in which case return 0. */
uint64_t GetRand(uint64_t nMax);
/** Return a random int64_t uniformly distributed on [0, nMax), unless nMax is 0 in which case return 0. nMax must be >= 0. */
int64_t GetRandInt64(int64_t nMax);
/** Return a random int uniformly distributed on [0, nMax), unless nMax is 0 in which case return 0. nMax must be >= 0. */
int GetRandInt(int nMax);
/** Return a random uniformly distributed uint256. */
uint256 GetRandHash();

/**
 * Implementation of a C++ Uniform Random Number Generator, backed by GetRandBytes.
 */
class ZcashRandomEngine
{
public:
    typedef uint64_t result_type;

    explicit ZcashRandomEngine() {}

    static constexpr result_type min() {
        return std::numeric_limits<result_type>::min();
    }
    static constexpr result_type max() {
        return std::numeric_limits<result_type>::max();
    }

    result_type operator()() {
        result_type nRand = 0;
        GetRandBytes((unsigned char*)&nRand, sizeof(nRand));
        return nRand;
    }

    double entropy() const noexcept {
        return 0;
    }
};

/**
 * Identity function for MappedShuffle, so that elements retain their original order.
 */
 int GenIdentity(int n);

/**
 * Rearranges the elements in the range [first,first+len) randomly, assuming
 * that gen is a uniform random number generator. Follows the same algorithm as
 * std::shuffle in C++11 (a Durstenfeld shuffle).
 *
 * The elements in the range [mapFirst,mapFirst+len) are rearranged according to
 * the same permutation, enabling the permutation to be tracked by the caller.
 *
 * gen takes an integer n and produces a uniform random output in [0,n).
 */
template <typename RandomAccessIterator, typename MapRandomAccessIterator>
void MappedShuffle(RandomAccessIterator first,
                   MapRandomAccessIterator mapFirst,
                   size_t len,
                   std::function<int(int)> gen)
{
    for (size_t i = len-1; i > 0; --i) {
        auto r = gen(i+1);
        assert(r >= 0);
        assert(r <= i);
        std::swap(first[i], first[r]);
        std::swap(mapFirst[i], mapFirst[r]);
    }
}

/**
 * Fast randomness source. This is seeded once with secure random data, but
 * is completely deterministic and insecure after that.
 * This class is not thread-safe.
 */
class FastRandomContext {
private:
    bool requires_seed;
    ChaCha20 rng;

    unsigned char bytebuf[64];
    int bytebuf_size;

    uint64_t bitbuf;
    int bitbuf_size;

    void RandomSeed();

    void FillByteBuffer()
    {
        if (requires_seed) {
            RandomSeed();
        }
        rng.Output(bytebuf, sizeof(bytebuf));
        bytebuf_size = sizeof(bytebuf);
    }

    void FillBitBuffer()
    {
        bitbuf = rand64();
        bitbuf_size = 64;
    }

public:
    explicit FastRandomContext(bool fDeterministic = false);

    /** Initialize with explicit seed (only for testing) */
    explicit FastRandomContext(const uint256& seed);

    /** Generate a random 64-bit integer. */
    uint64_t rand64()
    {
        if (bytebuf_size < 8) FillByteBuffer();
        uint64_t ret = ReadLE64(bytebuf + 64 - bytebuf_size);
        bytebuf_size -= 8;
        return ret;
    }

    /** Generate a random (bits)-bit integer. */
    uint64_t randbits(int bits) {
        if (bits == 0) {
            return 0;
        } else if (bits > 32) {
            return rand64() >> (64 - bits);
        } else {
            if (bitbuf_size < bits) FillBitBuffer();
            uint64_t ret = bitbuf & (~(uint64_t)0 >> (64 - bits));
            bitbuf >>= bits;
            bitbuf_size -= bits;
            return ret;
        }
    }

    /** Generate a random integer in the range [0..range). */
    uint64_t randrange(uint64_t range)
    {
        --range;
        int bits = CountBits(range);
        while (true) {
            uint64_t ret = randbits(bits);
            if (ret <= range) return ret;
        }
    }

    /** Generate random bytes. */
    std::vector<unsigned char> randbytes(size_t len);

    /** Generate a random 32-bit integer. */
    uint32_t rand32() { return randbits(32); }

    /** generate a random uint256. */
    uint256 rand256();

    /** Generate a random boolean. */
    bool randbool() { return randbits(1); }
};

#endif // BITCOIN_RANDOM_H
