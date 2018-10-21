// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "crypto/equihash.h"
#include "primitives/block.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    int nHeight = pindexLast->nHeight + 1;

    // Original Bitcion PoW.
    if (nHeight < params.BCRMHeight)
        return BitcoinGetNextWorkRequired(pindexLast, pblock, params);

    // PoW limit for premine period. (min-difficulty)
    if (nHeight < params.BCRMHeightRegular)
        return UintToArith256(params.PowLimit(true)).GetCompact();

    // Pow limit start for warm-up period.
    if (nHeight < params.BCRMHeightRegular + params.nZawyLwmaAveragingWindow)
        return UintToArith256(params.powLimitStart).GetCompact();

    // For TEST net:
    // If the new block's timestamp is more than 20 * nPowTargetSpacing, allow mining a min-difficulty block.
    // Because our avg block time is 60s, this should not even be triggered
    if (params.fPowAllowMinDifficultyBlocks && pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 20)
        return UintToArith256(params.PowLimit(true)).GetCompact();

    // Zawy's LWMA.
    return CalculateNextWorkRequired(pindexLast, params);
}

// (C) Copyright Zawy's LWMA2 algorithm
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
      return pindexLast->nBits;

    const int height = pindexLast->nHeight + 1;
    const int64_t FTL = params.BCRMMaxFutureBlockTime;  // Set to 5 * T in chainparams.cpp
    const int64_t T = params.nPowTargetSpacing;
    const int N = params.nZawyLwmaAveragingWindow;
    const int k = params.nZawyLwmaAdjustedWeight;
    const int dnorm = params.nZawyLwmaMinDenominator;
    const bool limit_st = params.fZawyLwmaSolvetimeLimitation;
    assert(height > N);

    arith_uint256 sum_target;
    int t = 0, j = 0;
    int64_t sum_3_st = 0;

    // Loop through N most recent blocks.
    for (int i = height - N; i < height; i++) {
        const CBlockIndex* block = pindexLast->GetAncestor(i);
        const CBlockIndex* block_Prev = block->GetAncestor(i - 1);
        int64_t solvetime = block->GetBlockTime() - block_Prev->GetBlockTime();

        if (limit_st) {
          if (solvetime > 6*T)
            solvetime = 6*T;
          else if (solvetime < -FTL)
            solvetime = -FTL;
        }

        j++;
        t += solvetime * j;  // Weighted solvetime sum.

        // Sum of last three solve times
        if (i >= height-3)
          sum_3_st += solvetime;

        arith_uint256 target;
        target.SetCompact(block->nBits);
        sum_target += target / (k * N);
    }

    // Keep t reasonable in case strange solvetimes occurred.
    if (t < k / dnorm) {
      //LogPrintf("DEVTEST: t Below k/dnorm\n");
      t = k / dnorm;
    }

    const arith_uint256 pow_limit = UintToArith256(params.PowLimit(true));
    arith_uint256 next_target = t * sum_target;
    arith_uint256 prev_target;
    prev_target.SetCompact(pindexLast->nBits);

    //LogPrintf("DEVTEST: Initial next_target: %s\n",next_target.ToString());

    // Prevent difficulty from dropping too fast or increasing too much. So stay in range: 67% - 150%
    if (next_target > prev_target * 150/100) {
      next_target = prev_target * 150/100;
      //LogPrintf("DEVTEST: Above 150/100; next_target: %s\n",next_target.ToString());
    }
    else if (next_target < prev_target * 100/150) {
      next_target = prev_target * 100/150;
      //LogPrintf("DEVTEST: Below 100/150; next_target: %s\n",next_target.ToString());
    }

    // If last 3 blocks are generated in less than 80% of block interval,
    // difficulty must jump at least 6% (For N=90 coins, 6% jump recommended)
    if (sum_3_st < T * 80/100) {
      //LogPrintf("DEVTEST: Below 80/100; next_target: %s\n",next_target.ToString());
      if (next_target > prev_target * 100/106) {
        next_target = prev_target * 100/106;
        //LogPrintf("DEVTEST: Adjusted next_target: %s\n",next_target.ToString());
      }
    }

    if (next_target > pow_limit) {
      //LogPrintf("DEVTEST: Above pow_limit; next_target: %s\n",next_target.ToString());
      next_target = pow_limit;
    }

    return next_target.GetCompact();
}

// Deprecated for Bitcoin RM
unsigned int BitcoinGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.PowLimit(false)).GetCompact();
    
    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return BitcoinCalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}


// Depricated for Bitcoin RM
unsigned int BitcoinCalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;
    
    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespanLegacy/4)
        nActualTimespan = params.nPowTargetTimespanLegacy/4;
    if (nActualTimespan > params.nPowTargetTimespanLegacy*4)
        nActualTimespan = params.nPowTargetTimespanLegacy*4;
    
    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.PowLimit(false));
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespanLegacy;
    
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;
    
    return bnNew.GetCompact();
}

bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams& params)
{
    unsigned int n = params.EquihashN();
    unsigned int k = params.EquihashK();

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);
    if (!isValid)
        return error("CheckEquihashSolution(): invalid solution");

    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, bool postfork, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.PowLimit(postfork)))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
