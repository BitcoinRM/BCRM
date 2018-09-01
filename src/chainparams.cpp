// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "uint256.h"
#include "arith_uint256.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

// For equihash_parameters_acceptable.
#include "crypto/equihash.h"
#include "net.h"
#include "validation.h"
#define equihash_parameters_acceptable(N, K) \
    ((CBlockHeader::HEADER_SIZE + equihash_solution_size(N, K))*MAX_HEADERS_RESULTS < \
     MAX_PROTOCOL_MESSAGE_LENGTH-1000)

#include "base58.h"
#include <assert.h>
#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include "genesisEquihash.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << SCRIPTSIG << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = ArithToUint256(arith_uint256(nNonce));
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.nHeight  = 0;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = STRING;
    const CScript genesisOutputScript = CScript() << ParseHex(GENKEY) << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 1440000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x00");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.BCRMHeight = 0;
        consensus.BCRMPremineWindow = consensus.BCRMHeight > 0 ? 20:21; // genesis block excluded
        consensus.BCRMHeightRegular = consensus.BCRMHeight + consensus.BCRMPremineWindow;  // Regular mining at this block and all subsequent blocks
        consensus.BCRMPremineEnforceWhitelist = true;
        consensus.BitcoinPostforkBlock = uint256S("00");
        consensus.BitcoinPostforkTime = 1522468800;
        consensus.powLimit = uint256S(MAIN_POWLIMIT);
        consensus.powLimitStart = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitLegacy = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        
        consensus.nPowAveragingWindow = 30;
        consensus.nPowMaxAdjustDown = 32;
        consensus.nPowMaxAdjustUp = 16;

        consensus.nPowTargetTimespanLegacy = 14 * 24 * 60 * 60; // 2 weeks
        consensus.nPowTargetSpacing = 60;

        consensus.nZawyLwmaAveragingWindow = 90; // std::round(45.0 * pow(600.0/consensus.nPowTargetSpacing, 0.3));
        consensus.nZawyLwmaAdjustedWeight = 245209; // std::round(0.998 * consensus.nPowTargetSpacing * consensus.nZawyLwmaAveragingWindow * (consensus.nZawyLwmaAveragingWindow + 1)/2.0);
        consensus.nZawyLwmaMinDenominator = 10;
        consensus.fZawyLwmaSolvetimeLimitation = true;
        consensus.BCRMMaxFutureBlockTime = 300; // 5 * consensus.nPowTargetSpacing

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespanLegacy / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = consensus.BitcoinPostforkTime + 31557600;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = consensus.BitcoinPostforkTime + 31557600;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStartLegacy[0] = 0xd1;
        pchMessageStartLegacy[1] = 0x41;
        pchMessageStartLegacy[2] = 0xf7;
        pchMessageStartLegacy[3] = 0xd9;

        pchMessageStart[0] = 0x42;
        pchMessageStart[1] = 0x43;
        pchMessageStart[2] = 0x52;
        pchMessageStart[3] = 0x4d;
        nDefaultPort = 2094; // different port than Bitcoin
        nBitcoinDefaultPort = 8333;
        nPruneAfterHeight = 100000;
        const size_t N = 144, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(MAIN_TIME, MAIN_NONCE, MAIN_NBITS, 1, MAIN_SUBSIDY * COIN);
        genesis.nSolution = ParseHex(MAIN_EQUIHASH);
        consensus.hashGenesisBlock = genesis.GetHash(consensus);

        assert(consensus.hashGenesisBlock == uint256S(MAIN_GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(MAIN_MERKLE_ROOT));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        vSeeds.emplace_back("dnsseed.bitcoinrm.org", true);
        vSeeds.emplace_back("dnsseedna.bitcoinrm.org", true);
        vSeeds.emplace_back("dnsseedau.bitcoinrm.org", true);
        vSeeds.emplace_back("dnsseedsg.bitcoinrm.org", true);
        vSeeds.emplace_back("dnsseed2.bitcoinrm.org", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);  // prefix: R
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,50);  // prefix: M
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {{{0, uint256S("0x00")}}};

        chainTxData = ChainTxData{
            // Data as of block 0x00 (height 0).
            0, // * UNIX timestamp of last known number of transactions
            0,  // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0         // * estimated number of transactions per second after that timestamp
        };

        // MAIN NET Groups: 1 to 100; Entries in each group: 1 to 100
        vPreminePubkeys = {
            { "RJzPFMaERA7a5ibdFWo1jaxymqempvju37" },
            { "RBxwCX6EjvSXH8L6mX4UF3mzP2fuAT8xGp" },
            { "RA2kQBNgM9c96sL1p5LrkbifZSVY6buw2k" },
            { "REGrMDHKx5zr4jsHUoqGyUBBKBhAnBr1sU" },
            { "RRAxkqfE3WDgThaeNrq7goVJ6uSmkoS9wF" },
            { "RScDFnWjbRFQjfWTfPjDUhm1CnfdqiPTR5" },
            { "R9ZTwv8teAFDZRn5tjo64zsKXVUWya4xij" },
            { "RA2bKF2qWUGTSyTab4LEg7z25nZBP1ZTYS" },
            { "RCshRauH1CxgnYgTEVW5SGxvsrV33YQS5H" },
            { "RB1v8Vk1b6XhrVNmh7otucZs5VpsiX6wPj" },
            { "RA2bKF2qWUGTSyTab4LEg7z25nZBP1ZTYS" },
            { "RT9XitNbiXbb3HGhTebV9QzSnbZXP4mwbg" },
            { "RNsXpypzskk1owLqf3ZoGKXHcEqxNmsAXS" },
            { "RWFP48SaLJJAHbJKMZAuowzo8G95TconNu" },
            { "RW3wEjscC28Dhy5GzLfkxuPpggEb346Wtt" },
            { "RXWn5RnRWAcNabGZ1bjaqFinVA98rfnkyz" },
            { "RWFP48SaLJJAHbJKMZAuowzo8G95TconNu" },
            { "RHcoHKgu8HuTZx1mNKwKsdJsZyoKC1Uuh9" },
            { "RDGcz3LW579cVti1TdJCRWAoBgoxmdu3fy" },
            { "RBeEwbDGgSJS3ZKQkmfXbdoUAiFpLUEwBK" },
        };

        // Founders Reward: Multisig addresses: 1 to 100
        vFoundersRewardAddress = {
            "RTBGFbhro71i2pka5RQGfYFrNA6WKvWr2i",
            "RYJZRWc1BNtBgzFAZpczU7M1tHWiYA5vzP",
            "RKkYrny3ZJEn8bCZhq1PLE3tob3HUnUVhh",
            "RTBGFbhro71i2pka5RQGfYFrNA6WKvWr2i",
            "RYJZRWc1BNtBgzFAZpczU7M1tHWiYA5vzP",
            "RKkYrny3ZJEn8bCZhq1PLE3tob3HUnUVhh",
            "RM5yaELh1qWTywm6ULnzCT9ttF3QKcBSfn",
            "RFGVe1ZVrTKpjbTY3nbTx494yoJqDmFSpK",
            "RJJv8UBAQBkveRJ54qaCj2s396VomcGbsX",
            "RM5yaELh1qWTywm6ULnzCT9ttF3QKcBSfn",
            "RFGVe1ZVrTKpjbTY3nbTx494yoJqDmFSpK",
            "RJJv8UBAQBkveRJ54qaCj2s396VomcGbsX",
            "RFXjPp69Gb5SRujbjjBfdbeW9dsAoCJw4K",
            "RMLyyofFyzC6hBtoBKRdA4L3mtvDmK3JTG",
            "RDLLNvApwDso39EUJizN7EGy6W7Yk6UyCL",
            "RFXjPp69Gb5SRujbjjBfdbeW9dsAoCJw4K",
            "R9gNyz1ZwW4kh2NMdRHozQyZTkFb2gp8Z7",
            "RLpDqrJnAiRr1QyHTXKrLPjevrmG3kTwds",
            "RR9yFJSB65qaJEvw537vJAmPqrBnc5DHwT",
            "RC5bJBHSfQeVj252MfbTbpzB2a3jKJMhXM",
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 1440000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x00");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.BCRMHeight = 0;
        consensus.BCRMPremineWindow = consensus.BCRMHeight > 0 ? 20:21; // genesis block excluded
        consensus.BCRMHeightRegular = consensus.BCRMHeight + consensus.BCRMPremineWindow;  // Regular mining at this block and all subsequent blocks
        consensus.BCRMPremineEnforceWhitelist = true;
        consensus.BitcoinPostforkBlock = uint256S("00");
        consensus.BitcoinPostforkTime = 1522468800;
        consensus.powLimit = uint256S(TEST_POWLIMIT);
        consensus.powLimitStart = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitLegacy = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        
        consensus.nPowAveragingWindow = 30;
        consensus.nPowMaxAdjustDown = 32;
        consensus.nPowMaxAdjustUp = 16;

        consensus.nPowTargetTimespanLegacy = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60;

        consensus.nZawyLwmaAveragingWindow = 90; // std::round(45.0 * pow(600.0/consensus.nPowTargetSpacing, 0.3));
        consensus.nZawyLwmaAdjustedWeight = 245209; // std::round(0.998 * consensus.nPowTargetSpacing * consensus.nZawyLwmaAveragingWindow * (consensus.nZawyLwmaAveragingWindow + 1)/2.0);
        consensus.nZawyLwmaMinDenominator = 10;
        consensus.fZawyLwmaSolvetimeLimitation = true;
        consensus.BCRMMaxFutureBlockTime = 300; // 5 * consensus.nPowTargetSpacing

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespanLegacy / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = consensus.BitcoinPostforkTime + 31557600;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = consensus.BitcoinPostforkTime + 31557600;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStartLegacy[0] = 0x0b;
        pchMessageStartLegacy[1] = 0x11;
        pchMessageStartLegacy[2] = 0x09;
        pchMessageStartLegacy[3] = 0x07;

        pchMessageStart[0] = 0x43;
        pchMessageStart[1] = 0x44;
        pchMessageStart[2] = 0x53;
        pchMessageStart[3] = 0x4e;
        nDefaultPort = 3094;
        nBitcoinDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        const size_t N = 144, K = 5;  // Same as mainchain.
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(TEST_TIME, TEST_NONCE, TEST_NBITS, 1, TEST_SUBSIDY * COIN);
        genesis.nSolution = ParseHex(TEST_EQUIHASH);
        consensus.hashGenesisBlock = genesis.GetHash(consensus);

        assert(consensus.hashGenesisBlock == uint256S(TEST_GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(TEST_MERKLE_ROOT));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        vSeeds.emplace_back("dnsseed-test1.bitcoinrm.org", true);
        vSeeds.emplace_back("dnsseed-test2.bitcoinrm.org", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,75);  // Prefix X
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,137); // Prefix x
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {{{0, uint256S("0x00")}}};

        chainTxData = ChainTxData{
            // Data as of block 0
            0,
            0,
            0
        };

        // TEST NET Groups: 1 to 100; Entries in each group: 1 to 100
        vPreminePubkeys = {
            { "XJDHayP2x55Eg7u6MKgFhJvQV1DCgf3sfM" },
            { "XCX1Ck4jXpsKJLARQS8FvD925cahpHizKQ" },
            { "XUbw1uYqQybYeFBDoqyZC5ejyxw5yjbbh3" },
            { "XLKzLkqQjKD5YX1CgEWssSRDN4vKkTeUGc" },
            { "XEGXopbSAEPks38MYBxrERznBCXKZitVeE" },
            { "XXfPLKmFNaetqpTDhTsvmGanagDQSYDuj3" },
            { "XFcEEjgAjfUVBWr37i16VvmDHvWYZCN5rC" },
            { "XMYJhQ6rcuf2ZpRf7tdUtS2niWXEoEELjg" },
            { "XFhZXEjaNHRN28RHbh9N2GJ2CCnYG7pco3" },
            { "XE25T1V24ibj2yHBsTdVks2WfZNwL2oWMT" },
            { "XC1tXLjrK48VWSqJWE1KoTJYFZ8sPH4qJf" },
            { "XUeVZTtHTVz1skU1jswDEXXssDYUx68gSN" },
            { "XNpX1q6xG6c5HzpGYXAoam6iPD6a2mjuNF" },
            { "XWpCrur2T4KeWHHH99wqyHa1or3Mv7ha4C" },
            { "XJXj7iGwk77WoWrLp92UQJHYBCMc6r8C71" },
            { "XC4MTG8voF3AiLsKkgkVH631U2dpoFq4Yh" },
            { "XLRMPT2QUyW8y7ZazsY6Fxm5XqziYpSzUt" },
            { "XVfTfq3w9d9FpR4utAbsRK1KnSYwcc5zWm" },
            { "XEvfGaPixdNGmcMw5ETabVr865XRFQcwPK" },
            { "XFh1Hz7omQfGRh7kazdhSPBGGXGrXaZHdc" },
        };

        // Founders Reward: Multisig addresses: 1 to 100
        vFoundersRewardAddress = {
            "XLwmCpLHeZDuAThp3xgGvYwDs5a91bfTzv",
            "XCX1Ck4jXpsKJLARQS8FvD925cahpHizKQ",
            "XUbw1uYqQybYeFBDoqyZC5ejyxw5yjbbh3",
            "XLKzLkqQjKD5YX1CgEWssSRDN4vKkTeUGc",
            "XEGXopbSAEPks38MYBxrERznBCXKZitVeE",
            "XXfPLKmFNaetqpTDhTsvmGanagDQSYDuj3",
            "XFcEEjgAjfUVBWr37i16VvmDHvWYZCN5rC",
            "XMYJhQ6rcuf2ZpRf7tdUtS2niWXEoEELjg",
            "XFhZXEjaNHRN28RHbh9N2GJ2CCnYG7pco3",
            "XE25T1V24ibj2yHBsTdVks2WfZNwL2oWMT",
            "XC1tXLjrK48VWSqJWE1KoTJYFZ8sPH4qJf",
            "XUeVZTtHTVz1skU1jswDEXXssDYUx68gSN",
            "XNpX1q6xG6c5HzpGYXAoam6iPD6a2mjuNF",
            "XWpCrur2T4KeWHHH99wqyHa1or3Mv7ha4C",
            "XJXj7iGwk77WoWrLp92UQJHYBCMc6r8C71",
            "XC4MTG8voF3AiLsKkgkVH631U2dpoFq4Yh",
            "XLRMPT2QUyW8y7ZazsY6Fxm5XqziYpSzUt",
            "XVfTfq3w9d9FpR4utAbsRK1KnSYwcc5zWm",
            "XEvfGaPixdNGmcMw5ETabVr865XRFQcwPK",
            "XFh1Hz7omQfGRh7kazdhSPBGGXGrXaZHdc",
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 1440000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x00");
        consensus.BIP65Height = 0; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 0; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.BCRMHeight = 0;
        consensus.BCRMPremineWindow = consensus.BCRMHeight > 0 ? 20:21; // genesis block excluded
        consensus.BCRMHeightRegular = consensus.BCRMHeight + consensus.BCRMPremineWindow;  // Regular mining at this block and all subsequent blocks
        consensus.BCRMPremineEnforceWhitelist = false;
        consensus.BitcoinPostforkBlock = uint256S("00");
        consensus.BitcoinPostforkTime = 1522468800;
        consensus.powLimit = uint256S(REG_POWLIMIT);
        consensus.powLimitStart = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitLegacy = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 30;
        consensus.nPowMaxAdjustDown = 32;
        consensus.nPowMaxAdjustUp = 16;

        consensus.nPowTargetTimespanLegacy = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60;

        consensus.nZawyLwmaAveragingWindow = 90; // std::round(45.0 * pow(600.0/consensus.nPowTargetSpacing, 0.3));
        consensus.nZawyLwmaAdjustedWeight = 245209; // std::round(0.998 * consensus.nPowTargetSpacing * consensus.nZawyLwmaAveragingWindow * (consensus.nZawyLwmaAveragingWindow + 1)/2.0);
        consensus.nZawyLwmaMinDenominator = 10;
        consensus.fZawyLwmaSolvetimeLimitation = true;
        consensus.BCRMMaxFutureBlockTime = 300; // 5 * consensus.nPowTargetSpacing

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStartLegacy[0] = 0xfa;
        pchMessageStartLegacy[1] = 0xbf;
        pchMessageStartLegacy[2] = 0xb5;
        pchMessageStartLegacy[3] = 0xda;
        
        pchMessageStart[0] = 0x44;
        pchMessageStart[1] = 0x45;
        pchMessageStart[2] = 0x54;
        pchMessageStart[3] = 0x4f;

        nDefaultPort = 4094;
        nBitcoinDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(REG_TIME, REG_NONCE, REG_NBITS, 1, REG_SUBSIDY * COIN);
        genesis.nSolution = ParseHex(REG_EQUIHASH);
        consensus.hashGenesisBlock = genesis.GetHash(consensus);

        assert(consensus.hashGenesisBlock == uint256S(REG_GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(REG_MERKLE_ROOT));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,78);  // Prefix Y
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,140); // Prefix y
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // REG NET Groups: 1 to 100; Entries in each group: 1 to 100
        vPreminePubkeys = {
            { "YXfjKB7SABiZUT8Fvkocjd9V2dMLajVe5f" },
            { "YUC6H4dGqTE1hTYT9PvN9oDrJTKbQHNv7m" },
            { "Yg4DxykSpWKkwrYyJBsFnEqKZCeJbzoBfo" },
        };

        // Founders Reward: Multisig addresses: 1 to 100
        vFoundersRewardAddress = {
            "YXfjKB7SABiZUT8Fvkocjd9V2dMLajVe5f",
            "YUC6H4dGqTE1hTYT9PvN9oDrJTKbQHNv7m",
            "Yg4DxykSpWKkwrYyJBsFnEqKZCeJbzoBfo",
        };
    }
    
};

class BitcoinAddressChainParam : public CMainParams
{
public:
    BitcoinAddressChainParam()
    {
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
    }
};

static std::unique_ptr<CChainParams> globalChainParams;
static BitcoinAddressChainParam chainParamsForAddressConversion;

const CChainParams &Params()
{
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams &BitcoinAddressFormatParams()
{
    return chainParamsForAddressConversion;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}


static CScript CltvMultiSigScript(const std::vector<std::string>& pubkeys, uint32_t lock_time, uint32_t num_sigs) {
    assert(pubkeys.size() > 0 && pubkeys.size() < 101);
    assert(num_sigs > 0);
    CScript redeem_script;

    if (lock_time > 0)
        redeem_script << lock_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP;

    redeem_script << num_sigs;

    for (const std::string& pubkey : pubkeys)
        redeem_script << ToByteVector(ParseHex(pubkey));

    redeem_script << pubkeys.size() << OP_CHECKMULTISIG;
    return redeem_script;
}

bool CChainParams::IsPremineAddressScript(const CScript& scriptPubKey, uint32_t height) const {

    int num_sigs = 1;
    int block = height - consensus.BCRMHeight;

    // If we are starting a new chain, rather than forking, genesis block is excluded from premine
    if (consensus.BCRMHeight == 0)
      block--;

    static const double SIG_NEEDED  = 4.0 / 6;    // fraction that must sign for each group
    assert((uint32_t)consensus.BCRMHeight <= height && height < (uint32_t)consensus.BCRMHeightRegular);
    assert(vPreminePubkeys.size() > 0 && vPreminePubkeys.size() < 101);  // At least one group of signatures

    // Round Robin if more than one group
    const std::vector<std::string> pubkeys = vPreminePubkeys.size() > 1 ? vPreminePubkeys[block % vPreminePubkeys.size()] : vPreminePubkeys[0];

    assert(pubkeys.size() > 0 && pubkeys.size() < 101);   // At least one signature in each group
    CScript redeem_script;

    if (pubkeys.size() > 1) {
        // All entries in the group must be compressed public keys
        for (const std::string& pubkey : pubkeys) {
            if (!(pubkey[0] == '0' && (pubkey[1] == '2' || pubkey[1] == '3'))) {
                LogPrintf("Bad public key found in group: %s\n", pubkey);
                return false;
            }
        }
        
        num_sigs = (int)round(SIG_NEEDED * pubkeys.size());

        // Minimum 2 signatures if multiple signatures in each group
        if (num_sigs < 2) num_sigs = 2;

        redeem_script = CltvMultiSigScript(pubkeys, 0, num_sigs);
        redeem_script = GetScriptForDestination(CScriptID(redeem_script));
    }
    else {
        std::string s = pubkeys[0];
        CBitcoinAddress address(s.c_str());

        if (address.IsValid()) {
            redeem_script = GetScriptForDestination(address.Get());
        }
        else if (!(s[0] == '0' && (s[1] == '2' || s[1] == '3')))
            throw std::runtime_error(strprintf("Bad public key: %s\n", s));
        else {
            CPubKey pubkey(ParseHex(s));
            if (!pubkey.IsFullyValid())
                throw std::runtime_error(strprintf("Invalid public key: %s\n", s));
            redeem_script = GetScriptForRawPubKey(pubkey);
        }
    }
    return scriptPubKey == redeem_script;
}

std::string CChainParams::GetFoundersRewardAddress(uint32_t height) const {

    int block = height - consensus.BCRMHeightRegular;

    if (vFoundersRewardAddress.size() == 0 || vFoundersRewardAddress.size() > 100)
        throw std::runtime_error("Invalid number of founders addresses; must be 1-100\n");

    return vFoundersRewardAddress.size() > 1 ? vFoundersRewardAddress[block % vFoundersRewardAddress.size()] : vFoundersRewardAddress[0];
}
    
CScript CChainParams::GetFoundersRewardScript(uint32_t height) const {
    CScript redeem_script;

    if (height < (uint32_t)consensus.BCRMHeightRegular)
        throw std::runtime_error(strprintf("Invalid block height for founders reward: %d\n", height));

    std::string s = GetFoundersRewardAddress(height - (uint32_t)consensus.BCRMHeightRegular);
    CBitcoinAddress address(s.c_str());

    if (!address.IsValid())
        throw std::runtime_error(strprintf("Bad founders address: %s\n",s));

    redeem_script = GetScriptForDestination(address.Get());
    return redeem_script;
}
