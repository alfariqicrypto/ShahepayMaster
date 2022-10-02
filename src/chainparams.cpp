// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The RavenCoin Core developers
// Copyright (c) 2022-Present The ShahePay Core developers

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>
#include "chainparamsseeds.h"

extern double algoHashTotal[16];
extern int algoHashHits[16];

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << CScriptNum(0) << 3162191751 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "SHAHEPAY - P2P Crypto Payment System";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

void CChainParams::TurnOffSegwit() {consensus.nSegwitEnabled = false;}
void CChainParams::TurnOffCSV() {consensus.nCSVEnabled = false;}
void CChainParams::TurnOffBIP34() {consensus.nBIP34Enabled = false;}
void CChainParams::TurnOffBIP65() {consensus.nBIP65Enabled = false;}
void CChainParams::TurnOffBIP66() {consensus.nBIP66Enabled = false;}

bool CChainParams::BIP34() {return consensus.nBIP34Enabled;}
bool CChainParams::BIP65() {return consensus.nBIP34Enabled;}
bool CChainParams::BIP66() {return consensus.nBIP34Enabled;}
bool CChainParams::CSVEnabled() const{return consensus.nCSVEnabled;}


/** MAIN NETWORK **/

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;

        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.kawpowLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetTimespan = 2016 * 60;
        consensus.nPowTargetSpacing = 1 * 60;
	consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1613;
        consensus.nMinerConfirmationWindow = 2016;

        consensus.nMinimumChainWork = uint256S("0x00");

        consensus.defaultAssumeValid = uint256S("0x00000087d3328011c972af5837f8b8e62f7fcbf4688cf19da12407237314e254"); // Block 0

        pchMessageStart[0] = 0x53; // S
        pchMessageStart[1] = 0x48; // H
        pchMessageStart[2] = 0x41; // A
        pchMessageStart[3] = 0x50; // P
        // nDefaultPort = 44789;
        nDefaultPort = 29154;

        nPruneAfterHeight = 500;

        genesis = CreateGenesisBlock(1649407854, 20908957, 0x1e00ffff, 2, 500 * COIN);

        consensus.hashGenesisBlock = genesis.GetX16RHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00000087d3328011c972af5837f8b8e62f7fcbf4688cf19da12407237314e254"));
        assert(genesis.hashMerkleRoot == uint256S("ce420af565487f911206de0108dd9a33dc746407165cb135c9977f8fecf4d0f0"));

        //vSeeds.emplace_back("dnsseed.shahepay.site", false);
        //vSeeds.emplace_back("54.37.142.121", false);
        //vSeeds.emplace_back("192.99.252.243", false);

        // Main Seeders
	vSeeds.emplace_back("dnsseed.shahepay.site", false);

	// Backup Seeders
	vSeeds.emplace_back("51.77.48.45", false);
	vSeeds.emplace_back("192.99.252.243", false);
	vSeeds.emplace_back("54.37.142.121", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63); // S
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,40); // H
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,23); // A
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // BIP44 cointype in mainnet is '175'
        nExtCoinType = 175;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;


        checkpointData = (CCheckpointData) {
            {
                { 1, uint256S("0x0000047e6a542572ff844ee69518e7010a0767a6a54eb912b6749ae98051e9ff")},
                { 2500, uint256S("0x0000000008d18ed22714b72696301412741d5cfda69d469d352b96f7d7abdf53")},
                { 6439, uint256S("0x0000000039f39555f86234390724d54c870dce7feb8c7decafaf3140a5effa7a")},
                { 6699, uint256S("0x000000003a4f2968547c2224f07637042d8e1161be3860650a6e6394dfd80a6c")},
                { 243392, uint256S("0x000000000ae49e507583c19129367c45ad636089844f1693a813e7258e071b28")}
	    }
        };


        chainTxData = ChainTxData{
            1649759378, // Tue, 12 Apr 2022 10:29:38 +0000
            6400,
            0.1
        };

        /** SHAHE Start **/
         // Burn Amounts
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

/*
        // Shahepay Community Asset Address
        strIssueAssetBurnAddress = "SVofnKu8U9uCbZrLK7dBevRYJVxNaUPg1z";
        strReissueAssetBurnAddress = "SgfdPmuEJHnuEk8XUmbbFAV79iqoj2qSf9";
        strIssueSubAssetBurnAddress = "SiQ56nm6SEkrcg5QvEA4FBM1XTQr3ZzMX5";
        strIssueUniqueAssetBurnAddress = "SNzoXQb3JwKgdP9i3U7JjYfLqnKQ3GW3Js";
        strIssueMsgChannelAssetBurnAddress = "SXptGbVNUjw7t6KgAhZsswFDm8VjZuCoqm";
        strIssueQualifierAssetBurnAddress = "SdQTP75LuGfbPniMTEikNkAD8HtoUNtx9S";
        strIssueSubQualifierAssetBurnAddress = "SdzzjDWdU4fcMQa1KvcpmtVmLweMZeANyj";
        strIssueRestrictedAssetBurnAddress = "SWd3GsxVC23J2KWBdAW1vGTbNwbFwmZsuG";
        strAddNullQualifierTagBurnAddress = "SetYk6H4NojLzXnGA7eskNKcZkvpUhGpDh";

        //Global Development Address
        strGlobalBurnAddress = "ShHciapTkwEyAcbja8GEuu6s7e52zHVdMv";

*/

        // Burn Addresses
        strIssueAssetBurnAddress = "SDissueAssetXXXXXXXXXXXXXXXXarpEmt";
        strReissueAssetBurnAddress = "SDReissueAssetXXXXXXXXXXXXXXZAKPbJ";
        strIssueSubAssetBurnAddress = "SDissueSubAssetXXXXXXXXXXXXXW6D3dn";
        strIssueUniqueAssetBurnAddress = "SDissueUniqueAssetXXXXXXXXXXSkWCDd";
        strIssueMsgChannelAssetBurnAddress = "SDissueMsgChanneLAssetXXXXXXSkQjob";
        strIssueQualifierAssetBurnAddress = "SDissueQuaLifierXXXXXXXXXXXXZVc7zN";
        strIssueSubQualifierAssetBurnAddress = "SDissueSubQuaLifierXXXXXXXXXUhKn5T";
        strIssueRestrictedAssetBurnAddress = "SDissueRestrictedXXXXXXXXXXXXveZHA";
        strAddNullQualifierTagBurnAddress = "SDaddTagBurnXXXXXXXXXXXXXXXXaqLzue";

            //Global Burn Address
        strGlobalBurnAddress = "SDBurnXXXXXXXXXXXXXXXXXXXXXXWdW4er";


        // DGW Activation
        nDGWActivationBlock = 1;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        nAssetActivationHeight = 0; // Asset activated block height
        nMessagingActivationBlock = 0; // Messaging activated block height
        nRestrictedActivationBlock = 0; // Restricted activated block height

        nKAAAWWWPOWActivationTime = 1664761134; // Mon, 03 Oct 2022 08:38:54 +0700
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;
        /** SHAHE End **/
    }
};


/**  TESTNET **/

class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.nBIP34Enabled = false;
        consensus.nBIP65Enabled = false;
        consensus.nBIP66Enabled = false;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;

        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2016 * 60; //1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1310; // Approx 65% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000168050db560b4");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000006272208605c4df3b54d4d5515759105e7ffcb258e8cd8077924ffef1");
	    
        pchMessageStart[0] = 0xe4; // R
        pchMessageStart[1] = 0xa1; // V
        pchMessageStart[2] = 0xa3; // N
        pchMessageStart[3] = 0x54; // T
        //nDefaultPort = 45789;
        nDefaultPort = 16789;        

	nPruneAfterHeight = 500;

        genesis = CreateGenesisBlock(1649407854, 20908957, 0x1e00ffff, 2, 500 * COIN);

        consensus.hashGenesisBlock = genesis.GetX16RHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00000087d3328011c972af5837f8b8e62f7fcbf4688cf19da12407237314e254"));
        assert(genesis.hashMerkleRoot == uint256S("ce420af565487f911206de0108dd9a33dc746407165cb135c9977f8fecf4d0f0"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.emplace_back("51.195.249.132", false);
	    
 	base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,90);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // BIP44 cointype in mainnet is '175'
        nExtCoinType = 175;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;

        checkpointData = (CCheckpointData) {
            {
            }
        };

        chainTxData = ChainTxData{
		
        };

        /** SHAHE Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        // Burn Addresses
        strIssueAssetBurnAddress = "n1issueAssetXXXXXXXXXXXXXXXXWdnemQ";
        strReissueAssetBurnAddress = "n1ReissueAssetXXXXXXXXXXXXXXWG9NLd";
        strIssueSubAssetBurnAddress = "n1issueSubAssetXXXXXXXXXXXXXbNiH6v";
        strIssueUniqueAssetBurnAddress = "n1issueUniqueAssetXXXXXXXXXXS4695i";
        strIssueMsgChannelAssetBurnAddress = "n1issueMsgChanneLAssetXXXXXXT2PBdD";
        strIssueQualifierAssetBurnAddress = "n1issueQuaLifierXXXXXXXXXXXXUysLTj";
        strIssueSubQualifierAssetBurnAddress = "n1issueSubQuaLifierXXXXXXXXXYffPLh";
        strIssueRestrictedAssetBurnAddress = "n1issueRestrictedXXXXXXXXXXXXZVT9V";
        strAddNullQualifierTagBurnAddress = "n1addTagBurnXXXXXXXXXXXXXXXXX5oLMH";

        // Global Burn Address
        strGlobalBurnAddress = "n1BurnXXXXXXXXXXXXXXXXXXXXXXU1qejP";

        // DGW Activation
        nDGWActivationBlock = 1;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        nAssetActivationHeight = 0; // Asset activated block height
        nMessagingActivationBlock = 0; // Messaging activated block height
        nRestrictedActivationBlock = 0; // Restricted activated block height

        nKAAAWWWPOWActivationTime = 1694225030; // 2023-09-09T02:03:50+00:00
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;
        /** SHAHE End **/
    }
};


/**  REGRESSION TEST **/

class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nBIP34Enabled = false;
        consensus.nBIP65Enabled = false; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.nBIP66Enabled = false;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
	    
        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x52; // R
        pchMessageStart[1] = 0x41; // A
        pchMessageStart[2] = 0x56; // V
        pchMessageStart[3] = 0x43; // C

        //nDefaultPort = 46789;
        nDefaultPort = 26789;
	    
        nPruneAfterHeight = 500;

        genesis = CreateGenesisBlock(1649407854, 20908957, 0x1e00ffff, 2, 500 * COIN);

        consensus.hashGenesisBlock = genesis.GetX16RHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00000087d3328011c972af5837f8b8e62f7fcbf4688cf19da12407237314e254"));
        assert(genesis.hashMerkleRoot == uint256S("ce420af565487f911206de0108dd9a33dc746407165cb135c9977f8fecf4d0f0"));

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData) {
            {
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // BIP44 cointype in mainnet is '175'
        nExtCoinType = 175;

        /** SHAHE Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 500 * COIN;
        nReissueAssetBurnAmount = 100 * COIN;
        nIssueSubAssetBurnAmount = 100 * COIN;
        nIssueUniqueAssetBurnAmount = 5 * COIN;
        nIssueMsgChannelAssetBurnAmount = 100 * COIN;
        nIssueQualifierAssetBurnAmount = 1000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 100 * COIN;
        nIssueRestrictedAssetBurnAmount = 1500 * COIN;
        nAddNullQualifierTagBurnAmount = .1 * COIN;

        // Burn Addresses
        strIssueAssetBurnAddress = "n1issueAssetXXXXXXXXXXXXXXXXWdnemQ";
        strReissueAssetBurnAddress = "n1ReissueAssetXXXXXXXXXXXXXXWG9NLd";
        strIssueSubAssetBurnAddress = "n1issueSubAssetXXXXXXXXXXXXXbNiH6v";
        strIssueUniqueAssetBurnAddress = "n1issueUniqueAssetXXXXXXXXXXS4695i";
        strIssueMsgChannelAssetBurnAddress = "n1issueMsgChanneLAssetXXXXXXT2PBdD";
        strIssueQualifierAssetBurnAddress = "n1issueQuaLifierXXXXXXXXXXXXUysLTj";
        strIssueSubQualifierAssetBurnAddress = "n1issueSubQuaLifierXXXXXXXXXYffPLh";
        strIssueRestrictedAssetBurnAddress = "n1issueRestrictedXXXXXXXXXXXXZVT9V";
        strAddNullQualifierTagBurnAddress = "n1addTagBurnXXXXXXXXXXXXXXXXX5oLMH";

        // Global Burn Address
        strGlobalBurnAddress = "n1BurnXXXXXXXXXXXXXXXXXXXXXXU1qejP";

        // DGW Activation
        nDGWActivationBlock = 1;

        nMaxReorganizationDepth = 60;
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12;

        nAssetActivationHeight = 0; // Asset activated block height
        nMessagingActivationBlock = 0; // Messaging activated block height
        nRestrictedActivationBlock = 0; // Restricted activated block height

        nKAAAWWWPOWActivationTime = 1694225030; // 2023-09-09T02:03:50+00:00
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;
        /** SHAHE End **/
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &GetParams() {
    assert(globalChainParams);
    return *globalChainParams;
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

void SelectParams(const std::string& network, bool fForceBlockNetwork)
{
    SelectBaseParams(network);
    if (fForceBlockNetwork) {
        bNetwork.SetNetwork(network);
    }
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

void TurnOffSegwit(){globalChainParams->TurnOffSegwit();}
void TurnOffCSV() {globalChainParams->TurnOffCSV();}
void TurnOffBIP34() {globalChainParams->TurnOffBIP34();}
void TurnOffBIP65() {globalChainParams->TurnOffBIP65();}
void TurnOffBIP66() {globalChainParams->TurnOffBIP66();}
