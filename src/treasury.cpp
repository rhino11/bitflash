// Copyright (c) 2026 The Bitflash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#include "headers.h"
#include "treasury.h"

int  nTreasurySharePercent = 0;
bool fPoolFeeToTreasury    = false;

namespace {

// Mainnet: filled the day the three holders hand over their keys (see
// docs/treasury.md). Until then there is no mainnet treasury and everything
// that would pay it says so.
const char* const MAINNET_KEYS[3] = { "", "", "" };

// Testnet: one key in the bench wallet, one in the 202 test node, one made
// with openssl and kept outside any wallet. Test money only.
const char* const TESTNET_KEYS[3] = {
    "0454df45edfef8a5f4239acd34a3f68a356ea7c311f2b1ae8e34351bbc6274c83a34930526aad2d232f3085b7ef5d48d6f4a84fb88a5ada343f7316c30d0ac6bcc",
    "0450ebd4d1e9405108544e5dc2de355c1723f4ac0540b09b24847b09182233c92ffff1881ecb05bcf571631827aca521adeb083157448037705c9904d9e98c35c2",
    "0431724d3617be6cc6c91bb090ab480d5dfdb079dcf4a57d0b6f40259664684a804e206d4db8e785e6d3fdfbf5f1e6ed5a03aa469af9f304c81c914840de946bb6",
};

const char* const* KeysForNetwork()
{
    return IsTestNet() ? TESTNET_KEYS : MAINNET_KEYS;
}

} // namespace

namespace treasury {

bool Configured()
{
    const char* const* k = KeysForNetwork();
    for (int i = 0; i < 3; i++)
        if (!k[i] || !k[i][0])
            return false;
    return true;
}

std::vector<std::string> Keys()
{
    std::vector<std::string> v;
    if (!Configured())
        return v;
    const char* const* k = KeysForNetwork();
    for (int i = 0; i < 3; i++)
        v.push_back(k[i]);
    return v;
}

bool Script(CScript& scriptRet)
{
    scriptRet.clear();
    if (!Configured())
        return false;
    std::vector<std::vector<unsigned char> > keys;
    const char* const* k = KeysForNetwork();
    for (int i = 0; i < 3; i++)
    {
        std::vector<unsigned char> key = ParseHex(k[i]);
        // 65 bytes uncompressed or 33 compressed; anything else is a typo in
        // this file, and a typo here must never become an output.
        if (key.size() != 65 && key.size() != 33)
        {
            scriptRet.clear();
            return false;
        }
        keys.push_back(key);
    }
    scriptRet.SetMultisig(REQUIRED, keys);
    return true;
}

std::string ScriptHex()
{
    CScript s;
    if (!Script(s))
        return "";
    return HexStr(s.begin(), s.end(), false);
}

bool IsTreasury(const CScript& scriptPubKey)
{
    CScript s;
    return Script(s) && !s.empty() && scriptPubKey == s;
}

long long ShareOf(long long nBlockValue, int nPercent)
{
    if (nPercent <= 0 || nPercent > SHARE_MAX_PERCENT || nBlockValue <= 0 || !Configured())
        return 0;
    return nBlockValue * nPercent / 100;
}

} // namespace treasury
