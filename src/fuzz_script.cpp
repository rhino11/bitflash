// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// libFuzzer harness for raw script parsing and evaluation. It keeps the
// target deliberately small: arbitrary bytes become one CScript, then the
// parser, standard-script extractors and EvalScript all see that same input.

#include "headers_core.h"

#include <stdint.h>
#include <stddef.h>

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 4096)
        return 0;

    try
    {
        int nHashType = data[0];
        const unsigned char* pbegin = data + 1;
        const unsigned char* pend = data + size;
        CScript script(pbegin, pend);

        CScript::const_iterator pc = script.begin();
        opcodetype opcode;
        vector<unsigned char> vchPush;
        while (pc < script.end())
        {
            if (!script.GetOp(pc, opcode, vchPush))
                break;
        }

        script.GetSigOpCount();
        script.ToString();

        vector<unsigned char> vchPubKey;
        ExtractPubKey(script, false, vchPubKey);
        uint160 hash160;
        ExtractHash160(script, hash160);

        CTransaction tx;
        tx.vin.push_back(CTxIn(COutPoint(), CScript()));
        tx.vout.push_back(CTxOut(0, CScript()));

        vector<vector<unsigned char> > stack;
        EvalScript(script, tx, 0, nHashType, &stack);
    }
    catch (...)
    {
    }

    return 0;
}
