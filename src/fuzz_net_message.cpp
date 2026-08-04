// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// libFuzzer harness for the P2P message envelope parser. It feeds arbitrary
// receive-buffer bytes into ProcessMessages() through a dummy CNode, without
// opening sockets or starting node threads.

#include "headers_core.h"

#include <stdint.h>
#include <stddef.h>

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Keep this first target focused on parser behavior, not multi-megabyte
    // allocation pressure. The protocol size guards have their own selftest.
    if (size > 4096)
        return 0;

    CNode node(INVALID_SOCKET, CAddress("127.0.0.1"));
    node.nVersion = 0; // exercise pre-version gating plus the version parser
    if (size > 0)
        node.vRecv.write((const char*)data, (int)size);

    ProcessMessages(&node);
    return 0;
}
