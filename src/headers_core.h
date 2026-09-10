// Core node headers -- no GUI framework dependency.
// Included by gui.cpp and all non-GUI source files.

// The one place the human-readable release version lives -- bump it at release.
// It is what the About dialog shows. Protocol and transaction versions elsewhere
// (nVersion fields) are unrelated and must not be changed for a release.
#define BITFLASH_VERSION_STRING "1.2.21"

#ifdef _MSC_VER
#pragma warning(disable:4786)
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <direct.h>  // _mkdir on MSVC
#ifndef _MSC_VER
// MinGW: _mkdir not defined, use mkdir from <sys/stat.h>
#include <sys/stat.h>
inline int _mkdir(const char* p) { return ::mkdir(p); }
#endif
#else
#include "compat.h"
#endif

#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <assert.h>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <deque>
#include <map>
#include <set>
#include <algorithm>
#include <numeric>
#include <array>
#include <boost/foreach.hpp>
#pragma hdrstop
using namespace std;

template<typename T1, typename T2>
inline typename std::common_type<T1,T2>::type min(const T1& a, const T2& b)
{ return (a<b)?a:b; }
template<typename T1, typename T2>
inline typename std::common_type<T1,T2>::type max(const T1& a, const T2& b)
{ return (a>b)?a:b; }

#include "serialize.h"
#include "uint256.h"
#include "util.h"
#include "key.h"
#include "bignum.h"
#include "base58.h"
#include "script.h"
#include "db.h"
#include "net.h"
#include "nostr.h"
#include "randomx_pow.h"
#include "main.h"
#include "market.h"

// GUI callback -- implemented in gui.cpp (or as no-op in headless builds)
void MainFrameRepaint();
string DateTimeStr(int64 nTime);
