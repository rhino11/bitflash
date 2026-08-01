// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.


// For abi::__forced_unwind, which CATCH_PRINT_EXCEPTION below must let past.
#ifndef _WIN32
#include <cxxabi.h>
#endif

#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef __int64  int64;
typedef unsigned __int64  uint64;
#else
typedef long long  int64;
typedef unsigned long long  uint64;
#endif
#if defined(_MSC_VER) && _MSC_VER < 1300
#define for  if (false) ; else for
#endif

// MinGW already provides __forceinline for MSVC compatibility, so defining it
// unconditionally warned ten times per build once -w was removed.
#if !defined(_MSC_VER) && !defined(__forceinline)
#define __forceinline  inline
#endif

#define foreach             BOOST_FOREACH
#define loop                for (;;)
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))

// Route printf to debug.log (and the console on non-Windows) everywhere.
// (Previously gated on `defined(_WINDOWS) || !defined(_WIN32)` -- but
// _WINDOWS is only ever defined by the legacy, unused makefile.vc build;
// the real Windows build (makefile.mingw) never defines it, so on actual
// Windows this condition was always false and debug.log was never written.
// OutputDebugStringF() is already platform-safe internally: it always
// writes debug.log, and only echoes to the console when not on Windows.)
#define printf              OutputDebugStringF

#ifdef snprintf
#undef snprintf
#endif
#define snprintf my_snprintf

// One definition for every target. The MSVCRT branch that used to sit here
// produced "I64d", which is the specifier that segfaults on glibc (issue #5) --
// and it was pointless besides: this build targets UCRT, which accepts the C99
// forms, and the rest of the tree already prints int64 with %lld on Windows.
// Keeping one spelling everywhere is also what lets the format attributes below
// use a single archetype, so a bad specifier fails the build on both platforms.
#ifndef PRId64
#define PRId64  "lld"
#define PRIu64  "llu"
#define PRIx64  "llx"
#endif

// This is needed because the foreach macro can't get over the comma in pair<t1, t2>
#define PAIRTYPE(t1, t2)    pair<t1, t2>

// Used to bypass the rule against non-const reference to temporary
// where it makes sense with wrappers such as CFlatData or CTxDB
template<typename T>
inline T& REF(const T& val)
{
    return (T&)val;
}









extern bool fDebug;

// ---------------------------------------------------------------------------
// Categorized, burst-collapsing logging
//
// Plain printf() (routed to OutputDebugStringF below) writes every call
// unfiltered to debug.log. That's fine for one-off events, but a loop that
// logs once per item -- once per discovered peer, once per connect attempt,
// once per share -- turns debug.log into a wall of near-identical lines that
// differ only by an address, while the line that actually explains a stuck
// flow ("Stratum: no job available for ...") scrolls off screen under the
// noise. LogPrint() is a drop-in replacement for printf() that fixes both
// problems without touching call sites' formatting:
//
//   1. Category tag: every call names the subsystem it belongs to ("pool",
//      "worker", "payout", "net", "nostr", ...). LogAcceptsCategory()
//      controls what's written (see util.cpp); the pool/worker/payout flow
//      the person actually needs visibility into is on by default.
//   2. Burst collapse: repeated LogPrint() calls from the *same source line*
//      only emit one line per DEDUP_WINDOW_SECS; if more calls land inside
//      that window they're counted instead of reprinted, and the count is
//      flushed as a single "(xN similar in Ws)" line the moment the window
//      rolls over. A loop discovering 500 peers by address now produces a
//      small, bounded number of lines instead of 500 -- log growth is capped
//      by elapsed time, not by how many similar events happen to fire.
// ---------------------------------------------------------------------------
bool LogAcceptsCategory(const char* category);
void LogPrintDedup(const char* category, const char* file, int line, const std::string& msg);
#define LogPrint(category, ...) \
    do { if (LogAcceptsCategory(category)) LogPrintDedup((category), __FILE__, __LINE__, strprintf(__VA_ARGS__)); } while (0)

// Every format string in this project goes through one of the four functions
// below -- `printf` itself is remapped to OutputDebugStringF just above, and
// snprintf to my_snprintf. None of them carried a format attribute, and GCC
// only checks format strings for functions it knows are printf-like, so
// -Wformat had nothing to inspect and the whole tree was unchecked. That is
// how `%I64d` (MSVC-only, and a segfault on glibc) survived in
// CTxOut::ToString until it crashed a node mid-sync -- see issue #5.
//
// gnu_printf on both platforms, deliberately. MinGW's other option, ms_printf,
// models the legacy msvcrt: it rejects %zu, which this tree uses and UCRT
// supports, and it accepts %I64d, which is the specifier that crashes on glibc.
// It would give false positives where the code is right and stay silent where it
// is dangerous. gnu_printf describes UCRT's C99 behaviour accurately, so one
// archetype covers both builds and a bad specifier fails either one.
#if defined(__GNUC__)
#define BF_FORMAT(fmt, args) __attribute__((format(gnu_printf, fmt, args)))
#else
#define BF_FORMAT(fmt, args)
#endif

void RandAddSeed(bool fPerfmon=false);
int my_snprintf(char* buffer, size_t limit, const char* format, ...) BF_FORMAT(3, 4);
string strprintf(const char* format, ...) BF_FORMAT(1, 2);
bool error(const char* format, ...) BF_FORMAT(1, 2);
void PrintException(std::exception* pex, const char* pszThread);
void ParseString(const string& str, char c, vector<string>& v);
string FormatMoney(int64 n, bool fPlus=false);
bool ParseMoney(const char* pszIn, int64& nRet);
bool FileExists(const char* psz);
int GetFilesize(FILE* file);
uint64 GetRand(uint64 nMax);
int64 GetTime();
int64 GetAdjustedTime();
void AddTimeData(unsigned int ip, int64 nTime);












// Wrapper to automatically initialize critical section
// Could use wxCriticalSection for portability, but it doesn't support TryEnterCriticalSection
class CCriticalSection
{
protected:
    CRITICAL_SECTION cs;
public:
    char* pszFile;
    int nLine;
    explicit CCriticalSection() { InitializeCriticalSection(&cs); }
    ~CCriticalSection() { DeleteCriticalSection(&cs); }
    void Enter() { EnterCriticalSection(&cs); }
    void Leave() { LeaveCriticalSection(&cs); }
    bool TryEnter() { return TryEnterCriticalSection(&cs); }
    CRITICAL_SECTION* operator&() { return &cs; }
};

// Automatically leave critical section when leaving block, needed for exception safety
class CCriticalBlock
{
protected:
    CRITICAL_SECTION* pcs;
public:
    CCriticalBlock(CRITICAL_SECTION& csIn) { pcs = &csIn; EnterCriticalSection(pcs); }
    CCriticalBlock(CCriticalSection& csIn) { pcs = &csIn; EnterCriticalSection(pcs); }
    ~CCriticalBlock() { LeaveCriticalSection(pcs); }
};

// WARNING: This will catch continue and break!
// break is caught with an assertion, but there's no way to detect continue.
// I'd rather be careful than suffer the other more error prone syntax.
// The compiler will optimise away all this loop junk.
#define CRITICAL_BLOCK(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by CRITICAL_BLOCK!", !fcriticalblockonce)), fcriticalblockonce=false)  \
    for (CCriticalBlock criticalblock(cs); fcriticalblockonce && (cs.pszFile=__FILE__, cs.nLine=__LINE__, true); fcriticalblockonce=false, cs.pszFile=NULL, cs.nLine=0)

class CTryCriticalBlock
{
protected:
    CRITICAL_SECTION* pcs;
public:
    CTryCriticalBlock(CRITICAL_SECTION& csIn) { pcs = (TryEnterCriticalSection(&csIn) ? &csIn : NULL); }
    CTryCriticalBlock(CCriticalSection& csIn) { pcs = (TryEnterCriticalSection(&csIn) ? &csIn : NULL); }
    ~CTryCriticalBlock() { if (pcs) LeaveCriticalSection(pcs); }
    bool Entered() { return pcs != NULL; }
};

#define TRY_CRITICAL_BLOCK(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by TRY_CRITICAL_BLOCK!", !fcriticalblockonce)), fcriticalblockonce=false)  \
    for (CTryCriticalBlock criticalblock(cs); fcriticalblockonce && (fcriticalblockonce = criticalblock.Entered()) && (cs.pszFile=__FILE__, cs.nLine=__LINE__, true); fcriticalblockonce=false, cs.pszFile=NULL, cs.nLine=0)












inline string i64tostr(int64 n)
{
    return strprintf("%" PRId64, n);
}

inline string itostr(int n)
{
    return strprintf("%d", n);
}

inline int64 atoi64(const char* psz)
{
#ifdef _MSC_VER
    return _atoi64(psz);
#else
    return strtoll(psz, NULL, 10);
#endif
}

inline int64 atoi64(const string& str)
{
#ifdef _MSC_VER
    return _atoi64(str.c_str());
#else
    return strtoll(str.c_str(), NULL, 10);
#endif
}

inline int atoi(const string& str)
{
    return atoi(str.c_str());
}

inline int roundint(double d)
{
    return (int)(d > 0 ? d + 0.5 : d - 0.5);
}

template<typename T>
string HexStr(const T itbegin, const T itend, bool fSpaces=true)
{
    const unsigned char* pbegin = (const unsigned char*)&itbegin[0];
    const unsigned char* pend = pbegin + (itend - itbegin) * sizeof(itbegin[0]);
    string str;
    for (const unsigned char* p = pbegin; p != pend; p++)
        str += strprintf((fSpaces && p != pend-1 ? "%02x " : "%02x"), *p);
    return str;
}

template<typename T>
string HexNumStr(const T itbegin, const T itend, bool f0x=true)
{
    const unsigned char* pbegin = (const unsigned char*)&itbegin[0];
    const unsigned char* pend = pbegin + (itend - itbegin) * sizeof(itbegin[0]);
    string str = (f0x ? "0x" : "");
    for (const unsigned char* p = pend-1; p >= pbegin; p--)
        str += strprintf("%02X", *p);
    return str;
}

template<typename T>
void PrintHex(const T pbegin, const T pend, const char* pszFormat="%s", bool fSpaces=true)
{
    printf(pszFormat, HexStr(pbegin, pend, fSpaces).c_str());
}








// Forward declaration -- defined in main.cpp
string GetAppDir();

// Give a command-line operation somewhere to print.
//
// The Windows binary is linked -mwindows and starts with no console, so stdout
// goes nowhere even when it was launched from a terminal. Commands that report
// to the person who typed them -- the self-tests, the wallet phrase commands --
// call this first.
//
// Only when there is nowhere for stdout to go already: if the caller redirected
// it to a file or a pipe, that handle is inherited and works, and reopening it
// on CONOUT$ would take the output away from the file and put it on the screen.
inline void AttachTerminal()
{
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != NULL && hOut != INVALID_HANDLE_VALUE)
        return;
    if (AttachConsole(ATTACH_PARENT_PROCESS))
    {
        // Return values ignored on purpose: if the reopen fails there is
        // nowhere left to report it, and the exit status still carries the
        // result.
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }
#endif
}

inline int OutputDebugStringF(const char* pszFormat, ...) BF_FORMAT(1, 2);

inline int OutputDebugStringF(const char* pszFormat, ...)
{
#if 1 // debug.log always enabled
    // Write to data directory so it's always findable.
    //
    // Path resolution and the write are both under the lock, because neither
    // used to be under anything. strDebugFile was filled in lazily inside an
    // `if (empty())`, so one thread could read the path while another was
    // still assigning to it -- and at startup three threads log within
    // milliseconds of each other. When that raced, fopen got a torn path,
    // returned NULL, and the `if (fileout)` below dropped the line silently.
    // Measured before this change: unconditional first-statement printfs in
    // ThreadBtfAccept, ThreadNostrSeed and the cached-peer thread reached the
    // file in only 4/6, 5/6 and 2/6 of runs respectively. Concluding a thread
    // never ran because its line was absent was not sound, and the lock also
    // stops several threads calling fopen on the same file at once.
    static CCriticalSection cs_debugFile;
    CRITICAL_BLOCK(cs_debugFile)
    {
        static string strDebugFile;
        if (strDebugFile.empty()) {
            string dir = GetAppDir();
            if (!dir.empty())
                strDebugFile = dir +
#ifdef _WIN32
                    "\\"
#else
                    "/"
#endif
                    + "debug.log";
            else
                strDebugFile = "debug.log";
        }
        FILE* fileout = fopen(strDebugFile.c_str(), "a");
        if (fileout)
        {
            va_list arg_ptr;
            va_start(arg_ptr, pszFormat);
            vfprintf(fileout, pszFormat, arg_ptr);
            va_end(arg_ptr);
            fclose(fileout);
        }
    }

#ifndef _WIN32
    // Headless build: also echo to the console (the Windows path below returns
    // early before reaching the console print, which is fine for the GUI app).
    {
        va_list arg_ptr;
        va_start(arg_ptr, pszFormat);
        vprintf(pszFormat, arg_ptr);
        va_end(arg_ptr);
        fflush(stdout);
    }
#endif

    // accumulate a line at a time
    static CCriticalSection cs_OutputDebugStringF;
    CRITICAL_BLOCK(cs_OutputDebugStringF)
    {
        static char pszBuffer[50000];
        static char* pend;
        if (pend == NULL)
            pend = pszBuffer;
        va_list arg_ptr;
        va_start(arg_ptr, pszFormat);
        int limit = END(pszBuffer) - pend - 2;
        int ret = _vsnprintf(pend, limit, pszFormat, arg_ptr);
        va_end(arg_ptr);
        if (ret < 0 || ret >= limit)
        {
            pend = END(pszBuffer) - 2;
            *pend++ = '\n';
        }
        else
            pend += ret;
        *pend = '\0';
        char* p1 = pszBuffer;
        char* p2;
        while (p2 = strchr(p1, '\n'))
        {
            p2++;
            char c = *p2;
            *p2 = '\0';
            OutputDebugStringA(p1);
            *p2 = c;
            p1 = p2;
        }
        if (p1 != pszBuffer)
            memmove(pszBuffer, p1, pend - p1 + 1);
        pend -= (p1 - pszBuffer);
        return ret;
    }
#endif

    va_list arg_ptr;
    va_start(arg_ptr, pszFormat);
    vprintf(pszFormat, arg_ptr);
    va_end(arg_ptr);
    return 0;
}









inline void heapchk()
{
    if (_heapchk() != _HEAPOK)
        DebugBreak();
}

// Randomize the stack to help protect against buffer overrun exploits
#define IMPLEMENT_RANDOMIZE_STACK(ThreadFn)                         \
    {                                                               \
        static char nLoops;                                         \
        if (nLoops <= 0)                                            \
            nLoops = GetRand(50) + 1;                               \
        if (nLoops-- > 1)                                           \
        {                                                           \
            ThreadFn;                                               \
            return;                                                 \
        }                                                           \
    }

// The forced-unwind arm has to come first, and it has to rethrow.
//
// On POSIX, _endthread() is pthread_exit(), and glibc implements that by
// throwing abi::__forced_unwind through the stack. It is not a real exception
// and catching it without rethrowing is a fatal error by contract: glibc
// notices and calls abort().
//
// The bare catch(...) below did exactly that. Every shutdown on Linux died with
//
//     UNKNOWN EXCEPTION  bitflash-node in ThreadSocketHandler()
//     FATAL: exception not rethrown
//
// which looked like nothing worse than an ugly exit, and was not: the process
// aborted partway through shutting down, so nothing after StopNode() ran. See
// main_gui.cpp, where DBFlush(true) is now called -- it could never have
// worked while this abort stood in front of it. Windows is unaffected; there
// _endthread() is the CRT's and unwinds nothing.
#ifdef _WIN32
#define CATCH_FORCED_UNWIND
#else
#define CATCH_FORCED_UNWIND              \
    catch (abi::__forced_unwind&) {      \
        throw;                           \
    }
#endif

#define CATCH_PRINT_EXCEPTION(pszFn)     \
    CATCH_FORCED_UNWIND                  \
    catch (std::exception& e) {          \
        PrintException(&e, (pszFn));     \
    } catch (...) {                      \
        PrintException(NULL, (pszFn));   \
    }









template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    uint256 hash1;
    SHA256((unsigned char*)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Update(&ctx, (unsigned char*)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=VERSION)
{
    // Most of the time is spent allocating and deallocating CDataStream's
    // buffer.  If this ever needs to be optimized further, make a CStaticStream
    // class with its buffer on the stack.
    CDataStream ss(nType, nVersion);
    ss.reserve(10000);
    ss << obj;
    return Hash(ss.begin(), ss.end());
}

inline uint160 Hash160(const vector<unsigned char>& vch)
{
    uint256 hash1;
    SHA256(&vch[0], vch.size(), (unsigned char*)&hash1);
    uint160 hash2;
    RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}
