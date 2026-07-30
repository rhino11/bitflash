// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"



bool fDebug = false;

// ---------------------------------------------------------------------------
// Categorized, burst-collapsing logging -- see the LogPrint doc comment in
// util.h for the problem this solves.
// ---------------------------------------------------------------------------

// Categories that explain the pool/worker/payout pipeline are on unconditionally:
// silence there is exactly the "worker stuck, nothing then happens" complaint
// this exists to fix, so it can't be opted out of by forgetting -debug.
// "net" and "nostr" cover the per-address connection/discovery chatter that
// used to dominate debug.log; they're gated behind fDebug like the printf()
// calls they replace, so default output stays quiet unless requested.
static bool LogCategoryDefaultOn(const char* category)
{
    return strcmp(category, "pool")   == 0 ||
           strcmp(category, "worker") == 0 ||
           strcmp(category, "payout") == 0;
}

bool LogAcceptsCategory(const char* category)
{
    if (LogCategoryDefaultOn(category))
        return true;
    return fDebug;
}

// Only collapse bursts from the exact same call site within this window;
// a different LogPrint() call (different file/line) is never merged with
// this one, so unrelated messages never get mixed into one summary.
static const int64 DEDUP_WINDOW_SECS = 3;

struct LogDedupState {
    int64       windowStart;   // GetTime() when the current window opened
    int         suppressed;    // calls swallowed so far this window
    std::string lastMsg;       // most recent message text, for the summary line
};

static std::map<std::string, LogDedupState> g_logDedup;
static CCriticalSection cs_logDedup;

void LogPrintDedup(const char* category, const char* file, int line, const std::string& msgIn)
{
    // Call sites follow the existing printf() convention of ending their
    // format string with \n; strip it here so the single \n this function
    // adds below doesn't turn into a blank line.
    std::string msg = msgIn;
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
        msg.pop_back();

    char key[512];
    my_snprintf(key, sizeof(key), "%s|%s:%d", category, file, line);

    int64 now = GetTime();
    bool  fEmitNow = false;
    int   suppressedToFlush = 0;
    std::string flushedMsg;

    CRITICAL_BLOCK(cs_logDedup)
    {
        std::map<std::string, LogDedupState>::iterator it = g_logDedup.find(key);
        if (it == g_logDedup.end())
        {
            // First time this call site has fired (or its last window is long
            // gone) -- print it directly and open a fresh window.
            g_logDedup[key] = LogDedupState{now, 0, msg};
            fEmitNow = true;
        }
        else if (now - it->second.windowStart >= DEDUP_WINDOW_SECS)
        {
            // Window rolled over: flush what was suppressed during it (if
            // anything), then start a new window with this call printed.
            suppressedToFlush = it->second.suppressed;
            flushedMsg = it->second.lastMsg;
            it->second.windowStart = now;
            it->second.suppressed  = 0;
            it->second.lastMsg     = msg;
            fEmitNow = true;
        }
        else
        {
            // Still inside the window and already printed one line for it:
            // count this occurrence instead of writing another near-duplicate.
            it->second.suppressed++;
            it->second.lastMsg = msg;
        }
    }

    if (suppressedToFlush > 0)
        OutputDebugStringF("[%s] (%d similar in %llds, last: %s)\n",
                            category, suppressedToFlush, (long long)DEDUP_WINDOW_SECS, flushedMsg.c_str());
    if (fEmitNow)
        OutputDebugStringF("[%s] %s\n", category, msg.c_str());
}




#ifdef _WIN32
// Init openssl library multithreading support (OpenSSL < 1.1 needed callbacks;
// OpenSSL 1.1+/3 is internally thread-safe, so the Linux build skips this).
static HANDLE* lock_cs;

void win32_locking_callback(int mode, int type, const char* file, int line)
{
    if (mode & CRYPTO_LOCK)
        WaitForSingleObject(lock_cs[type], INFINITE);
    else
        ReleaseMutex(lock_cs[type]);
}
#endif

// Init
class CInit
{
public:
    CInit()
    {
#ifdef _WIN32
        // Init openssl library multithreading support
        lock_cs = (HANDLE*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            lock_cs[i] = CreateMutex(NULL,FALSE,NULL);
        CRYPTO_set_locking_callback(win32_locking_callback);

        // Seed random number generator with screen scrape and other hardware sources
        RAND_screen();
#endif
        // Seed random number generator with perfmon / high-res timer data
        RandAddSeed(true);
    }
    ~CInit()
    {
#ifdef _WIN32
        // Shutdown openssl library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i =0 ; i < CRYPTO_num_locks(); i++)
            CloseHandle(lock_cs[i]);
        OPENSSL_free(lock_cs);
#endif
    }
}
instance_of_cinit;




void RandAddSeed(bool fPerfmon)
{
#ifdef _WIN32
    // Seed with CPU performance counter
    LARGE_INTEGER PerformanceCount;
    QueryPerformanceCounter(&PerformanceCount);
    RAND_add(&PerformanceCount, sizeof(PerformanceCount), 1.5);
    memset(&PerformanceCount, 0, sizeof(PerformanceCount));

    static int64 nLastPerfmon;
    if (fPerfmon || GetTime() > nLastPerfmon + 5 * 60)
    {
        nLastPerfmon = GetTime();

        // Seed with the entire set of perfmon data
        unsigned char pdata[250000];
        memset(pdata, 0, sizeof(pdata));
        unsigned long nSize = sizeof(pdata);
        long ret = RegQueryValueEx(HKEY_PERFORMANCE_DATA, "Global", NULL, NULL, pdata, &nSize);
        RegCloseKey(HKEY_PERFORMANCE_DATA);
        if (ret == ERROR_SUCCESS)
        {
            uint256 hash;
            SHA256(pdata, nSize, (unsigned char*)&hash);
            RAND_add(&hash, sizeof(hash), min(nSize/500.0, (double)sizeof(hash)));
            hash = 0;
            memset(pdata, 0, nSize);
            printf("RandAddSeed() got %lu bytes of performance data\n", nSize);
        }
    }
#else
    // Seed with a high-resolution timer; OpenSSL also seeds itself from
    // /dev/urandom, so this is just extra entropy. No perfmon on Linux.
    (void)fPerfmon;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    RAND_add(&ts, sizeof(ts), 1.5);
    memset(&ts, 0, sizeof(ts));
#endif
}










// Safer snprintf
//  - prints up to limit-1 characters
//  - output string is always null terminated even if limit reached
//  - return value is the number of characters actually printed
int my_snprintf(char* buffer, size_t limit, const char* format, ...)
{
    if (limit == 0)
        return 0;
    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnprintf(buffer, limit, format, arg_ptr);
    va_end(arg_ptr);
    if (ret < 0 || ret >= limit)
    {
        ret = limit - 1;
        buffer[limit-1] = 0;
    }
    return ret;
}


string strprintf(const char* format, ...)
{
    char buffer[50000];
    char* p = buffer;
    int limit = sizeof(buffer);
    int ret;
    loop
    {
        va_list arg_ptr;
        va_start(arg_ptr, format);
        ret = _vsnprintf(p, limit, format, arg_ptr);
        va_end(arg_ptr);
        if (ret >= 0 && ret < limit)
            break;
        if (p != buffer)
            delete p;
        limit *= 2;
        p = new char[limit];
        if (p == NULL)
            throw std::bad_alloc();
    }
#ifdef _MSC_VER
    // msvc optimisation
    if (p == buffer)
        return string(p, p+ret);
#endif
    string str(p, p+ret);
    if (p != buffer)
        delete p;
    return str;
}


bool error(const char* format, ...)
{
    char buffer[50000];
    int limit = sizeof(buffer);
    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnprintf(buffer, limit, format, arg_ptr);
    va_end(arg_ptr);
    if (ret < 0 || ret >= limit)
    {
        ret = limit - 1;
        buffer[limit-1] = 0;
    }
    printf("ERROR: %s\n", buffer);
    return false;
}


void PrintException(std::exception* pex, const char* pszThread)
{
    char pszModule[260];
    pszModule[0] = '\0';
#ifdef _WIN32
    GetModuleFileName(NULL, pszModule, sizeof(pszModule));
    _strlwr(pszModule);
#else
    strncpy(pszModule, "bitflash-node", sizeof(pszModule) - 1);
#endif
    char pszMessage[1000];
    if (pex)
        snprintf(pszMessage, sizeof(pszMessage),
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        snprintf(pszMessage, sizeof(pszMessage),
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
    printf("\n\n************************\n%s", pszMessage);
    // Do NOT rethrow here. Every caller of PrintException (via
    // CATCH_PRINT_EXCEPTION) is a thread wrapped in its own
    // "try { ThreadFoo2() } catch(...) { log, sleep, loop again }" self-healing
    // retry loop -- that's the whole point of the wrapper. Rethrowing from
    // inside that catch block escapes the retry loop entirely (nothing above
    // it in the thread catches it) and takes down the whole process with
    // std::terminate() on the very first transient error -- a flaky relay
    // connection, a malformed message, anything -- instead of letting the
    // thread log it, sleep 5s, and try again like it's designed to.
    // Show error in GUI via repaint signal -- GUI polls g_errorMessage
}


void ParseString(const string& str, char c, vector<string>& v)
{
    unsigned int i1 = 0;
    unsigned int i2;
    do
    {
        i2 = str.find(c, i1);
        v.push_back(str.substr(i1, i2-i1));
        i1 = i2+1;
    }
    while (i2 != str.npos);
}


string FormatMoney(int64 n, bool fPlus)
{
    n /= CENT;
    string str = strprintf("%lld.%02lld", (n > 0 ? n : -n)/100, (n > 0 ? n : -n)%100);
    for (int i = 6; i < str.size(); i += 4)
        if (isdigit(str[str.size() - i - 1]))
            str.insert(str.size() - i, 1, ',');
    if (n < 0)
        str.insert((unsigned int)0, 1, '-');
    else if (fPlus && n > 0)
        str.insert((unsigned int)0, 1, '+');
    return str;
}

bool ParseMoney(const char* pszIn, int64& nRet)
{
    string strWhole;
    int64 nCents = 0;
    const char* p = pszIn;
    while (isspace(*p))
        p++;
    for (; *p; p++)
    {
        if (*p == ',' && p > pszIn && isdigit(p[-1]) && isdigit(p[1]) && isdigit(p[2]) && isdigit(p[3]) && !isdigit(p[4]))
            continue;
        if (*p == '.')
        {
            p++;
            if (!isdigit(p[0]) || !isdigit(p[1]))
                return false;
            nCents = atoi64(p);
            if (nCents < 0 || nCents > 99)
                return false;
            p += 2;
            break;
        }
        if (isspace(*p))
            break;
        if (!isdigit(*p))
            return false;
        strWhole.insert(strWhole.end(), *p);
    }
    for (; *p; p++)
        if (!isspace(*p))
            return false;
    if (strWhole.size() > 17)
        return false;
    int64 nWhole = atoi64(strWhole);
    int64 nValue = nWhole * 100 + nCents;
    if (nValue / 100 != nWhole)
        return false;
    nValue *= CENT;
    nRet = nValue;
    return true;
}










bool FileExists(const char* psz)
{
#ifdef WIN32
    return GetFileAttributes(psz) != -1;
#else
    return access(psz, 0) != -1;
#endif
}

int GetFilesize(FILE* file)
{
    int nSavePos = ftell(file);
    int nFilesize = -1;
    if (fseek(file, 0, SEEK_END) == 0)
        nFilesize = ftell(file);
    fseek(file, nSavePos, SEEK_SET);
    return nFilesize;
}








uint64 GetRand(uint64 nMax)
{
    if (nMax == 0)
        return 0;

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    uint64 nRange = (_UI64_MAX / nMax) * nMax;
    uint64 nRand = 0;
    do
        RAND_bytes((unsigned char*)&nRand, sizeof(nRand));
    while (nRand >= nRange);
    return (nRand % nMax);
}










//
// "Never go to sea with two chronometers; take one or three."
// Our three chronometers are:
//  - System clock
//  - Median of other server's clocks
//  - NTP servers
//
// note: NTP isn't implemented yet, so until then we just use the median
//  of other nodes clocks to correct ours.
//

int64 GetTime()
{
    return time(NULL);
}

static int64 nTimeOffset = 0;

int64 GetAdjustedTime()
{
    return GetTime() + nTimeOffset;
}

void AddTimeData(unsigned int ip, int64 nTime)
{
    int64 nOffsetSample = nTime - GetTime();

    // Ignore duplicates
    static set<unsigned int> setKnown;
    if (!setKnown.insert(ip).second)
        return;

    // Add data
    static vector<int64> vTimeOffsets;
    if (vTimeOffsets.empty())
        vTimeOffsets.push_back(0);
    vTimeOffsets.push_back(nOffsetSample);
    printf("Added time data, samples %d, ip %08x, offset %+lld (%+lld minutes)\n", (int)vTimeOffsets.size(), ip, vTimeOffsets.back(), vTimeOffsets.back()/60);
    if (vTimeOffsets.size() >= 5 && vTimeOffsets.size() % 2 == 1)
    {
        sort(vTimeOffsets.begin(), vTimeOffsets.end());
        int64 nMedian = vTimeOffsets[vTimeOffsets.size()/2];
        nTimeOffset = nMedian;
        if ((nMedian > 0 ? nMedian : -nMedian) > 5 * 60)
        {
            // Only let other nodes change our clock so far before we
            // go to the NTP servers
            /// todo: Get time from NTP servers, then set a flag
            ///    to make sure it doesn't get changed again
        }
        foreach(int64 n, vTimeOffsets)
            printf("%+lld  ", n);
        printf("|  nTimeOffset = %+lld  (%+lld minutes)\n", nTimeOffset, nTimeOffset/60);
    }
}

// Formats a block or transaction timestamp for logs and for the wallet view.
// It lived in gui.cpp, but main.cpp logs block times with it, so a headless
// build needed it too -- and nothing about formatting a date is GUI work.
string DateTimeStr(int64 nTime)
{
    time_t t = (time_t)nTime;
    struct tm* p = localtime(&t);
    if (!p) return "";
    char buf[32]; strftime(buf, sizeof(buf), "%m/%d/%y %H:%M", p);
    return buf;
}
