// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "wallet_sqlite.h"

static void SetSQLiteError(sqlite3* pdb, const string& strContext,
                           string& strError)
{
    if (pdb)
        strError = strContext + ": " + sqlite3_errmsg(pdb);
    else
        strError = strContext;
}

CWalletDBSQLite::CWalletDBSQLite() : pdb(NULL)
{
}

CWalletDBSQLite::~CWalletDBSQLite()
{
    Close();
}

bool CWalletDBSQLite::Open(const string& strPath, string& strError)
{
    Close();

    int ret = sqlite3_open_v2(strPath.c_str(), &pdb,
                              SQLITE_OPEN_READWRITE |
                              SQLITE_OPEN_CREATE |
                              SQLITE_OPEN_FULLMUTEX,
                              NULL);
    if (ret != SQLITE_OK)
    {
        SetSQLiteError(pdb, "cannot open SQLite wallet", strError);
        Close();
        return false;
    }

    sqlite3_busy_timeout(pdb, 5000);

    if (!Exec("PRAGMA journal_mode=WAL;", strError))
    {
        Close();
        return false;
    }
    if (!Exec("PRAGMA synchronous=FULL;", strError))
    {
        Close();
        return false;
    }
    if (!InitSchema(strError))
    {
        Close();
        return false;
    }
    return true;
}

bool CWalletDBSQLite::OpenReadOnly(const string& strPath, string& strError)
{
    Close();

    int ret = sqlite3_open_v2(strPath.c_str(), &pdb,
                              SQLITE_OPEN_READONLY |
                              SQLITE_OPEN_FULLMUTEX,
                              NULL);
    if (ret != SQLITE_OK)
    {
        SetSQLiteError(pdb, "cannot open SQLite wallet read-only", strError);
        Close();
        return false;
    }

    sqlite3_busy_timeout(pdb, 5000);
    return true;
}

void CWalletDBSQLite::Close()
{
    if (pdb)
    {
        sqlite3_close(pdb);
        pdb = NULL;
    }
}

bool CWalletDBSQLite::BeginTransaction(string& strError)
{
    if (!pdb)
    {
        strError = "SQLite wallet is not open";
        return false;
    }
    return Exec("BEGIN IMMEDIATE;", strError);
}

bool CWalletDBSQLite::CommitTransaction(string& strError)
{
    if (!pdb)
    {
        strError = "SQLite wallet is not open";
        return false;
    }
    return Exec("COMMIT;", strError);
}

bool CWalletDBSQLite::RollbackTransaction(string& strError)
{
    if (!pdb)
    {
        strError = "SQLite wallet is not open";
        return false;
    }
    return Exec("ROLLBACK;", strError);
}

bool CWalletDBSQLite::Checkpoint(string& strError)
{
    if (!pdb)
    {
        strError = "SQLite wallet is not open";
        return false;
    }
    return Exec("PRAGMA wal_checkpoint(TRUNCATE);", strError);
}

bool CWalletDBSQLite::Exec(const char* pszSql, string& strError)
{
    char* pszErr = NULL;
    int ret = sqlite3_exec(pdb, pszSql, NULL, NULL, &pszErr);
    if (ret != SQLITE_OK)
    {
        if (pszErr)
        {
            strError = pszErr;
            sqlite3_free(pszErr);
        }
        else
            SetSQLiteError(pdb, "SQLite exec failed", strError);
        return false;
    }
    return true;
}

bool CWalletDBSQLite::InitSchema(string& strError)
{
    return Exec("CREATE TABLE IF NOT EXISTS wallet_records ("
                "key BLOB PRIMARY KEY NOT NULL,"
                "value BLOB NOT NULL"
                ");",
                strError) &&
           Exec("PRAGMA user_version=1;", strError);
}

bool CWalletDBSQLite::WriteRecord(const vector<unsigned char>& vchKey,
                                  const vector<unsigned char>& vchValue,
                                  string& strError,
                                  bool fOverwrite)
{
    if (!pdb)
    {
        strError = "SQLite wallet is not open";
        return false;
    }
    if (vchKey.empty())
    {
        strError = "SQLite wallet record key is empty";
        return false;
    }

    sqlite3_stmt* stmt = NULL;
    const char* pszSql = fOverwrite
        ? "INSERT OR REPLACE INTO wallet_records(key, value) VALUES(?, ?);"
        : "INSERT INTO wallet_records(key, value) VALUES(?, ?);";
    int ret = sqlite3_prepare_v2(pdb, pszSql, -1, &stmt, NULL);
    if (ret != SQLITE_OK)
    {
        SetSQLiteError(pdb, "cannot prepare SQLite wallet write", strError);
        return false;
    }

    ret = sqlite3_bind_blob(stmt, 1, &vchKey[0], (int)vchKey.size(),
                            SQLITE_TRANSIENT);
    if (ret == SQLITE_OK)
        ret = sqlite3_bind_blob(stmt, 2,
                                vchValue.empty() ? NULL : &vchValue[0],
                                (int)vchValue.size(),
                                SQLITE_TRANSIENT);
    if (ret == SQLITE_OK)
        ret = sqlite3_step(stmt);

    bool fOk = (ret == SQLITE_DONE);
    if (!fOk)
        SetSQLiteError(pdb, "cannot write SQLite wallet record", strError);
    sqlite3_finalize(stmt);
    return fOk;
}

bool CWalletDBSQLite::ReadRecord(const vector<unsigned char>& vchKey,
                                 vector<unsigned char>& vchValueRet,
                                 string& strError)
{
    vchValueRet.clear();
    if (!pdb)
    {
        strError = "SQLite wallet is not open";
        return false;
    }
    if (vchKey.empty())
    {
        strError = "SQLite wallet record key is empty";
        return false;
    }

    sqlite3_stmt* stmt = NULL;
    const char* pszSql = "SELECT value FROM wallet_records WHERE key = ?;";
    int ret = sqlite3_prepare_v2(pdb, pszSql, -1, &stmt, NULL);
    if (ret != SQLITE_OK)
    {
        SetSQLiteError(pdb, "cannot prepare SQLite wallet read", strError);
        return false;
    }

    ret = sqlite3_bind_blob(stmt, 1, &vchKey[0], (int)vchKey.size(),
                            SQLITE_TRANSIENT);
    if (ret != SQLITE_OK)
    {
        SetSQLiteError(pdb, "cannot bind SQLite wallet key", strError);
        sqlite3_finalize(stmt);
        return false;
    }

    ret = sqlite3_step(stmt);
    if (ret == SQLITE_ROW)
    {
        const unsigned char* pch =
            (const unsigned char*)sqlite3_column_blob(stmt, 0);
        int nBytes = sqlite3_column_bytes(stmt, 0);
        if (nBytes > 0 && pch)
            vchValueRet.assign(pch, pch + nBytes);
        sqlite3_finalize(stmt);
        return true;
    }

    if (ret == SQLITE_DONE)
        strError = "SQLite wallet record not found";
    else
        SetSQLiteError(pdb, "cannot read SQLite wallet record", strError);
    sqlite3_finalize(stmt);
    return false;
}

bool CWalletDBSQLite::EraseRecord(const vector<unsigned char>& vchKey,
                                  string& strError)
{
    if (!pdb)
    {
        strError = "SQLite wallet is not open";
        return false;
    }
    if (vchKey.empty())
    {
        strError = "SQLite wallet record key is empty";
        return false;
    }

    sqlite3_stmt* stmt = NULL;
    const char* pszSql = "DELETE FROM wallet_records WHERE key = ?;";
    int ret = sqlite3_prepare_v2(pdb, pszSql, -1, &stmt, NULL);
    if (ret != SQLITE_OK)
    {
        SetSQLiteError(pdb, "cannot prepare SQLite wallet erase", strError);
        return false;
    }

    ret = sqlite3_bind_blob(stmt, 1, &vchKey[0], (int)vchKey.size(),
                            SQLITE_TRANSIENT);
    if (ret == SQLITE_OK)
        ret = sqlite3_step(stmt);

    bool fOk = (ret == SQLITE_DONE);
    if (!fOk)
        SetSQLiteError(pdb, "cannot erase SQLite wallet record", strError);
    sqlite3_finalize(stmt);
    return fOk;
}

bool CWalletDBSQLite::ScanRecords(CWalletRecordVisitor& visitor,
                                  string& strError)
{
    if (!pdb)
    {
        strError = "SQLite wallet is not open";
        return false;
    }

    sqlite3_stmt* stmt = NULL;
    const char* pszSql = "SELECT key, value FROM wallet_records ORDER BY rowid;";
    int ret = sqlite3_prepare_v2(pdb, pszSql, -1, &stmt, NULL);
    if (ret != SQLITE_OK)
    {
        SetSQLiteError(pdb, "cannot prepare SQLite wallet scan", strError);
        return false;
    }

    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        const unsigned char* pchKey =
            (const unsigned char*)sqlite3_column_blob(stmt, 0);
        int nKeyBytes = sqlite3_column_bytes(stmt, 0);
        const unsigned char* pchValue =
            (const unsigned char*)sqlite3_column_blob(stmt, 1);
        int nValueBytes = sqlite3_column_bytes(stmt, 1);

        vector<unsigned char> vchKey;
        vector<unsigned char> vchValue;
        if (nKeyBytes > 0 && pchKey)
            vchKey.assign(pchKey, pchKey + nKeyBytes);
        if (nValueBytes > 0 && pchValue)
            vchValue.assign(pchValue, pchValue + nValueBytes);

        CDataStream ssKey(vchKey, SER_DISK);
        CDataStream ssValue(vchValue, SER_DISK);
        if (!visitor.VisitWalletRecord(ssKey, ssValue, strError))
        {
            sqlite3_finalize(stmt);
            return false;
        }
    }

    if (ret != SQLITE_DONE)
    {
        SetSQLiteError(pdb, "cannot scan SQLite wallet records", strError);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

bool CWalletDBSQLite::CountRecords(int& nRecordsRet, string& strError)
{
    nRecordsRet = 0;
    if (!pdb)
    {
        strError = "SQLite wallet is not open";
        return false;
    }

    sqlite3_stmt* stmt = NULL;
    int ret = sqlite3_prepare_v2(pdb,
                                 "SELECT COUNT(*) FROM wallet_records;",
                                 -1, &stmt, NULL);
    if (ret != SQLITE_OK)
    {
        SetSQLiteError(pdb, "cannot prepare SQLite wallet count", strError);
        return false;
    }

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_ROW)
    {
        SetSQLiteError(pdb, "cannot count SQLite wallet records", strError);
        sqlite3_finalize(stmt);
        return false;
    }

    nRecordsRet = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return true;
}
