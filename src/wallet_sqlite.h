// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#ifndef BITFLASH_WALLET_SQLITE_H
#define BITFLASH_WALLET_SQLITE_H

#include <sqlite3.h>

class CWalletDBSQLite
{
public:
    CWalletDBSQLite();
    ~CWalletDBSQLite();

    bool Open(const string& strPath, string& strError);
    void Close();

    bool BeginTransaction(string& strError);
    bool CommitTransaction(string& strError);
    bool RollbackTransaction(string& strError);
    bool Checkpoint(string& strError);

    bool WriteRecord(const vector<unsigned char>& vchKey,
                     const vector<unsigned char>& vchValue,
                     string& strError);
    bool ReadRecord(const vector<unsigned char>& vchKey,
                    vector<unsigned char>& vchValueRet,
                    string& strError);
    bool CountRecords(int& nRecordsRet, string& strError);

private:
    sqlite3* pdb;

    bool Exec(const char* pszSql, string& strError);
    bool InitSchema(string& strError);

    CWalletDBSQLite(const CWalletDBSQLite&);
    void operator=(const CWalletDBSQLite&);
};

#endif
