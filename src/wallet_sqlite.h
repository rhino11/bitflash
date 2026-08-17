// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#ifndef BITFLASH_WALLET_SQLITE_H
#define BITFLASH_WALLET_SQLITE_H

#include <sqlite3.h>

class CWalletRecordVisitor;

class CWalletDBSQLite
{
public:
    CWalletDBSQLite();
    ~CWalletDBSQLite();

    bool Open(const string& strPath, string& strError);
    bool OpenReadOnly(const string& strPath, string& strError);
    void Close();

    bool BeginTransaction(string& strError);
    bool CommitTransaction(string& strError);
    bool RollbackTransaction(string& strError);
    bool Checkpoint(string& strError);

    bool WriteRecord(const vector<unsigned char>& vchKey,
                     const vector<unsigned char>& vchValue,
                     string& strError,
                     bool fOverwrite=true);
    bool ReadRecord(const vector<unsigned char>& vchKey,
                    vector<unsigned char>& vchValueRet,
                    string& strError);
    bool EraseRecord(const vector<unsigned char>& vchKey,
                     string& strError);
    bool ScanRecords(CWalletRecordVisitor& visitor, string& strError);
    bool CountRecords(int& nRecordsRet, string& strError);

    template<typename K, typename T>
    bool WriteTypedRecord(const K& key, const T& value, string& strError,
                          bool fOverwrite=true)
    {
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;

        CDataStream ssValue(SER_DISK);
        ssValue.reserve(10000);
        ssValue << value;

        vector<unsigned char> vchKey(ssKey.begin(), ssKey.end());
        vector<unsigned char> vchValue(ssValue.begin(), ssValue.end());
        bool fOk = WriteRecord(vchKey, vchValue, strError, fOverwrite);

        if (!vchKey.empty())
            memset(&vchKey[0], 0, vchKey.size());
        if (!vchValue.empty())
            memset(&vchValue[0], 0, vchValue.size());
        if (!ssKey.empty())
            memset(&ssKey[0], 0, ssKey.size());
        if (!ssValue.empty())
            memset(&ssValue[0], 0, ssValue.size());
        return fOk;
    }

    template<typename K, typename T>
    bool ReadTypedRecord(const K& key, T& valueRet, string& strError)
    {
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        vector<unsigned char> vchKey(ssKey.begin(), ssKey.end());

        vector<unsigned char> vchValue;
        bool fOk = ReadRecord(vchKey, vchValue, strError);
        if (!vchKey.empty())
            memset(&vchKey[0], 0, vchKey.size());
        if (!ssKey.empty())
            memset(&ssKey[0], 0, ssKey.size());
        if (!fOk)
            return false;

        CDataStream ssValue(vchValue, SER_DISK);
        ssValue >> valueRet;
        bool fReadOk = !ssValue.fail();
        if (!vchValue.empty())
            memset(&vchValue[0], 0, vchValue.size());
        if (!ssValue.empty())
            memset(&ssValue[0], 0, ssValue.size());
        if (!fReadOk)
            strError = "SQLite wallet record could not be deserialized";
        return fReadOk;
    }

    template<typename K>
    bool EraseTypedRecord(const K& key, string& strError)
    {
        CDataStream ssKey(SER_DISK);
        ssKey.reserve(1000);
        ssKey << key;
        vector<unsigned char> vchKey(ssKey.begin(), ssKey.end());

        bool fOk = EraseRecord(vchKey, strError);
        if (!vchKey.empty())
            memset(&vchKey[0], 0, vchKey.size());
        if (!ssKey.empty())
            memset(&ssKey[0], 0, ssKey.size());
        return fOk;
    }

private:
    sqlite3* pdb;

    bool Exec(const char* pszSql, string& strError);
    bool InitSchema(string& strError);

    CWalletDBSQLite(const CWalletDBSQLite&);
    void operator=(const CWalletDBSQLite&);
};

#endif
