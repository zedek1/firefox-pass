#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <unordered_map>
#include <Windows.h>

class NSS {
public:
    bool Load_NSS(std::filesystem::path nss_path);
    bool Initialize_Profile(std::filesystem::path profile_path);
    bool Check_Authentication();
    std::string Decrypt(std::string data);
    void NSS_KILL();

private:
HMODULE nss_library;

// empty struct as PKCS slot
typedef struct PK11SlotInfoStr {} PK11SlotInfo;
typedef struct SECItemStr {
    uint32_t type;
    uint8_t* data;
    uint32_t len; 
} SECItem;

// Typedefs of needed functions
typedef int (*NSS_Init_t)(const char*); NSS_Init_t NSS_Init;
typedef int (*NSS_Shutdown_t)(void); NSS_Shutdown_t NSS_Shutdown;
typedef PK11SlotInfo* (*PK11_GetInternalKeySlot_t)(void); PK11_GetInternalKeySlot_t PK11_GetInternalKeySlot;
typedef void (*PK11_FreeSlot_t)(PK11SlotInfo*); PK11_FreeSlot_t PK11_FreeSlot;
typedef int (*PK11_NeedLogin_t)(PK11SlotInfo*); PK11_NeedLogin_t PK11_NeedLogin;
typedef int (*PK11_CheckUserPassword_t)(PK11SlotInfo*, unsigned char*); PK11_CheckUserPassword_t PK11_CheckUserPassword;
typedef int (*PK11SDR_Decrypt_t)(SECItem*, SECItem*, void*); PK11SDR_Decrypt_t PK11SDR_Decrypt;
typedef void (*SECITEM_ZfreeItem_t)(SECItem*, unsigned int); SECITEM_ZfreeItem_t SECITEM_ZfreeItem;
};

/*
typedef enum {
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
} SECStatus;
*/