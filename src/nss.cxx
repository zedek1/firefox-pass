#include "nss.hxx"
#include "crypt.hxx"


bool NSS::Load_NSS(std::filesystem::path nss_path)
{
    // setting path is necessary to load the dll
    SetCurrentDirectoryA(nss_path.string().c_str());

    // add "nss3.dll" for full file path
    std::string nss_location = (nss_path / "nss3.dll").string();

    // load dll
    nss_library = LoadLibraryA(nss_location.c_str());
    if (!nss_library) {
        std::cerr << "Failed to load nss3.dll" << std::endl;
        return false;
    }

    // load functions with macro voodoo
    #define DYNAMIC_FUNCTIONS \
        X(NSS_Init) X(NSS_Shutdown) X(PK11_GetInternalKeySlot) X(PK11_FreeSlot) \
        X(PK11_NeedLogin) X(PK11_CheckUserPassword) X(PK11SDR_Decrypt) X(SECITEM_ZfreeItem)

    #define X(f) \
        f = (f##_t)GetProcAddress(nss_library, #f); \
        if (f == NULL) { \
            std::cerr << "Error loading " << #f << std::endl; \
            return false; \
        }

    DYNAMIC_FUNCTIONS
    #undef X
    return true;
}

void NSS::NSS_KILL()
{
    NSS_Shutdown();
    FreeLibrary(nss_library);
}

bool NSS::Initialize_Profile(std::filesystem::path profile_path)
{
    // NSS_Init takes in the profile path and looks for cert9.db
    // the profile is the same name as the profile folder; AppData/Roaming/Mozilla/Firefox/Profiles/[here]
    
    std::string full_profile_path = "sql:";
    full_profile_path.append(profile_path.string());
    std::cout << "Initializing Profile '" << full_profile_path << "'...\n";

    int status = NSS_Init(full_profile_path.c_str());
    if (status != 0) {
        std::cerr << "[-] NSS_Init Failed\n\n";
        return false;
    }
    std::cout << "[+] NSS_Init Successful\n\n";
    return true;
}

bool NSS::Check_Authentication()
{
    std::cout << "Checking Authentication...\n";
    PK11SlotInfo* keyslot = PK11_GetInternalKeySlot();
    if (!keyslot) {
        std::cout << "Couldn't get keyslot... Exiting\n";
        return false;
    }

    try {
        if (PK11_NeedLogin(keyslot)) {
            std::cout << "[-] Need master password\n\n";
            PK11_FreeSlot(keyslot);
            return false;
        } else {
            std::cout << "[+] No master password needed\n\n";
        }
    } 
    catch (const std::exception& e) {
        std::cerr << "Something fucked up with PK11_NeedLogin()\nError: " << e.what() << "\nContinuing\n";
    }
    PK11_FreeSlot(keyslot);
    return true;
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