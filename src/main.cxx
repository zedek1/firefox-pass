#include "ffbt.hxx"

#define OUTPUT_TYPE 0
// 0:console only, 1:.txt file, 2:json file

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
    
    status = ffbt.Load_NSS(nss_dir);
    if (status!=0) { ffbt.NSS_KILL(); return 0; }
    
    for (auto profile = begin(valid_profiles); profile != end(valid_profiles); ++profile)
    {
        status = ffbt.Initialize_Profile(*profile); if (status!=0) { std::cerr << "Exiting\n"; ffbt.NSS_KILL(); return 0; }
        status = ffbt.Check_Authentication();       if (status!=0) { std::cerr << "Exiting\n"; ffbt.NSS_KILL(); return 0; }
        status = ffbt.retrieve_credentials(*profile, OUTPUT_TYPE);    if (status!=0) { std::cerr << "Exiting\n"; ffbt.NSS_KILL(); return 0; }
    }
    ffbt.NSS_KILL();
    return 0;
}