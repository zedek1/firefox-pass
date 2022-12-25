#include "ffbt.hxx"


int FFBT::find_credentials(std::filesystem::path profile_path)
{
    std::vector<std::vector<std::string>> json_ret;
    try {
        // check if file exists then throw if not
        json_ret = get_json_credentials(profile_path / "logins.json");
        if (json_ret.empty()) {
            std::cerr << "logins.json exists but is empty or something really fucked up\n";
            return 1;
        }
        std::cout << "\n=========== ENCRYPTED ===========\n";
        for (auto& login : json_ret) {
            std::cout << "Hostname: " << login[0] << std::endl;
            std::cout << "Encrypted username: " << login[1] << std::endl;
            std::cout << "Encrypted password: " << login[2] << std::endl;
            std::cout << "Encryption type: " << login[3] << std::endl;
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
    decrypt_credentials(json_ret);
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

void FFBT::decrypt_credentials(std::vector<std::vector<std::string>> encrypted_creds)
{
    std::string d_username, d_password;
    std::cout << "\n\n=========== DECRYPTED ===========\n";
    for (auto &site : encrypted_creds) {
        if (std::stoi(site[3])) { // if it has encryption
            try {
                d_username = Decrypt(site[1]);
                d_password = Decrypt(site[2]);
            }
            catch (const std::exception& e) {
                std::cerr << "Decryption failed for '" << site[0] << "' with Error: " << e.what() << "\n";
                continue;
            }
        }
        else {
            //std::cout << "[+] Username and Password are not encrypted\n";
            d_username = site[1];
            d_password = site[2];
        }

        std::cout << "url: " << site[0] << "\n"
                  << "username: " << d_username << "\n"
                  << "password: " << d_password << "\n\n";
    }
    // void for now but ill return something better for more output options
    /* std::vector<std::unordered_map<std::string, std::string> = 
    {
        {
            ["url":hostname]
            ["username":d_username]
            ["password":d_password]
        }

        {
            ["url":hostname]
            ["username":d_username]
            ["password":d_password]
        }
    }*/
}