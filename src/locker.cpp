#include "locker/locker.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

namespace
{
auto get_encrypted_key(
    std::ifstream& stream, 
    std::string const& pub_key) -> std::string
{
    std::string line, encrypted_key;

    while (std::getline(stream, line)) {
        auto ws_pos = std::find(std::begin(line), std::end(line), ' ');
        if (ws_pos == std::end(line))
            continue;

        if (std::equal(
                std::begin(pub_key),
                std::end(pub_key),
                std::begin(line),
                ws_pos))
        {
            encrypted_key = std::string {
                ++ws_pos,
                std::end(line)
            };
            break;
        }
    }

    return encrypted_key;
}

} // END anonymous

auto locker::detail::encrypt_impl(
        std::string const& db_path,
        std::string const& key_path,
        Span<unsigned char const> plain_text,
        PwdCallback cb,
        void* user_data) -> std::vector<unsigned char>
{
    using namespace std::literals;

    auto keepers_path = fs::path(db_path) / "keepers";
    if (!fs::exists(keepers_path))
        throw std::runtime_error { "Error: Not found - "s + keepers_path.c_str() };

    auto pub_key_base64 = base64_key(load_public_key(key_path));
    auto keepers_file = std::ifstream(keepers_path);
    std::string encrypted_key = get_encrypted_key(keepers_file, pub_key_base64);

    if (encrypted_key.empty())
        throw std::runtime_error { "Error: not a keeper" };

    auto raw_encrypted_key = 
        from_base64({ &encrypted_key[0], encrypted_key.size() });

    auto decrypted_key = pk_decrypt(
        { &raw_encrypted_key[0], raw_encrypted_key.size() },
        load_private_key(key_path, [&](bool verify) { return cb(user_data, verify); })
    );

    return symmetric_encrypt(
        plain_text, 
        { &decrypted_key[0], decrypted_key.size() }
    );
}

auto locker::detail::decrypt_impl(
        std::string const& db_path,
        std::string const& key_path,
        Span<unsigned char const> encrypted_data,
        PwdCallback cb,
        void* user_data) -> std::vector<unsigned char>
{
    using namespace std::literals;

    auto keepers_path = fs::path(db_path) / "keepers";
    if (!fs::exists(keepers_path))
        throw std::runtime_error { "Error: Not found - "s + keepers_path.c_str() };

    auto pub_key_base64 = base64_key(load_public_key(key_path));
    auto keepers_file = std::ifstream(keepers_path);
    std::string encrypted_key = get_encrypted_key(keepers_file, pub_key_base64);

    if (encrypted_key.empty())
        throw std::runtime_error { "Error: not a keeper" };

    auto raw_encrypted_key = 
        from_base64({ &encrypted_key[0], encrypted_key.size() });

    auto decrypted_key = pk_decrypt(
        { &raw_encrypted_key[0], raw_encrypted_key.size() },
        load_private_key(key_path, [&](bool verify) { return cb(user_data, verify); })
    );

    return symmetric_decrypt(
        encrypted_data, 
        { &decrypted_key[0], decrypted_key.size() }
    );
}
