#include "locker/keys.hpp"
#include "locker/fs.hpp"
#include "locker/io.hpp"
#include "locker/utils.hpp"

#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

namespace fs = std::filesystem;

auto locker::EVP_PKEYDeleter::operator()(EVP_PKEY* fp) const noexcept -> void
{
    EVP_PKEY_free(fp);
}

namespace
{

struct FILEDeleter
{
    auto operator()(FILE* fp) const noexcept -> void
    {
        std::fclose(fp);
    }
};

using FILEPtr = std::unique_ptr<FILE, FILEDeleter>;

enum class KeyType
{
    Public,
    Private,
};

[[noreturn]] auto throw_crypto_error(std::size_t e, std::string const& msg)
{
    char buffer[256];
    ERR_error_string_n(e, buffer, 256);
    if (!msg.empty())
        throw std::runtime_error { msg + ": " + std::string { buffer } };
    else
        throw std::runtime_error { std::string { buffer } };
}

auto load_key(
        std::string const& dir, 
        KeyType key_type, 
        locker::PwdCallback cb, 
        void* user_data) -> locker::Key
{
    using namespace locker;
    using namespace std::literals;

    auto key_path = fs::path(dir);
    switch (key_type) {
        case KeyType::Private:
            key_path /= "locker-key";
            break;
        case KeyType::Public:
            key_path /= "locker-key.pub";
            break;
    }

    FILEPtr fp { std::fopen(key_path.c_str(), "r") };
    if (!fp)
        throw std::runtime_error { "Error: fopen - "s + key_path.c_str() }; 

    auto callback = [&](char* buffer, int size, int /*rwflag*/) -> int {
        auto pass = cb(user_data);

        if (!size)
            return -1;

        if (pass.size() > safe_cast<std::size_t>(size) - 1)
            return -1;

        std::strcpy(buffer, pass.c_str());
        return safe_cast<int>(pass.size());
    };

    Key pkey;
    if (key_type == KeyType::Private)
        pkey.reset(
            PEM_read_PrivateKey(
                fp.get(), 
                nullptr, 
                &detail::password_callback_proxy<decltype(callback)>, 
                &callback));
    else
        pkey.reset(PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr));

    if (!pkey)
        throw_crypto_error(ERR_get_error(), "Couldn't read key");

    return pkey;
}

}

auto locker::derive_key(Span<char const> passphrase, Span<unsigned char> key) -> void
{
    auto success = 
        PKCS5_PBKDF2_HMAC(
            passphrase.data(),
            static_cast<int>(passphrase.size()),
            nullptr,
            0,
            1000,
            EVP_sha256(),
            static_cast<int>(key.size()),
            key.data()
        );

    if (!success)
        throw std::runtime_error { "Unable to derive key" };
}

auto locker::load_public_key(std::string const& dir) -> Key
{
    return load_key(
        dir, 
        KeyType::Public,
        nullptr,
        nullptr);
}

auto locker::detail::load_private_key_impl(
        std::string const& dir,
        PwdCallback cb, 
        void* data) -> Key
{
    return load_key(dir, KeyType::Private, cb, data);
}

auto locker::base64_key(Key const& key) -> std::string
{
    BIOPtr b64 { BIO_new(BIO_f_base64()) };
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_push(b64.get(), bio);

    if (!i2d_PUBKEY_bio(b64.get(), key.get()))
        throw std::runtime_error { "Couldn't convert key" };

    BUF_MEM* bio_mem = nullptr;
    BIO_get_mem_ptr(bio, &bio_mem);
    if (!bio_mem)
        throw std::runtime_error { "Couldn't fetch BUF_MEM" };

    std::string base64_string(
        reinterpret_cast<char const*>(bio_mem->data),
        bio_mem->length);

    return base64_string;
}
