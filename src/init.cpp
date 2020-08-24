#include "locker/init.hpp"
#include "locker/io.hpp"
#include "locker/keys.hpp"
#include "locker/utils.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;

namespace
{
struct EVP_PKEY_CTXDeleter
{
    auto operator()(EVP_PKEY_CTX* p) const noexcept
    {
        EVP_PKEY_CTX_free(p);
    }
};

struct EVP_PKEYDeleter
{
    auto operator()(EVP_PKEY* p) const noexcept
    {
        EVP_PKEY_free(p);
    }
};

struct FILEDeleter
{
    auto operator()(FILE* p) const noexcept
    {
        std::fclose(p);
    }
};

using EVP_PKEY_CTXPtr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter>;
using EVP_PKEYPtr = std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>;
using FILEPtr = std::unique_ptr<FILE, FILEDeleter>;

auto generate_random_data(locker::Span<unsigned char> output) -> void
{
    std::ifstream urandom { "/dev/urandom", std::ios::binary };
    std::size_t read = 0;
    while (read < output.size()) {
        urandom.read(
            reinterpret_cast<char*>(&output[read]), 
            output.size() - read);
        read += urandom.gcount();
    }
}

}

auto locker::detail::init_db_impl(
        std::string const& path,
        std::string const& key_dir,
        PwdCallback,
        void*) -> void
{
    std::size_t constexpr kKeySize = 32;

    fs::path dir { path };
    if (!fs::exists(dir))
        fs::create_directories(dir);

    if (fs::exists(dir / "keepers"))
        throw std::runtime_error { "DB already initialized" };

    auto pub_key = load_public_key(key_dir);
    unsigned char random_data[kKeySize];
    generate_random_data(random_data);
    unsigned char key_data[kKeySize];
    derive_key(
        { reinterpret_cast<char const*>(random_data), kKeySize },
        key_data);

    EVP_PKEY_CTXPtr ctx { EVP_PKEY_CTX_new(pub_key.get(), nullptr) };
    if (!ctx)
        throw std::runtime_error { "Error: EVP_PKEY_CTX_new" };

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_encrypt_init" };

    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_CTX_set_rsa_padding" };

    std::size_t required_size;
    if (EVP_PKEY_encrypt(
                ctx.get(), 
                nullptr, 
                &required_size,
                key_data,
                kKeySize) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_encrypt" };

    std::vector<unsigned char> enc(required_size);
    if (EVP_PKEY_encrypt(
                ctx.get(), 
                &enc[0], 
                &required_size,
                key_data,
                kKeySize) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_encrypt" };

    auto base64_pub_key = base64_key(pub_key);
    auto base64_enc = to_base64({ &enc[0], enc.size() });

    std::ofstream keepers { (dir / "keepers").c_str() };
    keepers << base64_pub_key << " " << base64_enc << '\n';
    keepers.flush();
}

auto locker::detail::init_key_impl(
        std::string const& path,
        PwdCallback cb,
        void* f) -> void
{
    fs::path dir { path };
    if (!fs::exists(dir))
        fs::create_directories(dir);

    if (fs::exists(dir / "locker-key") || fs::exists(dir / "locker-key.pub"))
        throw std::runtime_error { "Key already initialized" };

    EVP_PKEY_CTXPtr ctx { EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr) };
    if (!ctx)
        throw std::runtime_error { "Error: EVP_PKEY_CTX_new_id" };

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_keygen_init" };

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 4096) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_CTX_set_rsa_keygen_bits" };

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &key) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_keygen" };

    EVP_PKEYPtr pkey { key };

    auto callback = [&](char* buffer, int size, int rwflag) -> int {
        auto pass = cb(f, rwflag == 1);

        if (!size)
            return -1;

        if (pass.size() > safe_cast<std::size_t>(size) - 1)
            return -1;

        std::strcpy(buffer, pass.c_str());
        return safe_cast<int>(pass.size());
    };

    FILEPtr output_file { std::fopen((dir / "locker-key").c_str(), "w") };
    if (!output_file)
        throw std::runtime_error { "Error: fopen - locker-key" };

    int success;
    try {
        success = PEM_write_PrivateKey(
                output_file.get(),
                pkey.get(),
                EVP_aes_256_cbc(),
                nullptr,
                0,
                &password_callback_proxy<decltype(callback)>,
                &callback);
    }
    catch (...) {
        for (auto& e : fs::directory_iterator { dir })
            fs::remove(e);
        throw;
    }

    if (success <= 0)
        throw std::runtime_error { "Error: PEM_write_PrivateKey" };

    std::fclose(output_file.get());
    output_file.release();

    fs::permissions(
        dir / "locker-key", 
        fs::perms::owner_write | fs::perms::owner_read,
        fs::perm_options::replace);

    output_file.reset(std::fopen((dir / "locker-key.pub").c_str(), "w"));
    if (!output_file)
        throw std::runtime_error { "Error: fopen - locker-key.pub" };

    success = PEM_write_PUBKEY(output_file.get(), pkey.get());
    if (success <= 0)
        throw std::runtime_error { "Error: PEM_write_PUBKEY" };
}
