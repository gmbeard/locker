#include "locker/crypt.hpp"
#include "locker/io.hpp"
#include "locker/utils.hpp"

#include <memory>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace
{

struct CipherCtxDeleter
{
    auto operator()(EVP_CIPHER_CTX* p) const noexcept
    {
        EVP_CIPHER_CTX_free(p);
    }
};

struct EVP_PKEY_CTXDeleter
{
    auto operator()(EVP_PKEY_CTX* p) const noexcept
    {
        EVP_PKEY_CTX_free(p);
    }
};

using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;
using EVP_PKEY_CTXPtr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter>;

auto required_decrypt_size(locker::Span<unsigned char const> data) -> std::size_t
{
    return static_cast<std::size_t>(EVP_CIPHER_block_size(EVP_aes_256_cbc())) + data.size();
}

auto required_encrypt_size(locker::Span<unsigned char const> data) -> std::size_t
{
    return static_cast<std::size_t>(EVP_CIPHER_block_size(EVP_aes_256_cbc())) + data.size();
}

} // END anonymous

auto locker::symmetric_decrypt(
    Span<unsigned char const> data,
    Span<unsigned char const> key) -> std::vector<unsigned char>
{
    CipherCtxPtr ctx { EVP_CIPHER_CTX_new() };
    if (!ctx)
        throw std::runtime_error { "Error: EVP_CIPHER_CTX_new" };

    if (EVP_DecryptInit(
            ctx.get(),
            EVP_aes_256_cbc(),
            key.data(),
            nullptr) <=0)
        throw std::runtime_error { "Error: EVP_DecryptInit" };

    int length;
    std::size_t total_length;
    std::vector<unsigned char> decrypted(required_decrypt_size(data));

    if (EVP_DecryptUpdate(
            ctx.get(),
            &decrypted[0],
            &length,
            data.data(),
            safe_cast<int>(data.size())) <= 0)
        throw std::runtime_error { "Error: EVP_DecryptUpdate" };

    total_length = safe_cast<std::size_t>(length);

    if (EVP_DecryptFinal_ex(
            ctx.get(),
            &decrypted[safe_cast<std::size_t>(length)],
            &length) <= 0)
        throw std::runtime_error { "Error: EVP_DecryptFinal_ex" };

    total_length += safe_cast<std::size_t>(length);

    decrypted.resize(total_length);

    return decrypted;
}

auto locker::symmetric_encrypt(
    Span<unsigned char const> data,
    Span<unsigned char const> key) -> std::vector<unsigned char>
{
    CipherCtxPtr ctx { EVP_CIPHER_CTX_new() };
    if (!ctx)
        throw std::runtime_error { "Error: EVP_CIPHER_CTX_new" };

    if (EVP_EncryptInit(
            ctx.get(),
            EVP_aes_256_cbc(),
            key.data(),
            nullptr) <= 0)
        throw std::runtime_error { "Error: EVP_EncryptInit" };

    int length;
    std::size_t total_length;
    std::vector<unsigned char> encrypted(required_encrypt_size(data));

    if (EVP_EncryptUpdate(
            ctx.get(),
            &encrypted[0],
            &length,
            data.data(),
            safe_cast<int>(data.size())) <= 0)
        throw std::runtime_error { "Couldn't encrypt data" };

    total_length = safe_cast<std::size_t>(length);

    if (EVP_EncryptFinal_ex(
            ctx.get(),
            &encrypted[safe_cast<int>(length)],
            &length) <= 0)
        throw std::runtime_error { "Couldn't encrypt data" };

    total_length += safe_cast<std::size_t>(length);
    encrypted.resize(total_length);
    return encrypted;
}

auto locker::pk_encrypt(
    Span<unsigned char const> data,
    Key key) -> std::vector<unsigned char>
{
    EVP_PKEY_CTXPtr ctx { EVP_PKEY_CTX_new(key.get(), ENGINE_get_default_RSA()) };
    if (!ctx)
        throw std::runtime_error { "Error: EVP_PKEY_CTX_new" };

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_encrypt_init" };

    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_CTX_set_rsa_padding" };

    std::size_t required_length;
    if (EVP_PKEY_encrypt(
            ctx.get(), 
            nullptr, 
            &required_length, 
            data.data(),
            data.size()) <= 0)
        throw std::runtime_error { "EVP_PKEY_encrypt" };

    std::vector<unsigned char> encrypted(required_length);

    if (EVP_PKEY_encrypt(
            ctx.get(), 
            &encrypted[0], 
            &required_length, 
            data.data(),
            data.size()) <= 0)
        throw std::runtime_error { "EVP_PKEY_encrypt" };

    encrypted.resize(required_length);

    return encrypted;
}

auto locker::pk_decrypt(
    Span<unsigned char const> data,
    Key key) -> std::vector<unsigned char>
{
    EVP_PKEY_CTXPtr ctx { EVP_PKEY_CTX_new(key.get(), ENGINE_get_default_RSA()) };
    if (!ctx)
        throw std::runtime_error { "Error: EVP_PKEY_CTX_new" };

    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_decrypt_init" };

    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_CTX_set_rsa_padding" };

    std::size_t required_length;
    if (EVP_PKEY_decrypt(
            ctx.get(), 
            nullptr, 
            &required_length, 
            data.data(),
            data.size()) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_decrypt (first call)" };

    std::vector<unsigned char> decrypted(required_length);

    if (EVP_PKEY_decrypt(
            ctx.get(), 
            &decrypted[0], 
            &required_length, 
            data.data(),
            data.size()) <= 0)
        throw std::runtime_error { "Error: EVP_PKEY_decrypt" };

    decrypted.resize(required_length);

    return decrypted;
}
