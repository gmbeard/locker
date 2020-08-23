#ifndef LOCKER_KEYS_HPP_INCLUDED
#define LOCKER_KEYS_HPP_INCLUDED

#include "./span.hpp"

#include <memory>
#include <openssl/evp.h>
#include <string>

namespace locker
{

using PwdCallback = auto (*)(void*) -> std::string;

struct EVP_PKEYDeleter
{
    auto operator()(EVP_PKEY* fp) const noexcept -> void;
};

using Key = std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>;

namespace detail
{

template<typename F>
auto pwd(void* data) -> std::string
{
    F& f = *reinterpret_cast<F*>(data);
    return f();
}

template<typename F>
auto password_callback_proxy(char* buffer, int size, int rwflag, void* u) -> int
{
    F& f = *reinterpret_cast<F*>(u);
    return f(buffer, size, rwflag);
}

auto load_private_key_impl(std::string const&, PwdCallback, void*) -> Key;
} // END detail

auto derive_key(Span<char const> passphrase, Span<unsigned char> key) -> void;
auto load_public_key(std::string const&) -> Key;
auto base64_key(Key const&) -> std::string;

template<typename F>
auto load_private_key(std::string const& dir, F f) -> Key
{
    return detail::load_private_key_impl(dir, &detail::pwd<F>, &f);
}

}

#endif //LOCKER_KEYS_HPP_INCLUDED
