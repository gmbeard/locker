#ifndef LOCKER_LOCKER_HPP_INCLUDED
#define LOCKER_LOCKER_HPP_INCLUDED

#include "./crypt.hpp"
#include "./keys.hpp"
#include "./init.hpp"
#include "./io.hpp"
#include "./utils.hpp"
#include "./locker-detail.hpp"

#include <string>
#include <vector>

namespace locker
{

template<typename F>
auto encrypt(
        std::string const& db_path,
        std::string const& key_path,
        Span<unsigned char const> plain_text,
        F f) -> std::vector<unsigned char>
{
    return detail::encrypt_impl(
        db_path, 
        key_path, 
        plain_text,
        &detail::pwd<F>,
        &f);
}

template<typename F>
auto decrypt(
        std::string const& db_path,
        std::string const& key_path,
        Span<unsigned char const> encrypted_text,
        F f) -> std::vector<unsigned char>
{
    return detail::decrypt_impl(
        db_path, 
        key_path, 
        encrypted_text,
        &detail::pwd<F>,
        &f);
}

}

#endif //LOCKER_LOCKER_HPP_INCLUDED
