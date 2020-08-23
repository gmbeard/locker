#ifndef LOCKER_CRYPT_HPP_INCLUDED
#define LOCKER_CRYPT_HPP_INCLUDED

#include "./span.hpp"
#include "./keys.hpp"

#include <vector>

namespace locker
{

//auto required_decrypt_size(Span<unsigned char const>) -> std::size_t;
//auto required_encrypt_size(Span<char const>) -> std::size_t;

auto symmetric_decrypt(
    Span<unsigned char const> data,
    Span<unsigned char const> key) -> std::vector<unsigned char>;

auto symmetric_encrypt(
    Span<unsigned char const> data,
    Span<unsigned char const> key) -> std::vector<unsigned char>;

//auto symmetric_decrypt_fd(
//    int fd,
//    Span<unsigned char const> key) -> std::vector<char>;
//
//auto symmetric_encrypt_fd(
//    int fd,
//    Span<unsigned char const> key) -> std::vector<unsigned char>;

auto pk_encrypt(
    Span<unsigned char const> data,
    Key key) -> std::vector<unsigned char>;

auto pk_decrypt(
    Span<unsigned char const> data,
    Key key) -> std::vector<unsigned char>;
}

#endif //LOCKER_CRYPT_HPP_INCLUDED
