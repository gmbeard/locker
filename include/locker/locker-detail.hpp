#ifndef LOCKER_LOCKER_DETAIL_HPP_INCLUDED
#define LOCKER_LOCKER_DETAIL_HPP_INCLUDED

#include "./keys.hpp"
#include "./utils.hpp"

#include <string>
#include <vector>

namespace locker::detail
{
auto encrypt_impl(
        std::string const&, 
        std::string const&,
        Span<unsigned char const>,
        PwdCallback,
        void*) -> std::vector<unsigned char>;

auto decrypt_impl(
        std::string const&, 
        std::string const&,
        Span<unsigned char const>,
        PwdCallback,
        void*) -> std::vector<unsigned char>;
}

#endif //LOCKER_LOCKER_DETAIL_HPP_INCLUDED
