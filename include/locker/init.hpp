#ifndef LOCKER_INIT_HPP_INCLUDED
#define LOCKER_INIT_HPP_INCLUDED

#include "./keys.hpp"

#include <string>

namespace locker
{

namespace detail
{

auto init_key_impl(std::string const& dir, PwdCallback cb, void* data) -> void;
auto init_db_impl(
        std::string const& db_dir, 
        std::string const& key_dir,
        PwdCallback cb, void* data) -> void;

} // END detail

template<typename F>
auto init_key(std::string const& dir, F f) -> void
{
    detail::init_key_impl(dir, &detail::pwd<F>, &f);
}

template<typename F>
auto init_db(
        std::string const& db_dir, 
        std::string const& key_dir, 
        F f) -> void
{
    detail::init_db_impl(db_dir, key_dir, &detail::pwd<F>, &f);
}

}
#endif //LOCKER_INIT_HPP_INCLUDED
