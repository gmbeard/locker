#ifndef LOCKER_FS_HPP_INCLUDED
#define LOCKER_FS_HPP_INCLUDED

#include <string>
#include <tuple>

namespace locker
{

auto get_locker_home() noexcept -> std::pair<bool, std::string>;

}

#endif //LOCKER_FS_HPP_INCLUDED
