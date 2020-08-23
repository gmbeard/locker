#include "locker/fs.hpp"

#include <filesystem>

namespace fs = std::filesystem;

auto locker::get_locker_home() noexcept -> std::pair<bool, std::string>
{    
    std::string locker_home;
    if (auto var = std::getenv("LOCKER_HOME"); var)
        locker_home = var;

    if (locker_home.empty()) {
        if (auto var = std::getenv("HOME"); var) {
            locker_home = var;
            if (locker_home.back() == '/')
                locker_home.pop_back();

            locker_home += "/.locker";
        }
    }

    if (locker_home.empty())
        return { false, { } };

    if (locker_home.back() == '/')
        locker_home.pop_back();

    if (!fs::exists(locker_home))
        return { false, { } };

    return { true, locker_home };
}

