#ifndef LOCKER_UTILS_HPP_INCLUDED
#define LOCKER_UTILS_HPP_INCLUDED

#ifdef NDEBUG
#define LOCKER_UNLIKELY(cond) __builtin_expect(!!(cond), 0)
#else
#define LOCKER_UNLIKELY(cond) cond
#endif

#include "./utils/safe_cast.hpp"

#endif //LOCKER_UTILS_HPP_INCLUDED
