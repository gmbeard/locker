#ifndef LOCKER_UTILS_SAFE_CAST_HPP_INCLUDED
#define LOCKER_UTILS_SAFE_CAST_HPP_INCLUDED

#include <exception>
#include <type_traits>

namespace locker
{

struct CastError : std::exception { };

template<typename To, typename From>
    requires std::is_convertible_v<From, To>
auto safe_cast(From from) -> To
{
    using std::is_signed_v;

    auto to = static_cast<To>(from);

    if constexpr (is_signed_v<From> != is_signed_v<To>) {
        if (LOCKER_UNLIKELY(static_cast<From>(to) != from ||
            ((from < From { }) != (to < To { }))))
            throw CastError { };
    }
    else {
        if (LOCKER_UNLIKELY(static_cast<From>(to) != from))
            throw CastError { };
    }

    return to;
}

}

#endif //LOCKER_UTILS_SAFE_CAST_HPP_INCLUDED
