#ifndef LOCKER_STRING_SPAN_HPP_INCLUDED
#define LOCKER_STRING_SPAN_HPP_INCLUDED

#include "./span.hpp"

#include <cstring>

namespace locker
{

template<typename T>
    requires 
        std::is_same_v<std::remove_const_t<T>, char> ||
        std::is_same_v<std::remove_const_t<T>, wchar_t>
auto string_span(T* data) -> Span<T>
{
    return { data, std::strlen(data) };
}

}

#endif //LOCKER_STRING_SPAN_HPP_INCLUDED
