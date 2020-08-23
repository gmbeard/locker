#ifndef LOCKER_SPAN_HPP_INCLUDED
#define LOCKER_SPAN_HPP_INCLUDED

#include <cassert>
#include <cstddef>
#include <type_traits>

namespace locker
{

template<typename T, typename P, bool IsConst>
struct SpanBase;

template<typename T, typename P>
struct SpanBase<T, P, true>
{
    constexpr auto operator[](std::size_t n) const noexcept -> T const&
    {
        P const& self = *static_cast<P const*>(this);
        assert(n < self.size());
        return *(self.data() + n);
    }

    constexpr auto data() const noexcept -> T const* 
    { 
        P const& self = *static_cast<P const*>(this);
        return self.data_;
    }
};

template<typename T, typename P>
struct SpanBase<T, P, false> :
    SpanBase<T, P, true>
{
    constexpr auto operator[](std::size_t n) noexcept -> T&
    {
        P& self = *static_cast<P*>(this);
        assert(n < self.size());
        return *(self.data() + n);
    }

    constexpr auto data() noexcept -> T* 
    { 
        P& self = *static_cast<P*>(this);
        return self.data_;
    }
};

template<typename T>
    requires !std::is_reference_v<T>
struct Span :
    SpanBase<T, Span<T>, std::is_const_v<T>>
{
    friend SpanBase<T, Span<T>, true>;
    friend SpanBase<T, Span<T>, false>;

    using iterator = T*;
    using const_iterator = 
        std::conditional_t<std::is_const_v<T>, T*, T const*>;

    constexpr Span() noexcept :
        data_ { nullptr }
    ,   length_ { 0 }
    { }

    template<typename U>
        requires std::is_convertible_v<U, T*>
    constexpr Span(U data, std::size_t length) noexcept :
        data_ { data }
    ,   length_ { length }
    { }

    template<typename U, std::size_t N>
        requires std::is_convertible_v<U*, T*>
    constexpr Span(U (&data)[N]) noexcept :
        data_ { &data[0] }
    ,   length_ { N }
    { }

    constexpr auto size() const noexcept -> std::size_t { return length_; }
    constexpr auto begin() noexcept -> iterator { return data_; }
    constexpr auto end() noexcept -> iterator { return data_ + length_; };
    constexpr auto begin() const noexcept -> const_iterator { return data_; }
    constexpr auto end() const noexcept -> const_iterator { return data_ + length_; };

private:
    T* data_;
    std::size_t length_;
};

}

#endif //LOCKER_SPAN_HPP_INCLUDED
