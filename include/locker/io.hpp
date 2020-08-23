#ifndef LOCKER_IO_HPP_INCLUDED
#define LOCKER_IO_HPP_INCLUDED

#include "./span.hpp"

#include <memory>
#include <openssl/bio.h>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace locker
{

struct BIODeleter
{
    auto operator()(BIO* bio) const noexcept -> void;
};

using BIOPtr = std::unique_ptr<BIO, BIODeleter>;

template<typename T>
auto read_all_bytes(int fd, std::vector<T>& output) -> void
{
    std::size_t bytes_read = 0;
    long result;

    do {
        if (bytes_read == output.size())
            output.resize(output.size() * 2);

        result = read(fd, &output[bytes_read], output.size() - bytes_read);
        if (result < 0)
            throw std::system_error { 
                std::error_code { errno, std::system_category() } 
            };

        bytes_read += static_cast<std::size_t>(result);
    }
    while (result > 0);

    output.resize(bytes_read);
}

template<typename T>
auto write_all_bytes(int fd, Span<T> data) -> void
{
    std::size_t bytes_written = 0;
    long result;

    do {
        result = write(fd, &data[bytes_written], data.size() - bytes_written);
        if (result < 0)
            throw std::system_error { 
                std::error_code { errno, std::system_category() } 
            };

        bytes_written += static_cast<std::size_t>(result);
    }
    while (bytes_written < data.size());
}

auto write_encrypted(int fd, Span<unsigned char const> data) -> void;
auto read_all(int fd) -> std::vector<unsigned char>;

auto from_base64(Span<char const> base64) -> std::vector<unsigned char>;
auto to_base64(Span<unsigned char const> data) -> std::string;
auto write_bas64_file(Span<unsigned char const> data, std::string const& path) -> void;
auto read_base64_file(std::string const& path) -> std::vector<unsigned char>;
auto write_terminal(std::string const& text) -> void;
auto read_password_from_terminal(std::string const& prompt) -> std::string;
auto read_stdin_content() -> std::vector<unsigned char>;

}

#endif //LOCKER_IO_HPP_INCLUDED
