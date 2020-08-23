#include "locker/io.hpp"
#include "locker/utils.hpp"

#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <termios.h>
#include <unistd.h>

using namespace std::literals;

namespace
{

struct NoEchoGuard
{
    NoEchoGuard() :
        terminal_ {
            [] {
                int fd = open("/dev/tty", O_RDONLY);
                if (fd < 0)
                    throw std::runtime_error { "Error: open /dev/tty" };
                return fd;
            }()
        }
    ,   to_restore_ {
            [](int term_fd) {
                termios settings;
                if (tcgetattr(term_fd, &settings) < 0)
                    throw std::runtime_error { "Error: tcgetattr" };
                return settings;
            }(terminal_)
        }
    { 
        termios new_settings = to_restore_;
        new_settings.c_lflag &= ~ECHO;
        if (tcsetattr(terminal_, TCSANOW, &new_settings) < 0)
            throw std::runtime_error { "Error tcsetattr" };
    }

    ~NoEchoGuard() noexcept(false)
    {
        if (tcsetattr(terminal_, TCSANOW, &to_restore_) < 0)
            throw std::runtime_error { "Error tcsetattr" };
        close(terminal_);
    }

    NoEchoGuard(NoEchoGuard const&) = delete;
    auto operator=(NoEchoGuard const&) -> NoEchoGuard& = delete;

private:
    int terminal_;
    termios to_restore_;
};

} // END anonymous

auto locker::BIODeleter::operator()(BIO* p) const noexcept -> void
{
        BIO_free_all(p);
}

auto convert_to_hex(unsigned char byte, locker::Span<char> output)
{
    if (output.size() < 2)
        throw std::runtime_error { "Not enough room for hex conversion" };

    auto hi = (byte >> 4) & 0x0f;
    auto low = byte & 0x0f;

    if (hi >= 0x0a)
        output[0] = static_cast<char>('a' + (hi - 0x0a));
    else
        output[0] = static_cast<char>('0' + hi);

    if (low >= 0x0a)
        output[1] = static_cast<char>('a' + (low - 0x0a));
    else
        output[1] = static_cast<char>('0' + low);
}

auto convert_from_hex(locker::Span<char const> data, unsigned char& c) -> std::size_t
{
    if (data.size() < 2)
        throw std::runtime_error { "Invalid hex sequence" };

    char hi = data[0], low = data[1];
    unsigned char tmphi, tmplo;

    if (hi >= '0' && hi <= '9')
        tmphi = (hi - '0') & 0x0f;
    else if (hi >= 'a' && hi <= 'f')
        tmphi = (hi - 'a' + 10) & 0x0f;
    else if (hi >= 'A' && hi <= 'F')
        tmphi = (hi - 'A' + 10) & 0x0f;
    else
        throw std::runtime_error { "Invalid hex sequence" };

    if (low >= '0' && low <= '9')
        tmplo = (low - '0') & 0x0f;
    else if (low >= 'a' && low <= 'f')
        tmplo = (low - 'a' + 10) & 0x0f;
    else if (low >= 'A' && low <= 'F')
        tmplo = (low - 'A' + 10) & 0x0f;
    else
        throw std::runtime_error { "Invalid hex sequence" };

    c = (static_cast<unsigned char>(tmplo) & 0x0f) | 
        (static_cast<unsigned char>(tmphi << 4) & 0xf0);

    return 2;
}

auto locker::write_encrypted(int fd, Span<unsigned char const> data) -> void
{
    std::size_t constexpr kLineLength = 80;
    char buffer[kLineLength + 1];

    std::size_t column = 0;
    for (auto const& b : data) {
        convert_to_hex(b, { &buffer[column], kLineLength - column });
        column += 2;
        if (column == kLineLength) {
            buffer[column++] = '\n';
            write_all_bytes(fd, Span<char const> { buffer, column });
            column = 0;
        }
    }

    if (column) {
        buffer[column++] = '\n';
        write_all_bytes(fd, Span<char const> { buffer, column });
    }
}

auto locker::read_all(int fd) -> std::vector<unsigned char>
{
    std::vector<unsigned char> raw_bytes;
    read_all_bytes(fd, raw_bytes);
    return raw_bytes;
}

auto locker::from_base64(Span<char const> base64_data) -> std::vector<unsigned char>
{
    int constexpr kMaxRead = std::numeric_limits<int>::max();

    BIOPtr b64 { BIO_new(BIO_f_base64()) };
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_new_mem_buf(base64_data.data(), static_cast<int>(base64_data.size()));
    BIO_push(b64.get(), bio);

    std::vector<unsigned char> converted(512);
    std::size_t total_read = 0;
    while (true) {

        int to_read;
        if (converted.size() - total_read > static_cast<std::size_t>(kMaxRead))
            to_read = kMaxRead;
        else
            to_read = static_cast<int>(converted.size() - total_read);

        int read = BIO_read(b64.get(), &converted[total_read], to_read);

        if (read == 0)
            break;

        if (read < 0)
            throw std::runtime_error { "Couldn't convert Base64 data" };

        total_read += static_cast<std::size_t>(read);
        if (total_read == converted.size())
            converted.resize(converted.size() * 2);
    }

    converted.resize(total_read);
    return converted;
}

auto locker::to_base64(Span<unsigned char const> data) -> std::string
{
    int constexpr kMaxWrite = std::numeric_limits<int>::max();

    BIOPtr b64 { BIO_new(BIO_f_base64()) };
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_push(b64.get(), bio);

    std::size_t total_written = 0;
    while (total_written < data.size()) {
        int to_write;
        if (data.size() - total_written > static_cast<std::size_t>(kMaxWrite))
            to_write = kMaxWrite;
        else
            to_write = static_cast<int>(data.size() - total_written);

        int written = BIO_write(b64.get(), &data[total_written], to_write);

        if (written <= 0)
            throw std::runtime_error { "Couldn't convert Base64 data" };

        total_written += static_cast<std::size_t>(written);
    }

    BIO_flush(b64.get());

    BUF_MEM* bio_mem = nullptr;
    BIO_get_mem_ptr(bio, &bio_mem);
    if (!bio_mem)
        throw std::runtime_error { "Couldn't convert Base64 data" };

    return {
        reinterpret_cast<char const*>(bio_mem->data),
        static_cast<std::size_t>(bio_mem->length)
    };
}

auto locker::write_bas64_file(
        Span<unsigned char const> data, 
        std::string const& path) -> void
{
    int constexpr kMaxWrite = std::numeric_limits<int>::max();

    BIOPtr base64_filter { BIO_new(BIO_f_base64()) };
    BIO* bio = BIO_new_file(path.c_str(), "w");
    if (!bio)
        throw std::runtime_error { "Error: BIO_new_file - "s + path  };

    BIO_push(base64_filter.get(), bio);

    std::size_t total_written = 0;
    while (total_written < data.size()) {
        int to_write;
        if (data.size() - total_written > safe_cast<std::size_t>(kMaxWrite))
            to_write = kMaxWrite;
        else
            to_write = safe_cast<int>(data.size() - total_written);

        int written = BIO_write(base64_filter.get(), &data[total_written], to_write);

        if (written <= 0)
            throw std::runtime_error { "Error: BIO_write - "s + path };

        total_written += safe_cast<std::size_t>(written);
    }

    BIO_flush(base64_filter.get());
}

auto locker::read_base64_file(std::string const& path) 
    -> std::vector<unsigned char>
{
    int constexpr kMaxRead = std::numeric_limits<int>::max();

    BIOPtr base64_filter { BIO_new(BIO_f_base64()) };
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio)
        throw std::runtime_error { "Error: BIO_new_file - "s + path  };

    BIO_push(base64_filter.get(), bio);

    std::vector<unsigned char> converted(512);
    std::size_t total_read = 0;
    while (true) {

        int to_read;
        if (converted.size() - total_read > safe_cast<std::size_t>(kMaxRead))
            to_read = kMaxRead;
        else
            to_read = safe_cast<int>(converted.size() - total_read);

        int read = BIO_read(base64_filter.get(), &converted[total_read], to_read);

        if (read == 0)
            break;

        if (read < 0)
            throw std::runtime_error { "Error: BIO_read - "s + path };

        total_read += safe_cast<std::size_t>(read);
        if (total_read == converted.size())
            converted.resize(converted.size() * 2);
    }

    converted.resize(total_read);
    return converted;
}

auto locker::write_terminal(std::string const& text) -> void
{
    std::ofstream terminal { "/dev/tty" };
    terminal << text;
}

auto locker::read_password_from_terminal(std::string const& prompt) -> std::string
{
    std::fstream term { "/dev/tty" };
    term << prompt;
    term.flush();

    NoEchoGuard no_echo_guard;
    std::string password;
    std::getline(term, password);
    return password;
}

auto locker::read_stdin_content() -> std::vector<unsigned char>
{
    std::vector<unsigned char> data;
    data.reserve(1024);

    std::copy(
        std::istreambuf_iterator<char> { std::cin },
        std::istreambuf_iterator<char> { },
        std::back_inserter(data));

    return data;
}
