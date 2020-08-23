#include "locker/locker.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

auto key_path() -> std::string
{
    auto const* path = std::getenv("LOCKER_HOME");
    if (path)
        return { path };

    auto const* home = std::getenv("HOME");
    if (home)
        return { fs::path { home } / ".locker" };

    throw std::runtime_error { "Couldn't determine LOCKER_HOME path" };
}

auto db_path() -> std::string
{
    auto const* path = std::getenv("LOCKER_DB");
    if (path)
        return { path };

    auto const* home = std::getenv("HOME");
    if (home)
        return { fs::path { home } / ".locker-db" };

    throw std::runtime_error { "Couldn't determine LOCKER_DB path" };
}

auto die(std::string const& msg) -> int
{
    std::cerr << msg << '\n';
    return 1;
}

auto encrypt(locker::Span<char const*> args) -> int
{
    if (!args.size())
        return die("No name specified");

    if (isatty(STDIN_FILENO))
        std::cout << "Enter the data you wish to encrypt. Ctrl+D to finish:\n";

    auto plain_text = locker::read_stdin_content();
    auto encrypted_data = 
        locker::encrypt(
            db_path(),
            key_path(),
            { &plain_text[0], plain_text.size() },
            [] {
                auto pwd = locker::read_password_from_terminal("Enter locker password: ");
                locker::write_terminal("\n");
                return pwd;
            });

    locker::write_bas64_file(
        { &encrypted_data[0], encrypted_data.size() },
        fs::path { db_path() } / args[0]
    );

    return 0;
}

auto decrypt(locker::Span<char const*> args) -> int
{
    if (!args.size())
        return die("No name specified");

    auto encrypted_text = locker::read_base64_file(fs::path { db_path() } / args[0]);
    auto plain_text = 
        locker::decrypt(
            db_path(),
            key_path(),
            { &encrypted_text[0], encrypted_text.size() },
            [] {
                auto pwd = locker::read_password_from_terminal("Enter locker password: ");
                locker::write_terminal("\n");
                return pwd;
            });

    std::copy(
        plain_text.begin(),
        plain_text.end(),
        std::ostream_iterator<char> { std::cout });

    return 0;
}

auto list() -> int
{
    for (auto const& entry : fs::directory_iterator { db_path() }) {
        if (entry.path().filename() == "keepers")
            continue;

        std::cout << entry.path().filename().string() << '\n';
    }

    return 0;
}

auto main(int argc, char const** argv) -> int
{
    using locker::safe_cast;
    using namespace std::literals;

    if (argc < 2)
        return list();

    locker::Span<char const*> args { 
        argv + 1, 
        safe_cast<std::size_t>(argc - 1)
    };

    try {
        if (std::strcmp(args[0], "add") == 0)
            encrypt({ 
                args.data() + 1, 
                safe_cast<std::size_t>(args.size() - 1) 
            });
        else if (std::strcmp(args[0], "get") == 0)
            decrypt({
                args.data() + 1,
                safe_cast<std::size_t>(args.size() -1 )
            });
        else
            return die("Unknown command: "s + args[0]);
    }
    catch (std::runtime_error const& e) {
        return die(e.what());
    }

    return 0;
}
