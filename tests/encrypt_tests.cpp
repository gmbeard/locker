#include "locker/locker.hpp"
#include "testy/testy.hpp"

#include <stdexcept>
#include <filesystem>

namespace fs = std::filesystem;

McTest(should_encrypt_data)
{
    char constexpr kDbPath[] = "/tmp/.locker-db";
    char constexpr kKeyPath[] = "/tmp/.locker-test";
    char constexpr kPlainText[] = "Hello, World!";

    locker::encrypt(
        kDbPath,
        kKeyPath,
        { 
            reinterpret_cast<unsigned char const*>(kPlainText), 
            std::size(kPlainText) - 1 
        },
        [](bool) { return "Hello"; }
    );
}

McTest(should_decrypt_data)
{
    char constexpr kDbPath[] = "/tmp/.locker-db";
    char constexpr kKeyPath[] = "/tmp/.locker-test";
    char constexpr kPlainText[] = "Hello, World!";

    auto enc = locker::encrypt(
        kDbPath,
        kKeyPath,
        { 
            reinterpret_cast<unsigned char const*>(kPlainText), 
            std::size(kPlainText) - 1 
        },
        [](bool) { return "Hello"; }
    );

    auto dec = locker::decrypt(
        kDbPath,
        kKeyPath,
        { &enc[0], enc.size() },
        [](bool) { return "Hello"; }
    );

    std::string decrypted_text {
        reinterpret_cast<char const*>(&dec[0]),
        dec.size()
    };

    Expect(decrypted_text == kPlainText);
}

McTest(should_fail_if_not_a_keeper)
{
    char constexpr kDbPath[] = "/tmp/.locker-db";
    char constexpr kKeyPath[] = "/tmp/.locker-test-2";
    char constexpr kPlainText[] = "Hello, World!";

    if (fs::exists(kKeyPath))
        fs::remove_all(kKeyPath);

    locker::init_key(kKeyPath, [](bool) { return "Hello!"; });

    auto encrypt_func = [&] {
        locker::encrypt(
            kDbPath,
            kKeyPath,
            { 
                reinterpret_cast<unsigned char const*>(kPlainText), 
                std::size(kPlainText) - 1 
            },
            [](bool) { return "Hello"; }
        );
    };

    ExpectThrows(encrypt_func(), std::runtime_error);
}

auto main() -> int
{
    return testy::run_all_tests();
}
