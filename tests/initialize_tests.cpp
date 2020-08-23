#include "locker/init.hpp"
#include "testy/testy.hpp"

#include <filesystem>

namespace fs = std::filesystem;

McTest(should_initialize) 
{
    char constexpr kTmpPath[] = "/tmp/.locker-test";
    if (fs::exists(kTmpPath))
        fs::remove_all(kTmpPath);

    locker::init_key(kTmpPath, [] { return "Hello"; });

    Expect(fs::exists(kTmpPath));
    Expect(fs::exists(fs::path(kTmpPath) / "locker-key"));
    Expect(fs::exists(fs::path(kTmpPath) / "locker-key.pub"));
}

McTest(should_fail_to_initialize_if_dir_exists)
{
    char constexpr kTmpPath[] = "/tmp/.locker-test";
    if (fs::exists(kTmpPath))
        fs::remove_all(kTmpPath);

    locker::init_key(kTmpPath, [] { return "Hello"; });

    try {
        locker::init_key(kTmpPath, [] { return "Hello"; });
        Expect(false && "Should have thrown!");
    }
    catch (...)
    { }
}

McTest(should_initialize_db)
{
    char constexpr kTmpKeyPath[] = "/tmp/.locker-test";
    char constexpr kTmpDbPath[] = "/tmp/.locker-db";

    if (fs::exists(kTmpKeyPath))
        fs::remove_all(kTmpKeyPath);
    locker::init_key(kTmpKeyPath, [] { return "Hello"; });

    if (fs::exists(kTmpDbPath))
        fs::remove_all(kTmpDbPath);

    locker::init_db(kTmpDbPath, kTmpKeyPath, [] { return "Hello"; });

    Expect(fs::exists(kTmpDbPath));
    Expect(fs::exists(fs::path(kTmpDbPath) / "keepers"));
}

auto main() -> int
{
    return testy::run_all_tests();
}
