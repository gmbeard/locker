## Initialization Tests
add_executable(
    initialize-tests
    initialize_tests.cpp
)

target_link_libraries(
    initialize-tests
    PRIVATE
    locker-obj
    Testy::testy
)

add_test(
    NAME initialize-tests
    COMMAND initialize-tests
)

## Encrypt tests
add_executable(
    encrypt-tests
    encrypt_tests.cpp
)

target_link_libraries(
    encrypt-tests
    PRIVATE
    locker-obj
    Testy::testy
)

add_test(
    NAME encrypt-tests
    COMMAND encrypt-tests
)
