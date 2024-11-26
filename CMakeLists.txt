cmake_minimum_required(VERSION 3.10)

project(epicac)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

add_library(epicac lib/epicac.c)

add_executable(epicat cli/main.c)
target_link_libraries(epicat PUBLIC epicac)
target_include_directories(epicat PUBLIC lib)

add_executable(test_main test/test.c)
target_link_libraries(test_main PUBLIC epicac)
target_include_directories(test_main PUBLIC lib)

add_executable(bench test/bench.c)
target_link_libraries(bench PUBLIC epicac)
target_include_directories(bench PUBLIC lib)


enable_testing()
add_test(NAME test COMMAND $<TARGET_FILE:test_main>)

add_test(NAME bench COMMAND $<TARGET_FILE:bench>)
set_tests_properties(bench PROPERTIES PASS_REGULAR_EXPRESSION "Within acceptable range of less than")