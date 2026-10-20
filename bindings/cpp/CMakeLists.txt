# Header-only C++ wrapper over the ciplink C library.
#
#   cmake -S bindings/cpp -B build -DCIPLINK_LIB_DIR=<dir with the ciplink shared library and its import library>
#   cmake --build build && ctest --test-dir build   (tests need CIPLINK_TEST_PORTS="<logix port>;<slc port>")
#
# bindings/cpp/build_and_test.sh with BUILD=cmake does all of this, simulators included.
#
# Build the library first with `cargo build --release -p ciplink-ffi` (target/release).
cmake_minimum_required(VERSION 3.16)
project(ciplink_cpp LANGUAGES CXX)

set(CIPLINK_REPO "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "ciplink repository root")
set(CIPLINK_LIB_DIR "${CIPLINK_REPO}/target/release" CACHE PATH "directory holding the built ciplink library")

# Link the shared library.  On Windows cargo writes the import library as ciplink.dll.lib (MSVC) or ciplink.dll.a
# (GNU) next to a static ciplink.lib / libciplink.a, so name the import library first.
find_library(CIPLINK_LIBRARY NAMES ciplink.dll.lib ciplink.dll.a ciplink PATHS "${CIPLINK_LIB_DIR}" NO_DEFAULT_PATH REQUIRED)

add_library(ciplink_cpp INTERFACE)
add_library(ciplink::ciplink ALIAS ciplink_cpp)
target_include_directories(ciplink_cpp INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CIPLINK_REPO}/crates/ciplink-ffi/include")
target_compile_features(ciplink_cpp INTERFACE cxx_std_17)
target_link_libraries(ciplink_cpp INTERFACE "${CIPLINK_LIBRARY}")

add_executable(ciplink_example examples/example.cpp)
target_link_libraries(ciplink_example PRIVATE ciplink::ciplink)

add_executable(test_ciplink tests/test_ciplink.cpp)
target_link_libraries(test_ciplink PRIVATE ciplink::ciplink)

if(WIN32)
    # the executables load ciplink.dll from their own folder
    add_custom_command(TARGET test_ciplink POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CIPLINK_LIB_DIR}/ciplink.dll" "$<TARGET_FILE_DIR:test_ciplink>")
else()
    set_target_properties(ciplink_example test_ciplink PROPERTIES BUILD_RPATH "${CIPLINK_LIB_DIR}")
endif()

if(DEFINED ENV{CIPLINK_TEST_PORTS})
    enable_testing()
    add_test(NAME test_ciplink COMMAND test_ciplink $ENV{CIPLINK_TEST_PORTS}
        "${CIPLINK_REPO}/crates/ciplink/tests/fixtures/logix_descriptions.json")
endif()
