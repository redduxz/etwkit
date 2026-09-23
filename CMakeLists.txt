cmake_minimum_required(VERSION 3.20)
project(etwkit CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(etwkit
    src/main.cpp
    src/session.cpp
    src/decoder.cpp
    src/console.cpp
    src/enrich.cpp
)

target_compile_options(etwkit PRIVATE /W3 /O2)
target_link_libraries(etwkit PRIVATE tdh advapi32)
