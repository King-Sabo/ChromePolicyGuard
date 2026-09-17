cmake_minimum_required(VERSION 3.15)
project(ChromePolicyGuard LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static CRT (/MT, /MTd) - matches the .vcxproj, no VC++ redist needed on the target.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Console subsystem (no WIN32): the entry point is _tmain, and the service
# dispatcher is started from there. WIN32 would require WinMain -> LNK2019.
add_executable(ChromePolicyGuard
    main.cpp
    resource.h
    ChromePolicyGuard.rc
)

# rc.exe needs to find resource.h when building out-of-tree.
target_include_directories(ChromePolicyGuard PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(ChromePolicyGuard PRIVATE _UNICODE UNICODE)
target_link_libraries(ChromePolicyGuard PRIVATE advapi32)

if(MINGW)
    target_link_options(ChromePolicyGuard PRIVATE -municode)   # wmain entry point
endif()
