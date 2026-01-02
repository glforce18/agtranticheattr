cmake_minimum_required(VERSION 3.15)
project(agtr_anticheat VERSION 2.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/W3)
endif()

add_library(dinput SHARED dinput_proxy.cpp dinput.def)
target_link_libraries(dinput PRIVATE psapi advapi32)
set_target_properties(dinput PROPERTIES OUTPUT_NAME "dinput" PREFIX "" SUFFIX ".dll")
