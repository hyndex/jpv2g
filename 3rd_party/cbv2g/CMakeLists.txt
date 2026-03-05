cmake_minimum_required(VERSION 3.16)

project(cbv2g_embedded LANGUAGES C)

file(GLOB_RECURSE CBV2G_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/lib/cbv2g/*.c"
)

add_library(cbv2g STATIC ${CBV2G_SOURCES})
add_library(cbv2g::cbv2g ALIAS cbv2g)

target_compile_features(cbv2g PUBLIC c_std_99)

target_include_directories(cbv2g
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
