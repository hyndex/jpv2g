cmake_minimum_required(VERSION 3.16)

project(jpv2g VERSION 1.0.0
        DESCRIPTION "Microcontroller-focused platform-independent V2G library"
        LANGUAGES C
)

option(JPV2G_BUILD_EXAMPLES "Build usage examples" OFF)
option(JPV2G_BUILD_TESTING "Build unit tests" OFF)
option(JPV2G_INSTALL "Install jpv2g library and headers" ON)
option(JPV2G_ENABLE_CBV2G_CODEC "Enable cbv2g-backed EXI codec and full EVCC/SECC stack" ON)
option(JPV2G_BUNDLE_CBV2G "Build bundled cbv2g sources from 3rd_party" ON)
set(JPV2G_CBV2G_INCLUDE_DIR "" CACHE PATH "External cbv2g include directory (parent of cbv2g/)")
set(JPV2G_CBV2G_LIBRARY "" CACHE FILEPATH "External cbv2g library when not bundling")

set(JPV2G_CORE_SOURCES
    src/backend.c
    src/byte_utils.c
    src/cbv2g_adapter.c
    src/codec.c
    src/config.c
    src/config_loader.c
    src/discovery.c
    src/ev_controller.c
    src/evse_controller.c
    src/handler.c
    src/net_iface.c
    src/sdp.c
    src/security.c
    src/session.c
    src/session_ctx.c
    src/simple_flow.c
    src/state_evcc.c
    src/state_machine.c
    src/state_secc.c
    src/time_compat.c
    src/tls.c
    src/transport.c
    src/v2gtp.c
)

set(JPV2G_FULL_SOURCES
    src/cbv2g_codec.c
    src/evcc.c
    src/secc.c
)

if(JPV2G_ENABLE_CBV2G_CODEC)
    if(JPV2G_BUNDLE_CBV2G)
        add_subdirectory(3rd_party/cbv2g)
    elseif(NOT JPV2G_CBV2G_INCLUDE_DIR)
        message(FATAL_ERROR
            "JPV2G_ENABLE_CBV2G_CODEC=ON with JPV2G_BUNDLE_CBV2G=OFF requires JPV2G_CBV2G_INCLUDE_DIR")
    endif()
endif()

add_library(jpv2g)
add_library(jpv2g::jpv2g ALIAS jpv2g)

target_compile_features(jpv2g PUBLIC c_std_99)

target_include_directories(jpv2g
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_sources(jpv2g PRIVATE ${JPV2G_CORE_SOURCES})

if(JPV2G_ENABLE_CBV2G_CODEC)
    target_compile_definitions(jpv2g PUBLIC JPV2G_ENABLE_CBV2G_CODEC=1)
    target_sources(jpv2g PRIVATE ${JPV2G_FULL_SOURCES})

    if(TARGET cbv2g)
        target_link_libraries(jpv2g PUBLIC cbv2g::cbv2g)
    else()
        target_include_directories(jpv2g PUBLIC "${JPV2G_CBV2G_INCLUDE_DIR}")
        if(JPV2G_CBV2G_LIBRARY)
            target_link_libraries(jpv2g PUBLIC "${JPV2G_CBV2G_LIBRARY}")
        endif()
    endif()
endif()

if(JPV2G_BUILD_EXAMPLES)
    add_executable(jpv2g_mcu_usage_stub examples/microcontroller_usage_stub.c)
    target_link_libraries(jpv2g_mcu_usage_stub PRIVATE jpv2g::jpv2g)
endif()

if(JPV2G_BUILD_TESTING)
    include(CTest)
    add_subdirectory(tests)
endif()

if(JPV2G_INSTALL)
    install(
        TARGETS jpv2g
        EXPORT jpv2g-targets
    )

    if(TARGET cbv2g)
        install(
            TARGETS cbv2g
            EXPORT jpv2g-targets
        )
        install(
            DIRECTORY 3rd_party/cbv2g/include/
            TYPE INCLUDE
        )
    endif()

    install(
        DIRECTORY include/
        TYPE INCLUDE
    )

    install(
        EXPORT jpv2g-targets
        FILE jpv2g-targets.cmake
        NAMESPACE jpv2g::
        DESTINATION lib/cmake/jpv2g
    )
endif()
