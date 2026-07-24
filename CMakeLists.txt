cmake_minimum_required(VERSION 3.16)

project(jpv2g VERSION 1.0.0
        DESCRIPTION "Microcontroller-focused platform-independent V2G library"
        LANGUAGES C
)

option(JPV2G_BUILD_EXAMPLES "Build usage examples" OFF)
option(JPV2G_BUILD_TESTING "Build unit tests" OFF)
option(JPV2G_INSTALL "Install jpv2g library and headers" ON)
# Host-side compile gate for the mbedtls TLS branch (src/tls.c,
# src/security.c). OFF by default: the shipping firmware defines
# HAVE_MBEDTLS through its own build (never through CMake), and default
# builds must stay byte-identical in behavior (TLS wrap -> -ENOTSUP).
option(JPV2G_HAVE_MBEDTLS "Compile the mbedtls-backed TLS branch (defines HAVE_MBEDTLS, links mbedtls 2.28)" OFF)
option(JPV2G_ENABLE_CBV2G_CODEC "Enable cbv2g-backed EXI codec and full EVCC/SECC stack" ON)
option(JPV2G_BUNDLE_CBV2G "Build bundled cbv2g sources from 3rd_party" ON)
# ISO 15118-20 DC SECC module (DC + EIM + Scheduled). OFF by default: a
# default build stays byte-identical in behavior — -20 SAP offers simply
# fail to match and the EV falls back to -2/DIN. src/secc_iso20.c is always
# compiled (its body collapses to -ENOTSUP stubs when the flag is off, same
# pattern as the no-mbedtls branch of src/tls.c).
option(JPV2G_ENABLE_ISO20 "Enable the ISO 15118-20 DC SECC module" OFF)
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
    src/secc_iso20.c
)

# The -20 module needs exactly these 6 generated codec files — never the
# upstream cbv2g_iso20 target, which drags in AC/ACDP/WPT (~77k dead LOC).
# NOTE: the firmware's extra_script.py has NO corresponding source filter —
# it BuildSources the whole cbv2g tree and relies on --gc-sections to drop
# the unreferenced codecs. If JPV2G_ENABLE_ISO20 is ever turned ON in the
# firmware, nothing there enforces this 6-file footprint; re-verify the
# flash budget then. (The bundled-cbv2g glob also compiles them into
# libcbv2g.a; the duplicate archive members are inert — the linker resolves
# each symbol once — and this explicit list is what makes an external-cbv2g
# build work at all.)
set(JPV2G_ISO20_CODEC_SOURCES
    3rd_party/cbv2g/lib/cbv2g/iso_20/iso20_CommonMessages_Datatypes.c
    3rd_party/cbv2g/lib/cbv2g/iso_20/iso20_CommonMessages_Decoder.c
    3rd_party/cbv2g/lib/cbv2g/iso_20/iso20_CommonMessages_Encoder.c
    3rd_party/cbv2g/lib/cbv2g/iso_20/iso20_DC_Datatypes.c
    3rd_party/cbv2g/lib/cbv2g/iso_20/iso20_DC_Decoder.c
    3rd_party/cbv2g/lib/cbv2g/iso_20/iso20_DC_Encoder.c
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

if(JPV2G_HAVE_MBEDTLS)
    # HAVE_MBEDTLS changes the layout of jpv2g_tls_socket_t (tls.h), so the
    # define must be PUBLIC: every translation unit that includes tls.h has
    # to agree with the library or the struct ABIs diverge silently.
    target_compile_definitions(jpv2g PUBLIC HAVE_MBEDTLS=1)
    find_path(JPV2G_MBEDTLS_INCLUDE_DIR NAMES mbedtls/ssl.h)
    find_library(JPV2G_MBEDTLS_LIBRARY NAMES mbedtls)
    find_library(JPV2G_MBEDTLS_X509_LIBRARY NAMES mbedx509)
    find_library(JPV2G_MBEDTLS_CRYPTO_LIBRARY NAMES mbedcrypto)
    if(NOT JPV2G_MBEDTLS_INCLUDE_DIR OR NOT JPV2G_MBEDTLS_LIBRARY
       OR NOT JPV2G_MBEDTLS_X509_LIBRARY OR NOT JPV2G_MBEDTLS_CRYPTO_LIBRARY)
        message(FATAL_ERROR
            "JPV2G_HAVE_MBEDTLS=ON but mbedtls (2.28.x) was not found. Set "
            "JPV2G_MBEDTLS_INCLUDE_DIR, JPV2G_MBEDTLS_LIBRARY, "
            "JPV2G_MBEDTLS_X509_LIBRARY and JPV2G_MBEDTLS_CRYPTO_LIBRARY.")
    endif()
    # Only tls.c / security.c include mbedtls headers, so the include dir
    # stays PRIVATE; the libraries are PUBLIC so consumers of the static
    # archive resolve the mbedtls symbols it references (order: ssl ->
    # x509 -> crypto).
    target_include_directories(jpv2g PRIVATE "${JPV2G_MBEDTLS_INCLUDE_DIR}")
    target_link_libraries(jpv2g PUBLIC
        "${JPV2G_MBEDTLS_LIBRARY}"
        "${JPV2G_MBEDTLS_X509_LIBRARY}"
        "${JPV2G_MBEDTLS_CRYPTO_LIBRARY}")
endif()

if(JPV2G_ENABLE_CBV2G_CODEC)
    target_compile_definitions(jpv2g PUBLIC JPV2G_ENABLE_CBV2G_CODEC=1)
    target_sources(jpv2g PRIVATE ${JPV2G_FULL_SOURCES})

    if(JPV2G_ENABLE_ISO20)
        # PUBLIC: the tests (and any consumer probing for -20 support) gate
        # their -20 code paths on the same macro the library was built with.
        target_compile_definitions(jpv2g PUBLIC JPV2G_ENABLE_ISO20=1)
        target_sources(jpv2g PRIVATE ${JPV2G_ISO20_CODEC_SOURCES})
    endif()

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
