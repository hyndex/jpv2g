add_executable(jpv2g_unit_test jpv2g_unit_test.c)
target_link_libraries(jpv2g_unit_test PRIVATE jpv2g::jpv2g)
target_include_directories(jpv2g_unit_test PRIVATE "${PROJECT_SOURCE_DIR}/src")

add_test(NAME jpv2g_unit_test COMMAND jpv2g_unit_test)

add_test(
    NAME jpv2g_no_automatic_secc_exi_documents
    COMMAND "${CMAKE_COMMAND}"
            "-DSECC_SOURCE=${PROJECT_SOURCE_DIR}/src/secc.c"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/forbid_automatic_exi_docs.cmake"
)
