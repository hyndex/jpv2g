add_executable(jpv2g_unit_test jpv2g_unit_test.c)
target_link_libraries(jpv2g_unit_test PRIVATE jpv2g::jpv2g)

add_test(NAME jpv2g_unit_test COMMAND jpv2g_unit_test)
