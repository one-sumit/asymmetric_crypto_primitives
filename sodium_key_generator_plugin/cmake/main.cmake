add_subdirectory(sodium_key_generator)
target_link_libraries(${PLUGIN_NAME} PRIVATE ${CRATE_NAME})