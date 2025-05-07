add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/Runner/Resources/libtensorflowlite_c-mac.dylib"
    "$<TARGET_FILE_DIR:${BINARY_NAME}>/../Resources/libtensorflowlite_c-mac.dylib"
)
