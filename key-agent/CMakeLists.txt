cmake_minimum_required(VERSION 3.11)

message(STATUS "FOO1 = [" ${PROJECT_SOURCE_DIR} "]")
add_subdirectory(src)
add_subdirectory(cli)


install(FILES  key_agent.h types.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/key-agent)

install(FILES  npm/npm.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/key-agent/npm)
install(FILES  stm/stm.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/key-agent/stm)