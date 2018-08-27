cmake_minimum_required(VERSION 3.11)
SET(CMAKE_CXX_COMPILER g++)
SET(CMAKE_C_COMPILER gcc)
SET(CMAKE_INSTALL_RPATH "/usr/local/lib64")
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

find_package(PkgConfig REQUIRED)
include(FindPkgConfig)
pkg_check_modules(GLIB glib-2.0 REQUIRED)
include_directories(${GLIB_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include )
#include_directories( /home/dpreilan/sgx/restbed/distribution/include )


set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


add_library (stm_sw MODULE init.cpp application_intf.cpp server_intf.cpp internal.h)
#set_target_properties(npm_reference PROPERTIES OUTPUT_NAME npm_reference.so)
set_target_properties(stm_sw PROPERTIES PREFIX "")


target_compile_features(stm_sw PRIVATE cxx_std_14)

target_link_libraries(stm_sw key_configfile)

install(TARGETS stm_sw
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}/stm-modules
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}/stm-modules
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}/stm-modules)