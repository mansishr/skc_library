cmake_minimum_required(VERSION 3.11)
SET(CMAKE_CXX_COMPILER g++)
SET(CMAKE_C_COMPILER gcc)
SET(CMAKE_INSTALL_RPATH "/usr/local/lib64")
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

#find_package(PkgConfig REQUIRED)
#include(FindPkgConfig)
#pkg_check_modules(GLIB glib-2.0 REQUIRED)
#include_directories(${GLIB_INCLUDE_DIRS})


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
include_directories( ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include )

add_executable (keyagent-cli main.c)
#find_library(OpenSSL_LIB  crypto)
#find_library(JSONCPP_LIB jsoncpp )
#message(STATUS "TEST library = [" ${RESTBED_LIB} "]")

#find_package(OpenSSL)

target_compile_features(keyagent-cli PRIVATE cxx_std_14)


#target_link_libraries(testserver ${JSONCPP_LIB} ${OpenSSL_LIB} ${GLIB_LIBRARIES} ${RESTBED_LIB})
target_link_libraries(keyagent-cli key_agent)
