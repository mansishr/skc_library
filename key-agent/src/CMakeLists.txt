cmake_minimum_required(VERSION 3.11)
SET(CMAKE_CXX_COMPILER g++)
SET(CMAKE_C_COMPILER gcc)
SET(CMAKE_INSTALL_RPATH "/usr/local/lib64")
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

find_package(PkgConfig REQUIRED)
include(FindPkgConfig)
pkg_check_modules(GLIB glib-2.0 gmodule-2.0 REQUIRED)
include_directories(${GLIB_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include )
#include_directories( /home/dpreilan/sgx/restbed/distribution/include )


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library (key_agent SHARED intf.cpp curl.cpp cert.cpp key_init.cpp utils.cpp ../stm/stm_init.cpp ../npm/npm_init.cpp cache-common.cpp cache-init.cpp cache-session.cpp session.cpp)
find_library(OpenSSL_LIB  crypto)
find_library(CURL_LIB  curl)
#find_library(JSONCPP_LIB jsoncpp )
#find_library(RESTBED_LIB restbed PATHS /home/dpreilan/sgx/restbed/distribution/library)
#message(STATUS "TEST library = [" ${RESTBED_LIB} "]")

find_package(OpenSSL)

target_compile_features(key_agent PRIVATE cxx_std_14)


target_link_libraries(key_agent ${CURL_LIB} ${OpenSSL_LIB} ${GLIB_LIBRARIES} ${GLIB_GMODULE_LIBRARIES} key_configfile)

install(TARGETS key_agent
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

