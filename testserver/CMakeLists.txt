cmake_minimum_required(VERSION 3.11)
SET(CMAKE_CXX_COMPILER g++)
SET(CMAKE_C_COMPILER gcc)
SET(CMAKE_INSTALL_RPATH "/usr/local/lib64")
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

find_package(PkgConfig REQUIRED)
include(FindPkgConfig)
pkg_check_modules(GLIB glib-2.0 gmodule-2.0 REQUIRED)
include_directories(${GLIB_INCLUDE_DIRS})
include_directories( /home/dpreilan/sgx/restbed/distribution/include )
include_directories( ${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include )



set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable (testserver testserver.cpp key_trasnfer_intf.cpp utils.cpp)
find_library(OpenSSL_LIB  crypto)
find_library(JSONCPP_LIB jsoncpp )
find_library(RESTBED_LIB restbed PATHS /home/dpreilan/sgx/restbed/distribution/library)
message(STATUS "TEST library = [" ${RESTBED_LIB} "]")

find_package(OpenSSL)

target_compile_features(testserver PRIVATE cxx_std_14)


target_link_libraries(testserver key_configfile ${JSONCPP_LIB} ${OpenSSL_LIB} ${GLIB_LIBRARIES} ${GLIB_GMODULE_LIBRARIES} ${RESTBED_LIB})
