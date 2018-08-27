cmake_minimum_required(VERSION 3.11)
project(DHSM)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INSTALL_PREFIX "/tmp/foo123")

find_package(PkgConfig REQUIRED)
include(FindPkgConfig)
include(GNUInstallDirs)
pkg_check_modules(GLIB glib-2.0 REQUIRED)
include_directories(${GLIB_INCLUDE_DIRS})

add_subdirectory(config-file)
add_subdirectory(key-agent)
add_subdirectory(npm)
add_subdirectory(stm)
add_subdirectory(testserver)
