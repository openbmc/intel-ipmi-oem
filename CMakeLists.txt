cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

cmake_policy (SET CMP0054 NEW)

option (YOCTO_DEPENDENCIES "Use YOCTO depedencies system" OFF)
include (ExternalProject)
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti")

project (intel-ipmi-oem CXX)

add_definitions (-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions (-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions (-DBOOST_ALL_NO_LIB)
add_definitions (-DBOOST_NO_RTTI)
add_definitions (-DBOOST_NO_TYPEID)

if (NOT ${YOCTO_DEPENDENCIES})
    configure_file (CMakeLists.txt.in 3rdparty/CMakeLists.txt)
    execute_process (
        COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty
    )
    execute_process (
        COMMAND ${CMAKE_COMMAND} --build .
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty
    )

    set (CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR}/prefix ${CMAKE_PREFIX_PATH})
    include_directories (${CMAKE_BINARY_DIR}/prefix/include)
endif ()

# sdbusplus
if (NOT ${YOCTO_DEPENDENCIES})
    include_directories (${CMAKE_BINARY_DIR}/sdbusplus-src)
    link_directories (${CMAKE_BINARY_DIR}/sdbusplus-src/.libs)
endif ()


if (${YOCTO_DEPENDENCIES})
    find_package (PkgConfig REQUIRED)
    pkg_check_modules (LOGGING phosphor-logging REQUIRED)
    include_directories (${LOGGING_INCLUDE_DIRS})
    link_directories (${LOGGING_LIBRARY_DIRS})
endif ()

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library (oemcmds SHARED src/oemcommands.cpp ${CMAKE_BINARY_DIR}/phosphor-host-ipmid-src/utils.cpp)
set_target_properties (oemcmds PROPERTIES VERSION "0.1.0")
set_target_properties (oemcmds PROPERTIES SOVERSION "0")
target_link_libraries (oemcmds sdbusplus)
target_link_libraries (oemcmds ${LOGGING_LIBRARIES})

install (TARGETS oemcmds DESTINATION lib/ipmid-providers)

