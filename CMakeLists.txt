cmake_minimum_required (VERSION 3.2 FATAL_ERROR)
include (ExternalProject)
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti")

project (ipmi-providers CXX C)

add_definitions (-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions (-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions (-DBOOST_ALL_NO_LIB)
add_definitions (-DBOOST_NO_RTTI)
add_definitions (-DBOOST_NO_TYPEID)


option (YOCTO "Enable Building In Yocto" OFF)
if (NOT YOCTO)
    # headers that can't be built without yocto
    include_directories (non-yocto)

    include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include/phosphor-ipmi-host)
    include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include/sdbusplus)
    include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include/phosphor-logging)
else () # import phosphor-logging
    find_package (PkgConfig REQUIRED)
    pkg_check_modules (LOGGING phosphor-logging REQUIRED)
    include_directories (${LOGGING_INCLUDE_DIRS})
    link_directories (${LOGGING_LIBRARY_DIRS})
endif ()

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library (oemcmds SHARED src/oemcommands.cpp include/phosphor-ipmi-host/utils.cpp)
set_target_properties (oemcmds PROPERTIES VERSION "0.1.0")
set_target_properties (oemcmds PROPERTIES SOVERSION "0")
target_link_libraries (oemcmds sdbusplus)
target_link_libraries (oemcmds ${LOGGING_LIBRARIES})

install (TARGETS oemcmds DESTINATION lib/ipmid-providers)

