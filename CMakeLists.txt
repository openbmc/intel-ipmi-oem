cmake_minimum_required (VERSION 3.2 FATAL_ERROR)
include (ExternalProject)
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti")

option (HUNTER_ENABLED "Enable hunter package pulling" OFF)
include ("cmake/HunterGate.cmake")

huntergate (
    URL "https://github.com/ruslo/hunter/archive/v0.18.64.tar.gz" SHA1
    "baf9c8cc4f65306f0e442b5419967b4c4c04589a"
)

project (intel-ipmi-oem CXX C)

find_package (Boost REQUIRED)
include_directories (${Boost_INCLUDE_DIRS})

add_definitions (-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions (-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions (-DBOOST_ALL_NO_LIB)
add_definitions (-DBOOST_NO_RTTI)
add_definitions (-DBOOST_NO_TYPEID)

find_package (Threads)

option (YOCTO "Enable Building In Yocto" OFF)
if (NOT YOCTO)
    externalproject_add (
        Boost URL
        https://dl.bintray.com/boostorg/release/1.66.0/source/boost_1_66_0.tar.gz
        URL_MD5 d275cd85b00022313c171f602db59fc5 SOURCE_DIR
        "${CMAKE_BINARY_DIR}/boost-src" BINARY_DIR
        "${CMAKE_BINARY_DIR}/boost-build" CONFIGURE_COMMAND "" BUILD_COMMAND ""
        INSTALL_COMMAND mkdir -p "${CMAKE_BINARY_DIR}/prefix/include/" && cp -R
        ${CMAKE_BINARY_DIR}/boost-src/boost ${CMAKE_BINARY_DIR}/prefix/include
    )

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

option (ENABLE_TEST "Enable Google Test" ON)
if (ENABLE_TEST)
    set (SENSOR_TEST_SRC tests/test_sensorcommands.cpp src/sensorutils.cpp)
    hunter_add_package (GTest)
    find_package (GTest CONFIG REQUIRED)

    enable_testing ()

    add_executable (runSensorTests ${SENSOR_TEST_SRC})
    add_test (NAME test_sensorcommands COMMAND runSensorTests)
    target_link_libraries (
        runSensorTests GTest::main GTest::gtest ${CMAKE_THREAD_LIBS_INIT}
    )
endif ()

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

#
# import OpenSSL (crypto)
find_package (OpenSSL REQUIRED)
include_directories (${OPENSSL_INCLUDE_DIR})

add_library (
    sensorcommands SHARED src/sensorcommands.cpp src/sensorutils.cpp
    phosphor-ipmi-host/utils.cpp src/storagecommands.cpp
)
set_target_properties (sensorcommands PROPERTIES VERSION "0.1.0")
set_target_properties (sensorcommands PROPERTIES SOVERSION "0")
target_link_libraries (sensorcommands ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (sensorcommands sdbusplus)

install (TARGETS sensorcommands DESTINATION
                 lib/ipmid-providers)
