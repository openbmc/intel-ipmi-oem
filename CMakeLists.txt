cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

cmake_policy (SET CMP0054 NEW)

option (YOCTO "Use YOCTO depedencies system" OFF)
include (ExternalProject)
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")

project (intel-ipmi-oem CXX)

option (HUNTER_ENABLED "Enable hunter package pulling" OFF)
include ("cmake/HunterGate.cmake")

huntergate (
    URL "https://github.com/ruslo/hunter/archive/v0.18.64.tar.gz" SHA1
    "baf9c8cc4f65306f0e442b5419967b4c4c04589a"
)

add_definitions (-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions (-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions (-DBOOST_ALL_NO_LIB)
add_definitions (-DBOOST_NO_RTTI)
add_definitions (-DBOOST_NO_TYPEID)

if (NOT YOCTO)
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
if (NOT YOCTO)
    include_directories (${CMAKE_BINARY_DIR}/sdbusplus-src)
    link_directories (${CMAKE_BINARY_DIR}/sdbusplus-src/.libs)
endif ()

if (YOCTO)
    find_package (PkgConfig REQUIRED)
    pkg_check_modules (LOGGING phosphor-logging REQUIRED)
    include_directories (${LOGGING_INCLUDE_DIRS})
    link_directories (${LOGGING_LIBRARY_DIRS})

endif ()

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

option (ENABLE_TEST "Enable Google Test" OFF)
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

add_library (oemcmds SHARED src/oemcommands.cpp phosphor-ipmi-host/utils.cpp)
set_target_properties (oemcmds PROPERTIES VERSION "0.1.0")
set_target_properties (oemcmds PROPERTIES SOVERSION "0")
target_link_libraries (oemcmds sdbusplus)
target_link_libraries (oemcmds ${LOGGING_LIBRARIES})

add_library (
    sensorcommands SHARED src/sensorcommands.cpp src/sensorutils.cpp
    phosphor-ipmi-host/utils.cpp src/storagecommands.cpp
)
set_target_properties (sensorcommands PROPERTIES VERSION "0.1.0")
set_target_properties (sensorcommands PROPERTIES SOVERSION "0")
target_link_libraries (sensorcommands ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (sensorcommands sdbusplus)

add_library (zstoragecommands SHARED src/storagecommands.cpp)
set_target_properties (zstoragecommands PROPERTIES VERSION "0.1.0")
set_target_properties (zstoragecommands PROPERTIES SOVERSION "0")
target_link_libraries (zstoragecommands ${CMAKE_THREAD_LIBS_INIT})

install (
    TARGETS oemcmds sensorcommands zstoragecommands
    DESTINATION lib/ipmid-providers
)
