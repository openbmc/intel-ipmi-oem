cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

cmake_policy (SET CMP0054 NEW)

option (YOCTO "Use YOCTO depedencies system" OFF)
include (ExternalProject)
set (CMAKE_CXX_STANDARD 20)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

option (USING_ENTITY_MANAGER_DECORATORS
        "Enable using EM decorators to map FRUs to entity IDs" ON)

set (
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -Werror \
    -Wtype-limits \
    -Wnull-dereference \
"
)

project (intel-ipmi-oem CXX)

add_definitions (-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions (-DBOOST_SYSTEM_NO_DEPRECATED)
add_definitions (-DBOOST_ALL_NO_LIB)
add_definitions (-DBOOST_NO_RTTI)
add_definitions (-DBOOST_NO_TYPEID)
add_definitions (-DBOOST_ASIO_DISABLE_THREADS)
add_definitions (-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
add_definitions (-Wno-psabi)

if (NOT YOCTO) # headers that can't be built without yocto

    execute_process(
        COMMAND ${CMAKE_CXX_COMPILER} -dumpmachine
        OUTPUT_VARIABLE TRIPLE OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Target triple: ${TRIPLE}")

    include_directories (SYSTEM non-yocto)

    configure_file (CMakeLists.txt.in 3rdparty/CMakeLists.txt)
    execute_process (COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)
    execute_process (COMMAND ${CMAKE_COMMAND} --build .
                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)

    set (CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR}/prefix ${CMAKE_PREFIX_PATH})
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/prefix/include)
    link_directories (${CMAKE_BINARY_DIR}/prefix/lib)
    link_directories (${CMAKE_BINARY_DIR}/prefix/lib/${TRIPLE})

    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/sdbusplus-src)
    link_directories (${CMAKE_BINARY_DIR}/sdbusplus-src/.libs)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/phosphor-logging-src)
    link_directories (${CMAKE_BINARY_DIR}/phosphor-logging-src/.libs)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/phosphor-ipmi-host/include)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}/ipmid/user_channel)
    include_directories (SYSTEM ${CMAKE_BINARY_DIR}) # link_directories  (${CMAK
                                                     # E_BINARY_DIR}/sdbusplus-
                                                     # src/.libs)
endif ()

if (YOCTO)
    find_package (PkgConfig REQUIRED)
    pkg_check_modules (LOGGING phosphor-logging REQUIRED)
    include_directories (SYSTEM ${LOGGING_INCLUDE_DIRS})
    link_directories (${LOGGING_LIBRARY_DIRS})

    pkg_check_modules (LIBIPMID libipmid REQUIRED)
    include_directories (SYSTEM ${LIBIPMID_INCLUDE_DIRS})
    link_directories (${LIBIPMID_LIBRARY_DIRS})

endif ()

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

if (NOT YOCTO)
    set (SENSOR_TEST_SRC tests/test_sensorcommands.cpp)

    find_package (GTest REQUIRED)

    enable_testing ()

    add_executable (runSensorTests ${SENSOR_TEST_SRC})
    add_test (NAME test_sensorcommands COMMAND runSensorTests)
    target_link_libraries (runSensorTests ${GTEST_BOTH_LIBRARIES}
                           ${CMAKE_THREAD_LIBS_INIT} sdbusplus -lsystemd)
endif ()
#
# import OpenSSL (crypto)
find_package (OpenSSL REQUIRED)
include_directories (SYSTEM ${OPENSSL_INCLUDE_DIR})

include_directories (SYSTEM ${CMAKE_BINARY_DIR})
add_custom_command(OUTPUT include/ipmi-allowlist.hpp
                  COMMAND ./generate-allowlist.py
                  ARGS ipmi-allowlist.conf ${CMAKE_BINARY_DIR}/ipmi-allowlist.hpp
                  MAIN_DEPENDENCY ipmi-allowlist.conf
                  DEPENDS generate-allowlist.py
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_library (zinteloemcmds
             SHARED src/oemcommands.cpp src/sensorcommands.cpp src/biosconfigcommands.cpp
             src/storagecommands.cpp src/multinodecommands.cpp
             src/firmware-update.cpp src/appcommands.cpp src/smbioshandler.cpp
             src/smbiosmdrv2handler.cpp src/manufacturingcommands.cpp
             src/bmccontrolservices.cpp src/bridgingcommands.cpp
             src/ipmi_to_redfish_hooks.cpp src/me_to_redfish_hooks.cpp
             src/chassiscommands.cpp src/allowlist-filter.cpp
             include/ipmi-allowlist.hpp)
set_target_properties (zinteloemcmds PROPERTIES VERSION "0.1.0")
set_target_properties (zinteloemcmds PROPERTIES SOVERSION "0")
target_link_libraries (zinteloemcmds stdc++fs)
target_link_libraries (zinteloemcmds ipmid)
target_link_libraries (zinteloemcmds sdbusplus)
target_link_libraries (zinteloemcmds phosphor_logging)
target_link_libraries (zinteloemcmds -luserlayer)
target_link_libraries (zinteloemcmds -lchannellayer)
target_link_libraries (zinteloemcmds ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries (zinteloemcmds gpiodcxx)

find_package (tinyxml2 REQUIRED)
target_link_libraries (zinteloemcmds tinyxml2)

install (TARGETS zinteloemcmds DESTINATION lib/ipmid-providers)
option (INTEL_PFR_ENABLED "Intel PFR Enabled" OFF)
option (BMC_VALIDATION_UNSECURE_FEATURE
        "Enables unsecure features required by validation. Note: must
        be turned off for production images."
        OFF)
option (MDR_V1_SUPPORT "Support these MDR Verseion 1 IPMI OEM commands" OFF)

target_compile_definitions (
    zinteloemcmds PRIVATE
    $<$<BOOL:${INTEL_PFR_ENABLED}>: -DINTEL_PFR_ENABLED>
    $<$<BOOL:${BMC_VALIDATION_UNSECURE_FEATURE}>:
    -DBMC_VALIDATION_UNSECURE_FEATURE>
    $<$<BOOL:${MDR_V1_SUPPORT}>: -DMDR_V1_SUPPORT>
    $<$<BOOL:${USING_ENTITY_MANAGER_DECORATORS}>:
    -DUSING_ENTITY_MANAGER_DECORATORS>
)

# Code Coverage
if (NOT YOCTO)
    # non-Debug build may generate misleading code coverage results.
    set(CMAKE_BUILD_TYPE Debug)
    message(WARNING "Using Debug build type!")
    include(CodeCoverage)
    APPEND_COVERAGE_COMPILER_FLAGS()
    # check-code-coverage is a required name by
    # openbmc-build-scripts/scripts/unit-test.py#L487.
    SETUP_TARGET_FOR_COVERAGE_LCOV(
        NAME check-code-coverage
        EXECUTABLE runSensorTests
        DEPENDENCIES runSensorTests
        EXCLUDE "/usr/include/*" "/usr/local/include/*" "prefix/*"
    )
endif ()
