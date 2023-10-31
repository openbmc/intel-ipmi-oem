project(
  'intel-ipmi-oem',
  'cpp',
  version: '0.1',
  meson_version: '>=1.1.1',
  default_options: [
    'werror=true',
    'warning_level=3',
    'cpp_std=c++23',
  ])

# Project Arguments
all_args = [
    '-DBOOST_ERROR_CODE_HEADER_ONLY',
    '-DBOOST_SYSTEM_NO_DEPRECATED',
    '-DBOOST_ALL_NO_LIB',
    '-DBOOST_NO_RTTI',
    '-DBOOST_NO_TYPEID',
    '-DBOOST_ASIO_DISABLE_THREADS',
    '-DBOOST_COROUTINES_NO_DEPRECATION_WARNING',
    '-DBMC_VALIDATION_UNSECURE_FEATURE',
    '-DUSING_ENTITY_MANAGER_DECORATORS',
    '-Wno-psabi',
    '-Wno-pedantic',
  ]

feature_map = {
  'intel-pfr': '-DINTEL_PFR_ENABLED',
  'bmc-validation-unsecure-feature': '-DBMC_VALIDATION_UNSECURE_FEATURE',
  'using-entity-manager-decorators': '-DUSING_ENTITY_MANAGER_DECORATORS',
}

foreach option_key, option_value : feature_map
  if(get_option(option_key).allowed())
    summary(option_key,option_value, section : 'Enabled Features')
    add_project_arguments(option_value,language:'cpp')
  endif
endforeach

cpp = meson.get_compiler('cpp')
add_project_arguments(
  cpp.get_supported_arguments(all_args),
  language : 'cpp')

fs = import('fs')

root_inc = include_directories('.', 'include')

# Dependencies
sdbusplus_dep = dependency('sdbusplus')
phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')
ipmid_dep = dependency('libipmid')
channellayer_dep = dependency('libchannellayer')
userlayer_dep = dependency('libuserlayer')

if cpp.has_header_symbol(
        'nlohmann/json.hpp',
        'nlohmann::json::string_t',
        required:false)
    nlohmann_json_dep = declare_dependency()
else
    nlohmann_json_dep = dependency('nlohmann-json')
endif

tinyxml_dep = dependency('tinyxml2',
    default_options: ['tests=false'],
    include_type: 'system',
)

gpio_dep = dependency('libgpiodcxx',
      default_options: ['bindings=cxx'],
      )

zinteloemcmds_pre = declare_dependency(
  include_directories: root_inc,
  dependencies: [
    channellayer_dep,
    ipmid_dep,
    gpio_dep,
    nlohmann_json_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    tinyxml_dep,
    userlayer_dep,
  ])

prog_python = import('python').find_installation('python3')
generate_allowlist_script = files('generate-allowlist.py')
ipmiallowlist = custom_target(
    'ipmi-allowlist.hpp',
    input: [generate_allowlist_script, 'ipmi-allowlist.conf' ],
    output: 'ipmi-allowlist.hpp',
    command: [ prog_python, '@INPUT0@', '@INPUT1@', '@OUTPUT@' ],
    )

zinteloemcmds_src = [
  'src/oemcommands.cpp',
  'src/sensorcommands.cpp',
  'src/biosconfigcommands.cpp',
  'src/storagecommands.cpp',
  'src/multinodecommands.cpp',
  'src/firmware-update.cpp',
  'src/appcommands.cpp',
  'src/smbiosmdrv2handler.cpp',
  'src/manufacturingcommands.cpp',
  'src/bmccontrolservices.cpp',
  'src/bridgingcommands.cpp',
  'src/ipmi_to_redfish_hooks.cpp',
  'src/me_to_redfish_hooks.cpp',
  'src/chassiscommands.cpp',
  'src/allowlist-filter.cpp',
  'src/fruutils.cpp',
  ipmiallowlist,
]

zinteloemcmds_lib = library(
  'zinteloemcmds',
  sources: zinteloemcmds_src,
  implicit_include_directories: false,
  dependencies: zinteloemcmds_pre,
  version: meson.project_version(),
  override_options: ['b_lundef=false'],
  install: true,
  install_dir: get_option('libdir') / 'ipmid-providers')

if get_option('tests').allowed()
  subdir('tests')
endif
