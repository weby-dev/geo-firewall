cmake_minimum_required(VERSION 3.10)
project(webup_firewall CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Position-independent executables (ASLR) + warnings + hardening.
# Optimization level comes from CMAKE_BUILD_TYPE (Release => -O3 -DNDEBUG); we
# don't pin -O2 here so the hot packet path gets the full Release treatment.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_options(-Wall -Wextra
  -fstack-protector-strong
  $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>)
add_link_options(-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack)

# Link-time optimization (Release): lets the geo/asn/policy/packet hot path
# inline across translation units. Enabled only where the toolchain supports it.
include(CheckIPOSupported)
check_ipo_supported(RESULT HAS_IPO OUTPUT IPO_MSG)
if(HAS_IPO AND CMAKE_BUILD_TYPE STREQUAL "Release")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  message(STATUS "LTO / interprocedural optimization: enabled")
else()
  message(STATUS "LTO / interprocedural optimization: disabled (${IPO_MSG})")
endif()

# -fstack-clash-protection is supported by recent gcc/clang on common arches.
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-fstack-clash-protection HAS_STACK_CLASH)
if(HAS_STACK_CLASH)
  add_compile_options(-fstack-clash-protection)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(MNL  REQUIRED libmnl)
pkg_check_modules(NFQ  REQUIRED libnetfilter_queue)

pkg_check_modules(MMDB libmaxminddb)
if(NOT MMDB_FOUND)
  find_path(MMDB_INCLUDE_DIRS maxminddb.h)
  find_library(MMDB_LIBRARIES NAMES maxminddb)
endif()

# Optional: systemd readiness/watchdog notifications.
pkg_check_modules(SYSTEMD libsystemd)

# --- daemon -----------------------------------------------------------------
add_executable(webup-firewall
  src/main.cpp
  src/config.cpp
  src/geoip.cpp
  src/asn.cpp
  src/policy.cpp
  src/packet.cpp
  src/stats.cpp
)
target_include_directories(webup-firewall PRIVATE
  ${MNL_INCLUDE_DIRS} ${NFQ_INCLUDE_DIRS} ${MMDB_INCLUDE_DIRS})
target_link_libraries(webup-firewall PRIVATE
  ${NFQ_LIBRARIES} ${MNL_LIBRARIES} ${MMDB_LIBRARIES} pthread)

if(SYSTEMD_FOUND)
  target_compile_definitions(webup-firewall PRIVATE HAVE_SYSTEMD)
  target_include_directories(webup-firewall PRIVATE ${SYSTEMD_INCLUDE_DIRS})
  target_link_libraries(webup-firewall PRIVATE ${SYSTEMD_LIBRARIES})
  message(STATUS "systemd watchdog/readiness support: enabled")
else()
  message(STATUS "systemd watchdog/readiness support: disabled (libsystemd not found)")
endif()

install(TARGETS webup-firewall RUNTIME DESTINATION sbin)

# --- tests (portable: no netfilter/geoip deps) ------------------------------
enable_testing()
add_executable(webup-tests
  tests/test_parser.cpp
  src/packet.cpp
  src/policy.cpp
  src/config.cpp
)
target_include_directories(webup-tests PRIVATE src)
add_test(NAME unit COMMAND webup-tests)
