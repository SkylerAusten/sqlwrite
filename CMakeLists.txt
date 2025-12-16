cmake_minimum_required(VERSION 3.16)
project(sqlwrite VERSION 1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Options
option(USE_SYSTEM_SQLITE "Use system SQLite instead of fetching latest" OFF)
option(USE_BUNDLED_SQLITE "Use bundled SQLite amalgamation" OFF)
option(USE_SYSTEM_FMT "Use system fmt library" OFF)
option(USE_BUNDLED_FMT "Use bundled fmt library" ON)

include(FetchContent)

# Find required packages
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

# SQLite setup
if(USE_BUNDLED_SQLITE)
    message(STATUS "Using bundled SQLite amalgamation")
    add_library(sqlite3 SHARED sqlite3.c)
    target_compile_definitions(sqlite3 PRIVATE
        SQLITE_ENABLE_LOAD_EXTENSION=1
        SQLITE_ENABLE_COLUMN_METADATA=1
    )
    target_include_directories(sqlite3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    if(UNIX AND NOT APPLE)
        target_link_libraries(sqlite3 PRIVATE pthread dl m)
    endif()
    set(SQLITE3_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    set(SQLITE3_LIBRARY sqlite3)
elseif(USE_SYSTEM_SQLITE)
    find_package(SQLite3 REQUIRED)
    set(SQLITE3_INCLUDE_DIR ${SQLite3_INCLUDE_DIRS})
    set(SQLITE3_LIBRARY SQLite::SQLite3)
else()
    # Fetch latest SQLite (3.51.1 as of Dec 2024)
    message(STATUS "Fetching latest SQLite 3.51.1")
    FetchContent_Declare(
        sqlite3_fetch
        URL https://www.sqlite.org/2025/sqlite-amalgamation-3510100.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(sqlite3_fetch)
    
    add_library(sqlite3 SHARED ${sqlite3_fetch_SOURCE_DIR}/sqlite3.c)
    target_compile_definitions(sqlite3 PRIVATE
        SQLITE_ENABLE_LOAD_EXTENSION=1
        SQLITE_ENABLE_COLUMN_METADATA=1
    )
    target_include_directories(sqlite3 PUBLIC ${sqlite3_fetch_SOURCE_DIR})
    if(UNIX AND NOT APPLE)
        target_link_libraries(sqlite3 PRIVATE pthread dl m)
    endif()
    set(SQLITE3_INCLUDE_DIR ${sqlite3_fetch_SOURCE_DIR})
    set(SQLITE3_LIBRARY sqlite3)
endif()

# fmt setup
if(USE_BUNDLED_FMT)
    message(STATUS "Using bundled fmt library")
    add_library(fmt_lib STATIC
        fmt/src/format.cc
        fmt/src/os.cc
    )
    target_include_directories(fmt_lib PUBLIC fmt/include)
    set(FMT_LIBRARY fmt_lib)
elseif(USE_SYSTEM_FMT)
    find_package(fmt REQUIRED)
    set(FMT_LIBRARY fmt::fmt)
else()
    message(STATUS "Fetching fmt library")
    FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 10.2.1
    )
    FetchContent_MakeAvailable(fmt)
    set(FMT_LIBRARY fmt::fmt)
endif()

# nlohmann_json (header-only, use bundled)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/json.hpp)
    message(STATUS "Using bundled nlohmann/json")
    add_library(nlohmann_json INTERFACE)
    target_include_directories(nlohmann_json INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
else()
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# SQLwrite extension library
add_library(sqlwrite_ext SHARED sqlwrite.cpp)
target_include_directories(sqlwrite_ext PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SQLITE3_INCLUDE_DIR}
)
target_link_libraries(sqlwrite_ext PRIVATE
    ${FMT_LIBRARY}
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_compile_definitions(sqlwrite_ext PRIVATE NDEBUG)
set_target_properties(sqlwrite_ext PROPERTIES
    OUTPUT_NAME "sqlwrite"
    PREFIX ""
)

# SQLite shell binary with sqlwrite built-in
# Always use bundled shell.c + sqlite3.c since they must match versions
add_library(sqlite3_for_shell SHARED sqlite3.c)
target_compile_definitions(sqlite3_for_shell PRIVATE
    SQLITE_ENABLE_LOAD_EXTENSION=1
    SQLITE_ENABLE_COLUMN_METADATA=1
)
target_include_directories(sqlite3_for_shell PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
if(UNIX AND NOT APPLE)
    target_link_libraries(sqlite3_for_shell PRIVATE pthread dl m)
endif()

add_executable(sqlwrite-bin shell.c sqlwrite.cpp)
target_include_directories(sqlwrite-bin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(sqlwrite-bin PRIVATE SQLWRITE_AUTOLOAD NDEBUG)
target_link_libraries(sqlwrite-bin PRIVATE 
    sqlite3_for_shell
    ${FMT_LIBRARY}
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
)
if(UNIX AND NOT APPLE)
    target_link_libraries(sqlwrite-bin PRIVATE pthread dl m readline)
endif()

# Installation
include(GNUInstallDirs)

install(TARGETS sqlwrite_ext
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

if(TARGET sqlwrite-bin)
    install(TARGETS sqlwrite-bin sqlite3
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

install(PROGRAMS sqlwrite DESTINATION ${CMAKE_INSTALL_BINDIR})

# CPack for packaging
set(CPACK_PACKAGE_NAME "sqlwrite")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "AI-powered natural language to SQL")
set(CPACK_PACKAGE_CONTACT "emery@cs.umass.edu")

if(APPLE)
    set(CPACK_GENERATOR "productbuild")
elseif(UNIX)
    if(EXISTS "/etc/debian_version")
        set(CPACK_GENERATOR "DEB")
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcurl4, libssl3")
    elseif(EXISTS "/etc/redhat-release")
        set(CPACK_GENERATOR "RPM")
        set(CPACK_RPM_PACKAGE_REQUIRES "libcurl, openssl")
    endif()
endif()

include(CPack)
