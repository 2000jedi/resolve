cmake_minimum_required(VERSION 3.22)
project(checker)

# Export compile commands for IDEs and tools
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_COMPILER clang++)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)
find_package(jsoncpp REQUIRED)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Found Clang ${Clang_PACKAGE_VERSION}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2")

# Find all source (.cpp) files in the src directory
file(GLOB SRC_FILES
    CONFIGURE_DEPENDS
    "src/*.cpp"
)

# Exclude standalone plugin entry-points: they define their own
# `function_name` and FrontendPluginRegistry::Add, which would
# collide when linked into libchecker.so alongside Checker.cpp.
list(FILTER SRC_FILES EXCLUDE REGEX ".*search_malloc_plugin\\.cpp$")
list(FILTER SRC_FILES EXCLUDE REGEX ".*search_um_plugin\\.cpp$")

# Find all header (.hpp) files in the src directory
file(GLOB HDR_FILES
    CONFIGURE_DEPENDS
    "src/*.hpp"
)

add_library(checker SHARED
    ${SRC_FILES}
    ${HDR_FILES}
)

# Link to clang libraries we need
target_link_libraries(checker PRIVATE clang-cpp jsoncpp_lib)

# Ensure proper include paths and compile flags from clang
set_target_properties(checker PROPERTIES
    CXX_STANDARD 17
    POSITION_INDEPENDENT_CODE ON
)
target_include_directories(checker PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(checker PRIVATE ${LLVM_DEFINITIONS})

# Copy compile_commands.json to project root for IDE support
add_custom_command(TARGET checker POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/../compile_commands.json
    COMMENT "Copying compile_commands.json to project root"
)

# ── cpath baseline plugins ──────────────────────────────────────────────────
# Two standalone PluginASTAction libraries used by the cpath benchmark suite.
# Each loads independently via clang -Xclang -load.

# Common code only — csv_writer + helper.  queryBadMalloc.cpp is NOT
# in the common lib because it references `extern std::string function_name`,
# which only the search_um plugin defines.  Linking it into search_malloc
# would leave that symbol unresolved.
add_library(cpath_baseline_common STATIC
    src/csv_writer.cpp
    src/helper.cpp
)
set_target_properties(cpath_baseline_common PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_STANDARD 17
)
target_link_libraries(cpath_baseline_common PRIVATE clang-cpp jsoncpp_lib)
target_include_directories(cpath_baseline_common PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(cpath_baseline_common PRIVATE ${LLVM_DEFINITIONS})

add_library(search_malloc SHARED src/search_malloc_plugin.cpp)
target_link_libraries(search_malloc PRIVATE
    cpath_baseline_common clang-cpp jsoncpp_lib)
target_include_directories(search_malloc PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(search_malloc PRIVATE ${LLVM_DEFINITIONS})

# search_um pulls queryBadMalloc.cpp directly so it gets the analysis;
# the source file is also compiled (separately) into libchecker.so via
# its src/*.cpp glob — harmless, the two .so files are independent.
add_library(search_um SHARED
    src/search_um_plugin.cpp
    src/queryBadMalloc.cpp)
target_link_libraries(search_um PRIVATE
    cpath_baseline_common clang-cpp jsoncpp_lib)
target_include_directories(search_um PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(search_um PRIVATE ${LLVM_DEFINITIONS})
