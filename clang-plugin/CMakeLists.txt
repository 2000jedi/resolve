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
target_link_libraries(checker PRIVATE clang-cpp jsoncpp_lib tcmalloc)

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
