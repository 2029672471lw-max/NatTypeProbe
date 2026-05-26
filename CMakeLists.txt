cmake_minimum_required(VERSION 3.10)
project(NatTypeProbe)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # 生成compile_commands.json文件
set(CMAKE_CXX_STANDARD 17)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/output)

include_directories(${PROJECT_SOURCE_DIR}/include)
aux_source_directory(${PROJECT_SOURCE_DIR}/source SRC_LIST)

add_executable(NatTypeProbe ${SRC_LIST})
target_link_libraries(NatTypeProbe ws2_32)
