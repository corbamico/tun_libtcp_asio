project(lab1)
add_executable(lab1 src/main.cpp)

find_program(CLANG_TIDY NAMES clang-tidy PATHS /usr/bin)
if(CLANG_TIDY)
    set(CMAKE_CXX_CLANG_TIDY 
        clang-tidy;
        -extra-arg=-std=c++17;
        -extra-arg=-DASIO_STANDALONE
        -checks='clang-diagnostic-*,clang-analyzer-*,cppcoreguidelines-*,modernize-*';
        -p ${CMAKE_BINARY_DIR})
endif()


target_compile_definitions(lab1 PUBLIC ASIO_STANDALONE)
target_compile_options(lab1 PUBLIC -std=c++17)
target_link_libraries(lab1 pthread viface)