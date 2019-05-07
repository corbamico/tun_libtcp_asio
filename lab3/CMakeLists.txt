project(lab3)
add_executable(lab3 src/main.cpp)

find_program(CLANG_TIDY NAMES clang-tidy PATHS /usr/bin)
if(CLANG_TIDY)
    set(CMAKE_CXX_CLANG_TIDY 
        clang-tidy;
        -extra-arg=-std=c++17;
        -extra-arg=-DASIO_STANDALONE
        -checks='clang-diagnostic-*,clang-analyzer-*,cppcoreguidelines-*,modernize-*';
        -p ${CMAKE_BINARY_DIR})
endif()


target_compile_definitions(lab3 PUBLIC ASIO_STANDALONE ASIO_NO_DEPRECATED
   #ASIO_ENABLE_HANDLER_TRACKING
)
target_compile_options(lab3 PUBLIC -std=c++17)
target_link_libraries(lab3 pthread viface tins)