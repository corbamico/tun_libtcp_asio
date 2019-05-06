project(lab2)
add_executable(lab2 src/main.cpp)

find_program(CLANG_TIDY NAMES clang-tidy PATHS /usr/bin)
if(CLANG_TIDY)
    set(CMAKE_CXX_CLANG_TIDY 
        clang-tidy;
        -extra-arg=-std=c++17;
        -extra-arg=-DASIO_STANDALONE
        -checks='clang-diagnostic-*,clang-analyzer-*,cppcoreguidelines-*,modernize-*';
        -p ${CMAKE_BINARY_DIR})
endif()


target_compile_definitions(lab2 PUBLIC 
   ASIO_STANDALONE
   ASIO_NO_DEPRECATED
   #ASIO_ENABLE_HANDLER_TRACKING
)
target_compile_options(lab2 PUBLIC -std=c++17)
target_link_libraries(lab2 pthread viface tins)