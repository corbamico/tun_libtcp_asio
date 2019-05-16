project(lab5)
add_executable(lab5 src/main.cpp src/impl.cpp)

find_program(CLANG_TIDY NAMES clang-tidy PATHS /usr/bin)
if(CLANG_TIDY)
    set(CMAKE_CXX_CLANG_TIDY 
        clang-tidy;
        -extra-arg=-std=c++17;
        -extra-arg=-DASIO_STANDALONE
        -extra-arg=-I${PROJECT_SOURCE_DIR}/include
        -checks='clang-diagnostic-*,clang-analyzer-*,cppcoreguidelines-*,modernize-*';
        -p ${CMAKE_BINARY_DIR})
endif()



target_include_directories(lab5 PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(lab5 PUBLIC ASIO_STANDALONE ASIO_NO_DEPRECATED
   #ASIO_ENABLE_HANDLER_TRACKING
)
target_compile_options(lab5 PUBLIC -std=c++17)
target_link_libraries(lab5 pthread viface tins)