cmake_minimum_required(VERSION 3.5)
project(auto_vuln_scanner)
set(CMAKE_CXX_STANDARD 17)
set(SOURCES
    src/main.cpp
    src/Disassembler.cpp
    src/Demangler.cpp
    src/HeapOverflowDetector.cpp
    src/CommandInjectionDetector.cpp
    src/UnsafeDetector.cpp
)
include_directories(include)
add_executable(scanner ${SOURCES})