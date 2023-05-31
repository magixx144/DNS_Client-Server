cmake_minimum_required(VERSION 3.25)
project(DNSRootServer C)

set(CMAKE_C_STANDARD 11)

add_executable(DNSRootServer main.c DNSRootServer.c DNSRootServer.h)
