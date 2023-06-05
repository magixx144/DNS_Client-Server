cmake_minimum_required(VERSION 3.25)
project(DNSPTRServer C)

set(CMAKE_C_STANDARD 11)

add_executable(DNSPTRServer main.c DNSPTRServer.c DNSPTRServer.h)
