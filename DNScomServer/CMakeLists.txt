cmake_minimum_required(VERSION 3.25)
project(DNScomServer C)

set(CMAKE_C_STANDARD 11)

add_executable(DNScomServer main.c DNScomServer.c DNScomServer.h)
