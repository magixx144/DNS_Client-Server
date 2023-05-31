cmake_minimum_required(VERSION 3.25)
project(DNSusServer C)

set(CMAKE_C_STANDARD 11)

add_executable(DNSusServer main.c DNSusServer.c DNSusServer.h)
