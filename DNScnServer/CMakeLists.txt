cmake_minimum_required(VERSION 3.25)
project(DNScnServer C)

set(CMAKE_C_STANDARD 11)

add_executable(DNScnServer main.c DNScnServer.c DNScnServer.h)
