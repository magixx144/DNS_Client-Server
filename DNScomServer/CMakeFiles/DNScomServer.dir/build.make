# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.26

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/magixx/DNScomServer

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/magixx/DNScomServer

# Include any dependencies generated for this target.
include CMakeFiles/DNScomServer.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/DNScomServer.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/DNScomServer.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/DNScomServer.dir/flags.make

CMakeFiles/DNScomServer.dir/main.c.o: CMakeFiles/DNScomServer.dir/flags.make
CMakeFiles/DNScomServer.dir/main.c.o: main.c
CMakeFiles/DNScomServer.dir/main.c.o: CMakeFiles/DNScomServer.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/magixx/DNScomServer/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/DNScomServer.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/DNScomServer.dir/main.c.o -MF CMakeFiles/DNScomServer.dir/main.c.o.d -o CMakeFiles/DNScomServer.dir/main.c.o -c /home/magixx/DNScomServer/main.c

CMakeFiles/DNScomServer.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/DNScomServer.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/magixx/DNScomServer/main.c > CMakeFiles/DNScomServer.dir/main.c.i

CMakeFiles/DNScomServer.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/DNScomServer.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/magixx/DNScomServer/main.c -o CMakeFiles/DNScomServer.dir/main.c.s

CMakeFiles/DNScomServer.dir/DNScomServer.c.o: CMakeFiles/DNScomServer.dir/flags.make
CMakeFiles/DNScomServer.dir/DNScomServer.c.o: DNScomServer.c
CMakeFiles/DNScomServer.dir/DNScomServer.c.o: CMakeFiles/DNScomServer.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/magixx/DNScomServer/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/DNScomServer.dir/DNScomServer.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/DNScomServer.dir/DNScomServer.c.o -MF CMakeFiles/DNScomServer.dir/DNScomServer.c.o.d -o CMakeFiles/DNScomServer.dir/DNScomServer.c.o -c /home/magixx/DNScomServer/DNScomServer.c

CMakeFiles/DNScomServer.dir/DNScomServer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/DNScomServer.dir/DNScomServer.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/magixx/DNScomServer/DNScomServer.c > CMakeFiles/DNScomServer.dir/DNScomServer.c.i

CMakeFiles/DNScomServer.dir/DNScomServer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/DNScomServer.dir/DNScomServer.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/magixx/DNScomServer/DNScomServer.c -o CMakeFiles/DNScomServer.dir/DNScomServer.c.s

# Object files for target DNScomServer
DNScomServer_OBJECTS = \
"CMakeFiles/DNScomServer.dir/main.c.o" \
"CMakeFiles/DNScomServer.dir/DNScomServer.c.o"

# External object files for target DNScomServer
DNScomServer_EXTERNAL_OBJECTS =

DNScomServer: CMakeFiles/DNScomServer.dir/main.c.o
DNScomServer: CMakeFiles/DNScomServer.dir/DNScomServer.c.o
DNScomServer: CMakeFiles/DNScomServer.dir/build.make
DNScomServer: CMakeFiles/DNScomServer.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/magixx/DNScomServer/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable DNScomServer"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/DNScomServer.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/DNScomServer.dir/build: DNScomServer
.PHONY : CMakeFiles/DNScomServer.dir/build

CMakeFiles/DNScomServer.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/DNScomServer.dir/cmake_clean.cmake
.PHONY : CMakeFiles/DNScomServer.dir/clean

CMakeFiles/DNScomServer.dir/depend:
	cd /home/magixx/DNScomServer && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/magixx/DNScomServer /home/magixx/DNScomServer /home/magixx/DNScomServer /home/magixx/DNScomServer /home/magixx/DNScomServer/CMakeFiles/DNScomServer.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/DNScomServer.dir/depend

