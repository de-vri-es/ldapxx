cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Wpedantic)

add_library(ldapp
	connection.cpp
	options.cpp
	util.cpp
	walk_result.cpp
)
target_link_libraries(ldapp PUBLIC ldap lber)
