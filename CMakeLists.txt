cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Wpedantic)

add_executable(main
	main.cpp
	search.cpp
	util.cpp
	walk_result.cpp
)
target_link_libraries(main ldap lber)
