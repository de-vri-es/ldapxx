cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Wpedantic)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(LDAP REQUIRED)
find_package(LBER REQUIRED)

add_library(ldapp
	connection.cpp
	options.cpp
	util.cpp
	walk_result.cpp
)
target_link_libraries(ldapp PUBLIC ${LDAP_LIBRARIES} ${LBER_LIBRARIES})
