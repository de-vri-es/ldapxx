cmake_minimum_required(VERSION 3.10)
project(ldapxx VERSION 0.1.4)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Wpedantic)

option(BUILD_SHARED_LIBRARIES "Build shared libraries" ON)
option(BUILD_STATIC_LIBRARIES "Build static libraries" OFF)

include(GNUInstallDirs)
set(CMAKE_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}" CACHE PATH "Installation directory for cmake files")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
find_package(LDAP REQUIRED)
find_package(LBER REQUIRED)
find_package(Boost REQUIRED)

set(ldapxx_sources         "")
set(ldapxx_libraries       "")
set(ldapxx_install_targets "")
list(APPEND ldapxx_sources   src/connection.cpp src/error.cpp src/options.cpp src/util.cpp src/walk_result.cpp)
list(APPEND ldapxx_libraries "${LDAP_LIBRARIES}" "${LBER_LIBRARIES}")

include_directories("include/${PROJECT_NAME}" SYSTEM ${Boost_INCLUDE_DIRECTORIES})

if (BUILD_SHARED_LIBRARIES)
	list(APPEND ldapxx_install_targets ldapxx_shared)
	add_library(ldapxx_shared SHARED ${ldapxx_sources})
	set_target_properties(ldapxx_shared PROPERTIES OUTPUT_NAME ldapxx)
	target_link_libraries(ldapxx_shared PUBLIC ${ldapxx_libraries})
	target_include_directories(ldapxx_shared
		INTERFACE "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
	)
	target_include_directories(ldapxx_shared
		SYSTEM INTERFACE ${Boost_INCLUDE_DIRECTORIES}
	)
endif()

if (BUILD_STATIC_LIBRARIES)
	list(APPEND ldapxx_install_targets ldapxx_static)
	add_library(ldapxx_static STATIC ${ldapxx_sources})
	set_target_properties(ldapxx_static PROPERTIES OUTPUT_NAME ldapxx)
	target_link_libraries(ldapxx_static PUBLIC ${ldapxx_libraries})
	target_include_directories(ldapxx_static
		INTERFACE "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
	)
	target_include_directories(ldapxx_static
		SYSTEM INTERFACE ${Boost_INCLUDE_DIRECTORIES}
	)
endif()

set(ldapxx_default OFF)
if (BUILD_SHARED_LIBRARIES)
	set(ldapxx_default "shared")
elseif (BUILD_STATIC_LIBRARIES)
	set(ldapxx_default "static")
endif()
if (ldapxx_default)
	list(APPEND ldapxx_install_targets ldapxx)
	add_library(ldapxx INTERFACE)
	target_link_libraries(ldapxx INTERFACE "ldapxx_${ldapxx_default}")
endif()


include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/Config.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
	INSTALL_DESTINATION "${CMAKE_INSTALL_CMAKEDIR}"
	PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_INCLUDEDIR
)
write_basic_package_version_file("${PROJECT_NAME}ConfigVersion.cmake" COMPATIBILITY SameMajorVersion)

install(TARGETS ${ldapxx_install_targets} EXPORT "${PROJECT_NAME}Targets"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(EXPORT "${PROJECT_NAME}Targets" DESTINATION "${CMAKE_INSTALL_CMAKEDIR}")
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
	DESTINATION "${CMAKE_INSTALL_CMAKEDIR}"
)
