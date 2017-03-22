cmake_minimum_required(VERSION 3.1)
project(ldapxx VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Wpedantic)

option(BUILD_SHARED_LIBRARIES "Build shared libraries" ON)
option(BUILD_STATIC_LIBRARIES "Build static libraries" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
find_package(LDAP REQUIRED)
find_package(LBER REQUIRED)

set(ldapxx_sources         "")
set(ldapxx_libraries       "")
set(ldapxx_install_targets "")
list(APPEND ldapxx_sources   src/connection.cpp src/options.cpp src/util.cpp src/walk_result.cpp)
list(APPEND ldapxx_libraries ${LDAP_LIBRARIES} ${LBER_LIBRARIES})

include_directories(PRIVATE "include/${PROJECT_NAME}")

if (${BUILD_SHARED_LIBRARIES})
	add_library(ldapxx_shared SHARED ${ldapxx_sources})
	list(APPEND ldapxx_install_targets ldapxx_shared)
	set_target_properties(ldapxx_shared PROPERTIES OUTPUT_NAME ldapxx)
	target_link_libraries(ldapxx_shared PUBLIC ${ldapxx_LIBRARIES})
endif()

if (${BUILD_STATIC_LIBRARIES})
	add_library(ldapxx_static STATIC ${ldapxx_sources})
	list(APPEND ldapxx_install_targets ldapxx_static)
	set_target_properties(ldapxx_static PROPERTIES OUTPUT_NAME ldapxx)
	target_link_libraries(ldapxx_static PUBLIC ${ldapxx_LIBRARIES})
endif()

include(GNUInstallDirs)
set(CMAKE_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}" CACHE PATH "Installation directory for cmake files")

include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/${PROJECT_NAME}Config.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
	INSTALL_DESTINATION "${CMAKE_INSTALL_CMAKEDIR}"
	PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_INCLUDEDIR
)
write_basic_package_version_file(ldapxxConfigVersion.cmake COMPATIBILITY SameMajorVersion)

install(TARGETS ${ldapxx_install_targets} EXPORT ldapxxTargets
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

install(EXPORT ldapxxTargets DESTINATION "${CMAKE_INSTALL_CMAKEDIR}")
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/ldapxxConfig.cmake"
		"${CMAKE_CURRENT_BINARY_DIR}/ldapxxConfigVersion.cmake"
	DESTINATION "${CMAKE_INSTALL_CMAKEDIR}"
)
