find_path(LDAP_INCLUDE_DIR ldap.h DOC "include directory containing ldap.h")
find_library(LDAP_LIBRARY ldap DOC "location of the LDAP library")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LDAP
	FOUND_VAR LDAP_FOUND
	REQUIRED_VARS LDAP_INCLUDE_DIR LDAP_LIBRARY
)

if (LDAP_FOUND)
	set(LDAP_LIBRARIES    "${LDAP_LIBRARY}")
	set(LDAP_INCLUDE_DIRS "${LDAP_INCLUDE_DIR}")
	add_library(LDAP INTERFACE IMPORTED)
	set_property(TARGET LDAP
		PROPERTY IMPORTED_LOCATION "${LDAP_LIRARIES}"
		PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${LDAP_INCLUDE_DIRS}"
	)
endif()
