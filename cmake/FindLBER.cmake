find_path(LBER_INCLUDE_DIR lber.h DOC "include directory containing lber.h")
find_library(LBER_LIBRARY lber DOC "location of the LBER library")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LBER
	FOUND_VAR LBER_FOUND
	REQUIRED_VARS LBER_INCLUDE_DIR LBER_LIBRARY
)

if (LBER_FOUND)
	set(LBER_LIBRARIES    "${LBER_LIBRARY}")
	set(LBER_INCLUDE_DIRS "${LBER_INCLUDE_DIR}")

	add_library(LBER INTERFACE IMPORTED)
	set_property(TARGET LBER
		PROPERTY IMPORTED_LOCATION "${LBER_LIRARY}"
		PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${LBER_INCLUDE_DIRS}"
	)
endif()
