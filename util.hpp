#pragma once
#include "error.hpp"

#include <chrono>
#include <list>
#include <type_traits>
#include <utility>
#include <vector>

namespace ldapp {

/// A scope guard.
/**
 * When destroyed, the scope guard calls a given functor unless the release() member is called first.
 *
 * When a scope guard is moved, * the moved-from guard releases the functor.
 */
template<typename F>
class scope_guard {
	F callback_;
	bool armed_;

public:
	explicit scope_guard(F const  & callback) : callback_{callback}, armed_{true} {}
	explicit scope_guard(F && callback) : callback_{std::move(callback)}, armed_{true} {}

	/// Dissalow copying the scope guard.
	scope_guard(scope_guard const &) = delete;
	void operator=(scope_guard)      = delete;

	/// Allow move construction.
	scope_guard(scope_guard && other) : scope_guard{std::move(other.callback_)} {
		other.release();
	}

	/// Allow move-assignment.
	scope_guard & operator= (scope_guard && other) {
		this->~scope_guard();
		new (this) scope_guard(std::move(other));
	}

	/// Release the scope guard.
	/**
	 * When called, the destructor of the scope guard becomes a no-op.
	 */
	void release() { armed_ = false; }

	~scope_guard() { if (armed_) callback_(); };
};

/// Create a scope guard for a given functor.
/**
 * The functor will be called when the scope guard is destroyed,
 * unless release() is called first.
 */
template<typename F>
scope_guard<F> at_scope_exit(F && callback) {
	return scope_guard<F>(std::forward<F>(callback));
}

/// Set an LDAP options.
/**
 * Pass nullptr as connection to set a global option.
 */
template<typename T>
void set_option(LDAP * connection, int option, T const & value) {
	if (int code = ldap_set_option(connection, option, &value)) {
		throw error(code, "setting option " + std::to_string(option));
	}
}

/// Get an LDAP options.
/**
 * Pass nullptr as connection to retrieve a global option.
 */
template<typename T>
int get_option(LDAP * connection, int option) {
	T result;
	if (int code = ldap_get_option(connection, option, &result)) {
		throw error(code, "setting option " + std::to_string(option));
	}
	return result;
}

/// Get the last error number from an LDAP connection.
inline int get_error(LDAP * connection) {
	return get_option<int>(connection, LDAP_OPT_RESULT_CODE);
}

/// Convert microseconds to a timeval struct.
inline timeval to_timeval(std::chrono::microseconds val) {
	return {
		val.count() / 1000000,
		val.count() % 1000000,
	};
}

/// Convert a vector of strings to a vector of non-owning C string pointers.
/**
 * If the input vector is destroyed, the returned vector contains dangling pointers.
 */
std::vector<char const *> to_cstr_array(std::vector<std::string> const & input);

}
