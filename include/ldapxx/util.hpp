/*
 * Copyright 2017 Maarten de Vries <maarten@de-vri.es>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once
#include <lber.h>

#include <chrono>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ldapxx {

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

/// Convert microseconds to a timeval struct.
inline timeval to_timeval(std::chrono::microseconds val) {
	return {
		val.count() / 1000000,
		val.count() % 1000000,
	};
}

/// Convert microseconds to a timeval struct.
inline std::chrono::microseconds to_chrono(timeval const & val) {
	return std::chrono::microseconds{val.tv_sec * 1000000 + val.tv_usec};
}

/// Convert a string to a berval.
inline berval to_berval(std::string_view string) {
	berval result;
	result.bv_val = const_cast<char *>(string.data());
	result.bv_len = string.size();
	return result;
}

/// Convert a vector of string to a vector of bervals.
std::vector<berval> toBervals(std::vector<std::string_view> const & values);
std::vector<berval> toBervals(std::vector<std::string> const & values);

/// Convert a vector to a vector of null terminated pointers to the elements.
/**
 * If the input vector is destroyed, the returned vector contains dangling pointers.
 */
template<typename T>
std::vector<T const *> toPtrs(std::vector<T> const & values) {
	std::vector<T const *> result;
	result.reserve(values.size());
	for (T const & value : values) result.push_back(&value);
	result.push_back(nullptr);
	return result;
}

/// Convert a vector to a vector of null terminated pointers to the elements.
/**
 * If the input vector is destroyed, the returned vector contains dangling pointers.
 */
template<typename T>
std::vector<T *> toPtrs(std::vector<T> & values) {
	std::vector<T *> result;
	result.reserve(values.size());
	for (T & value : values) result.push_back(&value);
	result.push_back(nullptr);
	return result;
}

/// Convert a vector of strings to a vector of non-owning C string pointers.
/**
 * If the input vector is destroyed, the returned vector contains dangling pointers.
 */
std::vector<char const *> to_cstr_array(std::vector<std::string_view> const & input);
std::vector<char const *> to_cstr_array(std::vector<std::string>      const & input);

}
