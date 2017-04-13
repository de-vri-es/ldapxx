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
#include <ldap.h>

#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>

namespace ldapxx {

enum class errc {
	success                        = LDAP_SUCCESS,
	operations_error               = LDAP_OPERATIONS_ERROR,
	protocol_error                 = LDAP_PROTOCOL_ERROR,
	time_limit_exceeded            = LDAP_TIMELIMIT_EXCEEDED,
	size_limit_exceeded            = LDAP_SIZELIMIT_EXCEEDED,
	auth_method_not_supported      = LDAP_AUTH_METHOD_NOT_SUPPORTED,
	stronger_auth_required         = LDAP_STRONG_AUTH_REQUIRED,
	referral                       = LDAP_REFERRAL,
	admin_limit_exceeded           = LDAP_ADMINLIMIT_EXCEEDED,
	unavailable_critical_extension = LDAP_UNAVAILABLE_CRITICAL_EXTENSION,
	confidentiality_required       = LDAP_CONFIDENTIALITY_REQUIRED,
	sasl_bind_in_progress          = LDAP_SASL_BIND_IN_PROGRESS,
	no_such_attribute              = LDAP_NO_SUCH_ATTRIBUTE,
	undefined_attribute_type       = LDAP_UNDEFINED_TYPE,
	inappropriate_matching         = LDAP_INAPPROPRIATE_MATCHING,
	constraint_violation           = LDAP_CONSTRAINT_VIOLATION,
	attribute_or_value_exists      = LDAP_TYPE_OR_VALUE_EXISTS,
	invalid_attribute_syntax       = LDAP_INVALID_SYNTAX,
	no_such_object                 = LDAP_NO_SUCH_OBJECT,
	alias_problem                  = LDAP_ALIAS_PROBLEM,
	invalid_dn_syntax              = LDAP_INVALID_DN_SYNTAX,
	alias_dereferencing_problem    = LDAP_ALIAS_DEREF_PROBLEM,
	inappropriate_authentication   = LDAP_INAPPROPRIATE_AUTH,
	invalid_credentials            = LDAP_INVALID_CREDENTIALS,
	insufficient_access_rights     = LDAP_INSUFFICIENT_ACCESS,
	busy                           = LDAP_BUSY,
	unavailable                    = LDAP_UNAVAILABLE,
	unwilling_to_perform           = LDAP_UNWILLING_TO_PERFORM,
	loop_detected                  = LDAP_LOOP_DETECT,
	loop_detect                    = LDAP_LOOP_DETECT,
	naming_violation               = LDAP_NAMING_VIOLATION,
	object_class_violation         = LDAP_OBJECT_CLASS_VIOLATION,
	not_allowed_on_non_leaf        = LDAP_NOT_ALLOWED_ON_NONLEAF,
	not_allowed_on_rdn             = LDAP_NOT_ALLOWED_ON_RDN,
	no_object_class_mods           = LDAP_NO_OBJECT_CLASS_MODS,
	affects_multiple_dsa           = LDAP_AFFECTS_MULTIPLE_DSAS,
	affects_multiple_dsas          = LDAP_AFFECTS_MULTIPLE_DSAS,
	other                          = LDAP_OTHER,

	// API errors.
	server_down                    = LDAP_SERVER_DOWN,
	local_error                    = LDAP_LOCAL_ERROR,
	encoding_error                 = LDAP_ENCODING_ERROR,
	decoding_error                 = LDAP_DECODING_ERROR,
	timeout                        = LDAP_TIMEOUT,
	auth_unknown                   = LDAP_AUTH_UNKNOWN,
	filter_error                   = LDAP_FILTER_ERROR,
	user_cancelled                 = LDAP_USER_CANCELLED,
	param_error                    = LDAP_PARAM_ERROR,
	no_memory                      = LDAP_NO_MEMORY,
	connect_error                  = LDAP_CONNECT_ERROR,
	not_supported                  = LDAP_NOT_SUPPORTED,
	control_not_found              = LDAP_CONTROL_NOT_FOUND,
	no_results_returned            = LDAP_NO_RESULTS_RETURNED,
	more_results_to_return         = LDAP_MORE_RESULTS_TO_RETURN,
	client_loop                    = LDAP_CLIENT_LOOP,
	referral_limit_exceeded        = LDAP_REFERRAL_LIMIT_EXCEEDED,
};


std::error_category const & ldap_category();

inline std::error_code make_error_code(errc code)      { return {int(code), ldap_category()}; }
inline std::error_code make_error_condition(errc code) { return {int(code), ldap_category()}; }

class error : public std::system_error {
	static std::string format_message(errc code, std::string const & details) {
		return "LDAP error " + std::to_string(int(code)) + " " + std::move(details) + ": " + ldap_err2string(int(code));
	}

	std::string message_;

public:
	error(errc code, std::string const & details) :
		std::system_error{make_error_code(code), format_message(code, details)},
		message_{format_message(code, details)} {};

	virtual ~error() {};

	virtual char const * what() const noexcept override {
		return message_.c_str();
	}
};

}

namespace std {
	template<> struct is_error_code_enum<ldapxx::errc>      : std::true_type {};
	template<> struct is_error_condition_enum<ldapxx::errc> : std::true_type {};
}
