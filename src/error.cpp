#include "error.hpp"

namespace ldapxx {
struct ldap_category : std::error_category {
	char const * name() const noexcept override { return "ldap"; }

	std::string message(int condition) const override {
		switch (errc(condition)) {
			case errc::success                        : return "success";
			case errc::operations_error               : return "operations error";
			case errc::protocol_error                 : return "protocol error";
			case errc::time_limit_exceeded            : return "time limit exceeded";
			case errc::size_limit_exceeded            : return "size limit exceeded";
			case errc::auth_method_not_supported      : return "auth method not supported";
			case errc::stronger_auth_required         : return "stronger auth required";
			case errc::referral                       : return "referral";
			case errc::admin_limit_exceeded           : return "admin limit exceeded";
			case errc::unavailable_critical_extension : return "unavailable critical extension";
			case errc::confidentiality_required       : return "confidentiality required";
			case errc::sasl_bind_in_progress          : return "sasl bind in progress";
			case errc::no_such_attribute              : return "no such attribute";
			case errc::undefined_attribute_type       : return "undefined attribute type";
			case errc::inappropriate_matching         : return "inappropriate matching";
			case errc::constraint_violation           : return "constraint violation";
			case errc::attribute_or_value_exists      : return "attribute or value exists";
			case errc::invalid_attribute_syntax       : return "invalid attribute syntax";
			case errc::no_such_object                 : return "no such object";
			case errc::alias_problem                  : return "alias problem";
			case errc::invalid_dn_syntax              : return "invalid dn syntax";
			case errc::alias_dereferencing_problem    : return "alias dereferencing problem";
			case errc::inappropriate_authentication   : return "inappropriate authentication";
			case errc::invalid_credentials            : return "invalid credentials";
			case errc::insufficient_access_rights     : return "insufficient access rights";
			case errc::busy                           : return "busy";
			case errc::unavailable                    : return "unavailable";
			case errc::unwilling_to_perform           : return "unwilling to perform";
			case errc::loop_detected                  : return "loop detected";
			case errc::naming_violation               : return "naming violation";
			case errc::object_class_violation         : return "object class violation";
			case errc::not_allowed_on_non_leaf        : return "not allowed on non leaf";
			case errc::not_allowed_on_rdn             : return "not allowed on rdn";
			case errc::no_object_class_mods           : return "no object class mods";
			case errc::affects_multiple_dsa           : return "affects multiple DSAs";
			case errc::other                          : return "other";

			// API errors.
			case errc::server_down                    : return "server down";
			case errc::local_error                    : return "local error";
			case errc::encoding_error                 : return "encoding error";
			case errc::decoding_error                 : return "decoding error";
			case errc::timeout                        : return "timeout";
			case errc::auth_unknown                   : return "auth unknown";
			case errc::filter_error                   : return "filter error";
			case errc::user_cancelled                 : return "user cancelled";
			case errc::param_error                    : return "param error";
			case errc::no_memory                      : return "no memory";
			case errc::connect_error                  : return "connect error";
			case errc::not_supported                  : return "not supported";
			case errc::control_not_found              : return "control not found";
			case errc::no_results_returned            : return "no results returned";
			case errc::more_results_to_return         : return "more results to return";
			case errc::client_loop                    : return "client loop";
			case errc::referral_limit_exceeded        : return "referral limit exceeded";
		}
		return "unknown error " + std::to_string(condition);
	}
} ldap_category_;

std::error_category const & ldap_category() { return ldap_category_; }

}
