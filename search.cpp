#include "error.hpp"
#include "search.hpp"
#include "util.hpp"

#include <ldap.h>

namespace ldapp {

owning_result search(LDAP * connection, query query, std::chrono::milliseconds timeout, std::size_t max_response) {
	timeval timeout_c = to_timeval(timeout);
	std::vector<char const *> attributes_c = to_cstr_array(query.attributes);

	LDAPMessage * result;
	int code = ldap_search_ext_s(
		connection,
		query.base.data(),
		int(query.scope),
		query.filter.data(),
		const_cast<char * *>(attributes_c.data()),
		0, nullptr, nullptr,
		&timeout_c,
		max_response,
		&result
	);
	owning_result safe_result{result};

	if (code) throw error{code, "performing LDAP search"};
	return safe_result;
}

}
