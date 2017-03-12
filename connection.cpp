#include "connection.hpp"
#include "options.hpp"
#include "util.hpp"

namespace ldapp {

namespace {
	template<typename T, typename Y>
	void set_if(LDAP * connection, boost::optional<T> const & value, void (*callback) (LDAP *, Y)) {
		if (!value) return;
		callback(connection, *value);
	}
}

void apply_options(LDAP * connection, connection_options::ldap_options const & options) {
	set_if(connection, options.protocol_version, &set_protocol_version);
	set_if(connection, options.debug_level,      &set_debug_level);
	set_if(connection, options.default_base_bn,  &set_default_base);
	set_if(connection, options.network_timeout,  &set_network_timeout);
}

void apply_options(LDAP * connection, connection_options::tcp_options const & options) {
	set_if(connection, options.keepalive_idle,     &set_tcp_keepalive_idle);
	set_if(connection, options.keepalive_interval, &set_tcp_keepalive_interval);
	set_if(connection, options.keepalive_probes,   &set_tcp_keepalive_probes);
}

void apply_options(LDAP * connection, connection_options::tls_options const & options) {
	set_if(connection, options.require_cert, set_tls_require_cert);
	set_if(connection, options.cacertdir,    set_tls_cacertdir);
	set_if(connection, options.cacertfile,   set_tls_cacertfile);
	set_if(connection, options.ciphersuite,  set_tls_cipher_suite);
	set_if(connection, options.crlcheck,     set_tls_crlcheck);
	set_if(connection, options.crlfile,      set_tls_crlfile);
	set_if(connection, options.dhfile,       set_tls_dhfile);
	set_if(connection, options.keyfile,      set_tls_keyfile);
	set_if(connection, options.protocol_min, set_tls_protocol_min);
	set_if(connection, options.random_file,  set_tls_random_file);
}

void apply_options(LDAP * connection, connection_options const & options) {
	apply_options(connection, options.ldap);
	apply_options(connection, options.tcp);
	apply_options(connection, options.tls);
}

connection::connection(LDAP * ldap) : ldap_(ldap) {}

connection::connection(std::string const & uri, connection_options const & options) {
	if (int code = ldap_initialize(&ldap_, uri.c_str())) throw error(code, "initializing LDAP connection");
	apply_options(ldap_, options);
	if (options.tls.starttls) {
		if (int error = ldap_start_tls_s(ldap_, nullptr, nullptr)) throw ldapp::error(error, "setting up TLS");
	}
}

owned_result connection::search(query const & query, std::chrono::milliseconds timeout, std::size_t max_response) {
	timeval timeout_c = to_timeval(timeout);
	std::vector<char const *> attributes_c = to_cstr_array(query.attributes);

	LDAPMessage * result = nullptr;
	int code = ldap_search_ext_s(
		ldap_,
		query.base.data(),
		int(query.scope),
		query.filter.data(),
		const_cast<char * *>(attributes_c.data()),
		0, nullptr, nullptr,
		&timeout_c,
		max_response,
		&result
	);

	// Wrap result in unique_ptr before throwing error,
	// because it always has to be freed.
	owned_result safe_result{result};
	if (code) throw error{code, "performing LDAP search"};
	return safe_result;
}

}
