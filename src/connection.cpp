#include "connection.hpp"
#include "options.hpp"
#include "util.hpp"

namespace ldapxx {

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
		if (int error = ldap_start_tls_s(ldap_, nullptr, nullptr)) throw ldapxx::error(error, "setting up TLS");
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
	// because it has to be freed either way.
	owned_result safe_result{result};
	if (code) throw error{code, "performing LDAP search"};
	return safe_result;
}

namespace {
	int to_ldap_mod_op(modification_type type) {
		switch (type) {
			case modification_type::add:              return LDAP_MOD_ADD;
			case modification_type::remove_values:    return LDAP_MOD_DELETE;
			case modification_type::remove_attribute: return LDAP_MOD_DELETE;
			case modification_type::replace:          return LDAP_MOD_REPLACE;
		}
		throw std::logic_error("unknown modification type: " + std::to_string(int(type)));
	}
}

void connection::modify(std::string const & dn, std::vector<modification> const & modifications) {
	// First convert to stupid LDAP API structures.
	std::vector<ldapmod> ldap_mods;
	std::vector<LDAPMod *> ldap_mod_ptrs;
	std::vector<std::vector<berval>> bervals;
	std::vector<std::vector<berval *>> berval_ptrs;

	// Can't have the vectors resize, it would invalidate pointers.
	ldap_mods.reserve(modifications.size());
	ldap_mod_ptrs.reserve(modifications.size() + 1);
	bervals.reserve(modifications.size());
	berval_ptrs.reserve(modifications.size() + 1);

	for (modification const & modification : modifications) {
		// Basic LDAPMod information.
		ldap_mods.push_back(ldapmod{});
		ldap_mod_ptrs.push_back(&ldap_mods.back());
		ldap_mods.back().mod_op = to_ldap_mod_op(modification.type) | LDAP_MOD_BVALUES;
		ldap_mods.back().mod_type = const_cast<char *>(modification.attribute.c_str());

		// Delete whole attribute?
		if (modification.type == modification_type::remove_attribute) {
			ldap_mods.back().mod_op = LDAP_MOD_DELETE;
			ldap_mods.back().mod_vals.modv_strvals = nullptr;
			continue;
		}

		// Add bervals.
		bervals.emplace_back(toBervals(modification.values));
		berval_ptrs.emplace_back(toPtrs(bervals.back()));
		ldap_mods.back().mod_vals.modv_bvals = berval_ptrs.back().data();
	}

	ldap_mod_ptrs.push_back(nullptr);

	// Then pass to LDAP -.-
	int code = ldap_modify_ext_s(ldap_, dn.data(), ldap_mod_ptrs.data(), nullptr, nullptr);
	if (code) throw error(code, "applying modifications");
}

void connection::add_attribute_value(std::string const & dn, std::string const & attribute, std::string const & value) {
	berval ldap_value = to_berval(value);
	std::array<berval *, 2> values{{&ldap_value, nullptr}};

	LDAPMod ldap_mod;
	ldap_mod.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
	ldap_mod.mod_type = const_cast<char *>(attribute.c_str());
	ldap_mod.mod_vals.modv_bvals = values.data();
	std::array<LDAPMod *, 2> mods{{&ldap_mod, nullptr}};

	int code = ldap_modify_ext_s(ldap_, dn.data(), mods.data(), nullptr, nullptr);
	if (code) throw error(code, "adding attribute value");
}

void connection::remove_attribute_value(std::string const & dn, std::string const & attribute, std::string const & value) {
	berval ldap_value = to_berval(value);
	std::array<berval *, 2> values{{&ldap_value, nullptr}};

	LDAPMod ldap_mod;
	ldap_mod.mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
	ldap_mod.mod_type = const_cast<char *>(attribute.c_str());
	ldap_mod.mod_vals.modv_bvals = values.data();
	std::array<LDAPMod *, 2> mods{{&ldap_mod, nullptr}};

	int code = ldap_modify_ext_s(ldap_, dn.data(), mods.data(), nullptr, nullptr);
	if (code) throw error(code, "deleting attribute value");
}

void connection::remove_attribute(std::string const & dn, std::string const & attribute) {
	LDAPMod ldap_mod;
	ldap_mod.mod_op = LDAP_MOD_DELETE;
	ldap_mod.mod_type = const_cast<char *>(attribute.c_str());
	ldap_mod.mod_vals.modv_strvals = nullptr;
	std::array<LDAPMod *, 2> mods{{&ldap_mod, nullptr}};

	int code = ldap_modify_ext_s(ldap_, dn.data(), mods.data(), nullptr, nullptr);
	if (code) throw error(code, "deleting attribute value");
}

void connection::add_entry(std::string const & dn, std::map<std::string, std::vector<std::string>> const & attributes) {
	std::vector<ldapmod> ldap_mods;
	std::vector<std::vector<berval>> bervals;
	std::vector<std::vector<berval *>> berval_ptrs;

	ldap_mods.reserve(attributes.size());
	bervals.reserve(attributes.size());
	berval_ptrs.reserve(attributes.size() + 1);

	for (auto const & attribute : attributes) {
		// Basic LDAPMod information.
		ldap_mods.push_back(ldapmod{});
		ldap_mods.back().mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		ldap_mods.back().mod_type = const_cast<char *>(attribute.first.c_str());

		// Add bervals.
		bervals.emplace_back(toBervals(attribute.second));
		berval_ptrs.emplace_back(toPtrs(bervals.back()));
		ldap_mods.back().mod_vals.modv_bvals = berval_ptrs.back().data();
	}

	std::vector<LDAPMod *> mod_ptrs = toPtrs(ldap_mods);

	int code = ldap_add_ext_s(ldap_, dn.c_str(), mod_ptrs.data(), nullptr, nullptr);
	if (code) throw error(code, "adding entry");
}

void connection::remove_entry(std::string const & dn) {
	int code = ldap_delete_ext_s(ldap_, dn.c_str(), nullptr, nullptr);
	if (code) throw error(code, "deleting entry");
}

}
