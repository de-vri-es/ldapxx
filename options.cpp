#include "options.hpp"
#include "util.hpp"

namespace ldapp {

template<>
std::string get_option<std::string>(LDAP * connection, int option) {
	char * c_str = get_option<char *>(connection, option);
	std::string result = c_str;
	ldap_memfree(c_str);
	return result;
}

template<>
void set_option<std::string>(LDAP * connection, int option, std::string const & value) {
	return set_option<char const *>(connection, option, value.data());
}

// Library options.

LDAPAPIFeatureInfo get_api_feature_info(LDAP * connection) {
	return get_option<LDAPAPIFeatureInfo>(connection, LDAP_OPT_API_FEATURE_INFO);
}

LDAPAPIInfo get_api_info(LDAP * connection) {
	return get_option<LDAPAPIInfo>(connection, LDAP_OPT_API_INFO);
}

int get_debug_level(LDAP * connection) {
	return get_option<int>(connection, LDAP_OPT_DEBUG_LEVEL);
}

void set_debug_level(LDAP * connection, int level) {
	return set_option(connection, LDAP_OPT_DEBUG_LEVEL, level);
}

std::string get_default_base(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_DEFBASE);
}

void set_default_base(LDAP * connection, std::string const & base_dn) {
	return set_option(connection, LDAP_OPT_DEFBASE, base_dn);
}

int get_file_descriptor(LDAP * connection) {
	return get_option<int>(connection, LDAP_OPT_DESC);
}

std::string get_diagnostic_message(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_DIAGNOSTIC_MESSAGE);
}

int get_result_code(LDAP * connection) {
	return get_option<int>(connection, LDAP_OPT_RESULT_CODE);
}

std::chrono::microseconds get_network_timeout(LDAP * connection) {
	return to_chrono(get_option<timeval>(connection, LDAP_OPT_NETWORK_TIMEOUT));
}

void set_network_timeout(LDAP * connection, std::chrono::microseconds timeout) {
	set_option(connection, LDAP_OPT_NETWORK_TIMEOUT, to_timeval(timeout));
}

int get_protocol_version(LDAP * connection) {
	return get_option<int>(connection, LDAP_OPT_PROTOCOL_VERSION);
}

void set_protocol_version(LDAP * connection, int version) {
	return set_option(connection, LDAP_OPT_PROTOCOL_VERSION, version);
}

// TCP options.

std::chrono::seconds get_tcp_keepalive_idle(LDAP * connection) {
	return std::chrono::seconds(get_option<int>(connection, LDAP_OPT_X_KEEPALIVE_IDLE));
}

void set_tcp_keepalive_idle(LDAP * connection, std::chrono::seconds timeout) {
	set_option(connection, LDAP_OPT_X_KEEPALIVE_IDLE, int(timeout.count()));
}

int get_tcp_keepalive_probes(LDAP * connection) {
	return get_option<int>(connection, LDAP_OPT_X_KEEPALIVE_PROBES);
}

void set_tcp_keepalive_probes(LDAP * connection, int count) {
	set_option(connection, LDAP_OPT_X_KEEPALIVE_PROBES, count);
}

std::chrono::seconds get_tcp_keepalive_interval(LDAP * connection) {
	return std::chrono::seconds(get_option<int>(connection, LDAP_OPT_X_KEEPALIVE_INTERVAL));
}

void set_tcp_keepalive_interval(LDAP * connection, std::chrono::seconds timeout) {
	set_option(connection, LDAP_OPT_X_KEEPALIVE_INTERVAL, int(timeout.count()));
}

// TLS options.

std::string get_tls_cacertdir(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_X_TLS_CACERTDIR);
}

void set_tls_cacertdir(LDAP * connection, std::string const & path) {
	set_option(connection, LDAP_OPT_X_TLS_CACERTDIR, path);
}

std::string get_tls_cacertfile(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_X_TLS_CACERTFILE);
}

void set_tls_cacertfile(LDAP * connection, std::string const & path) {
	set_option(connection, LDAP_OPT_X_TLS_CACERTFILE, path);
}

std::string get_tls_certfile(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_X_TLS_CERTFILE);
}

void set_tls_certfile(LDAP * connection, std::string const & path) {
	set_option(connection, LDAP_OPT_X_TLS_CERTFILE, path);
}

std::string get_tls_cipher_suite(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_X_TLS_CIPHER_SUITE);
}

void set_tls_cipher_suite(LDAP * connection, std::string const & suites) {
	set_option(connection, LDAP_OPT_X_TLS_CIPHER_SUITE, suites);
}

crl_check get_tls_crlcheck(LDAP * connection) {
	return crl_check(get_option<int>(connection, LDAP_OPT_X_TLS_CRLCHECK));
}

void set_tls_crlcheck(LDAP * connection, crl_check check) {
	set_option(connection, LDAP_OPT_X_TLS_CRLCHECK, int(check));
}

std::string get_tls_crlfile(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_X_TLS_CRLFILE);
}

void set_tls_crlfile(LDAP * connection, std::string const & path) {
	set_option(connection, LDAP_OPT_X_TLS_CRLFILE, path);
}

std::string get_tls_dhfile(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_X_TLS_DHFILE);
}

void set_tls_dhfile(LDAP * connection, std::string const & path) {
	set_option(connection, LDAP_OPT_X_TLS_DHFILE, path);
}

std::string get_tls_keyfile(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_X_TLS_KEYFILE);
}

void set_tls_keyfile(LDAP * connection, std::string const & path) {
	set_option(connection, LDAP_OPT_X_TLS_KEYFILE, path);
}

int get_tls_protocol_min(LDAP * connection) {
	return get_option<int>(connection, LDAP_OPT_X_TLS_PROTOCOL_MIN);
}

void set_tls_protocol_min(LDAP * connection, int minimum_version) {
	set_option(connection, LDAP_OPT_X_TLS_PROTOCOL_MIN, minimum_version);
}

std::string get_tls_random_file(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_X_TLS_RANDOM_FILE);
}

void set_tls_random_file(LDAP * connection, std::string const & path) {
	set_option(connection, LDAP_OPT_X_TLS_RANDOM_FILE, path);
}

certificate_verification get_tls_require_cert(LDAP * connection) {
	return certificate_verification(get_option<int>(connection, LDAP_OPT_X_TLS_REQUIRE_CERT));
}

void set_tls_require_cert(LDAP * connection, certificate_verification verify) {
	set_option(connection, LDAP_OPT_X_TLS_REQUIRE_CERT, int(verify));
}

}
