#pragma once
#include "error.hpp"

#include <ldap.h>

#include <chrono>
#include <string>

namespace ldapp {

/// Set an LDAP option.
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
T get_option(LDAP * connection, int option) {
	T result;
	if (int code = ldap_get_option(connection, option, &result)) {
		throw error(code, "setting option " + std::to_string(option));
	}
	return result;
}

/// Get an LDAP string option.
/**
 * Pass nullptr as connection to retrieve a global option.
 */
template<>
std::string get_option<std::string>(LDAP * connection, int option);

/// Get an LDAP string option.
/**
 * Pass nullptr as connection to retrieve a global option.
 */
template<>
void set_option<std::string>(LDAP * connection, int option, std::string const & value);

// Library options.

LDAPAPIFeatureInfo get_api_feature_info(LDAP * connection);
LDAPAPIInfo get_api_info(LDAP * connection);
int get_file_descriptor(LDAP * connection);
std::string get_diagnostic_message(LDAP * connection);
int get_result_code(LDAP * connection);

int get_debug_level(LDAP * connection);
void set_debug_level(LDAP * connection, int level);

std::string get_default_base(LDAP * connection);
void set_default_base(LDAP * connection, std::string const & base_dn);

std::chrono::microseconds get_network_timeout(LDAP * connection);
void set_network_timeout(LDAP * connection, std::chrono::microseconds timeout);

int get_protocol_version(LDAP * connection);
void set_protocol_version(LDAP * connection, int version);

// TCP options.

std::chrono::seconds get_tcp_keepalive_idle(LDAP * connection);
void set_tcp_keepalive_idle(LDAP * connection, std::chrono::seconds timeout);

int get_tcp_keepalive_probes(LDAP * connection);
void set_tcp_keepalive_probes(LDAP * connection, int count);

std::chrono::seconds get_tcp_keepalive_interval(LDAP * connection);
void set_tcp_keepalive_interval(LDAP * connection, std::chrono::seconds timeout);

// TLS options.

enum class crl_check_t {
	none = LDAP_OPT_X_TLS_CRL_NONE,
	peer = LDAP_OPT_X_TLS_CRL_PEER,
	all  = LDAP_OPT_X_TLS_CRL_ALL,
};

enum class require_cert_t {
	never   = LDAP_OPT_X_TLS_NEVER,
	hard    = LDAP_OPT_X_TLS_HARD,
	demand  = LDAP_OPT_X_TLS_DEMAND,
	allow   = LDAP_OPT_X_TLS_ALLOW,
	attempt = LDAP_OPT_X_TLS_TRY,
};

enum class tls_protocol_t {
	ssl2   = LDAP_OPT_X_TLS_PROTOCOL_SSL2,
	ssl3   = LDAP_OPT_X_TLS_PROTOCOL_SSL3,
	tls1_0 = LDAP_OPT_X_TLS_PROTOCOL_TLS1_0,
	tls1_1 = LDAP_OPT_X_TLS_PROTOCOL_TLS1_1,
	tls1_2 = LDAP_OPT_X_TLS_PROTOCOL_TLS1_2,
	tls1_3 = LDAP_OPT_X_TLS_PROTOCOL(3, 3),
};

require_cert_t get_tls_require_cert(LDAP * connection);
void set_tls_require_cert(LDAP * connection, require_cert_t verify);

std::string get_tls_cacertdir(LDAP * connection);
void set_tls_cacertdir(LDAP * connection, std::string const & path);

std::string get_tls_cacertfile(LDAP * connection);
void set_tls_cacertfile(LDAP * connection, std::string const & path);

std::string get_tls_certfile(LDAP * connection);
void set_tls_certfile(LDAP * connection, std::string const & path);

std::string get_tls_cipher_suite(LDAP * connection);
void set_tls_cipher_suite(LDAP * connection, std::string const & suites);

crl_check_t get_tls_crlcheck(LDAP * connection);
void set_tls_crlcheck(LDAP * connection, crl_check_t check);

std::string get_tls_crlfile(LDAP * connection);
void set_tls_crlfile(LDAP * connection, std::string const & path);

std::string get_tls_dhfile(LDAP * connection);
void set_tls_dhfile(LDAP * connection, std::string const & path);

std::string get_tls_keyfile(LDAP * connection);
void set_tls_keyfile(LDAP * connection, std::string const & path);

tls_protocol_t get_tls_protocol_min(LDAP * connection);
void set_tls_protocol_min(LDAP * connection, tls_protocol_t minimum_version);

std::string get_tls_random_file(LDAP * connection);
void set_tls_random_file(LDAP * connection, std::string const & path);

}
