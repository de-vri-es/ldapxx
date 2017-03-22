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

#include "options.hpp"
#include "util.hpp"

namespace ldapxx {

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

int get_file_descriptor(LDAP * connection) {
	return get_option<int>(connection, LDAP_OPT_DESC);
}

std::string get_diagnostic_message(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_DIAGNOSTIC_MESSAGE);
}

int get_result_code(LDAP * connection) {
	return get_option<int>(connection, LDAP_OPT_RESULT_CODE);
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

crl_check_t get_tls_crlcheck(LDAP * connection) {
	return crl_check_t(get_option<int>(connection, LDAP_OPT_X_TLS_CRLCHECK));
}

void set_tls_crlcheck(LDAP * connection, crl_check_t check) {
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

tls_protocol_t get_tls_protocol_min(LDAP * connection) {
	return tls_protocol_t(get_option<int>(connection, LDAP_OPT_X_TLS_PROTOCOL_MIN));
}

void set_tls_protocol_min(LDAP * connection, tls_protocol_t minimum_version) {
	set_option(connection, LDAP_OPT_X_TLS_PROTOCOL_MIN, int(minimum_version));
}

std::string get_tls_random_file(LDAP * connection) {
	return get_option<std::string>(connection, LDAP_OPT_X_TLS_RANDOM_FILE);
}

void set_tls_random_file(LDAP * connection, std::string const & path) {
	set_option(connection, LDAP_OPT_X_TLS_RANDOM_FILE, path);
}

require_cert_t get_tls_require_cert(LDAP * connection) {
	return require_cert_t(get_option<int>(connection, LDAP_OPT_X_TLS_REQUIRE_CERT));
}

void set_tls_require_cert(LDAP * connection, require_cert_t verify) {
	set_option(connection, LDAP_OPT_X_TLS_REQUIRE_CERT, int(verify));
}

}
