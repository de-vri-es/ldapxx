#include "options.hpp"
#include "types.hpp"

#include <ldap.h>

#include <boost/optional.hpp>

#include <chrono>
#include <string>

namespace ldapp {

/// Connection options.
/**
 * When default constructed, only the LDAP protocol version will be set to 3.
 * No other options are set and no STARTTLS handshake will be attempted.
 * An LDAPS URI may still force the use of TLS without STARTTLS.
 */
struct connection_options {
	/// Connection options regarding the LDAP library.
	struct ldap_options {
		boost::optional<int> protocol_version                      = 3;
		boost::optional<int> debug_level                           = boost::none;
		boost::optional<std::string> default_base_bn               = boost::none;
		boost::optional<std::chrono::microseconds> network_timeout = boost::none;
	} ldap;

	/// Connection options regarding TCP.
	struct tcp_options {
		boost::optional<std::chrono::seconds> keepalive_idle;
		boost::optional<std::chrono::seconds> keepalive_interval;
		boost::optional<int> keepalive_probes;
	} tcp;

	/// Connection options regarding TLS.
	struct tls_options {
		bool starttls                                = false;
		boost::optional<require_cert_t> require_cert = boost::none;
		boost::optional<std::string>    cacertdir    = boost::none;
		boost::optional<std::string>    cacertfile   = boost::none;
		boost::optional<std::string>    ciphersuite  = boost::none;
		boost::optional<crl_check_t>    crlcheck     = boost::none;
		boost::optional<std::string>    crlfile      = boost::none;
		boost::optional<std::string>    dhfile       = boost::none;
		boost::optional<std::string>    keyfile      = boost::none;
		boost::optional<tls_protocol_t> protocol_min = boost::none;
		boost::optional<std::string>    random_file  = boost::none;
	} tls;
};

/// Get a sane set of default options for an LDAP over TLS connection using an ldaps:// uri.
/**
 * The returned options do not cause a STARTTLS handshake to be perfomed.
 * The connection MUST be opened with an LDAPS URI to use TLS.
 *
 * Alternatively, to force a STARTTLS handshake, see defalt_tls_options().
 */
inline connection_options default_ldaps_options() {
	connection_options result;
	result.tls.require_cert = require_cert_t::demand;
	result.tls.ciphersuite  = "HIGH:!EXPORT:!NULL";
	result.tls.protocol_min = tls_protocol_t::tls1_2;
	return result;
}

/// Get a sane set of default options for a TLS connection using STARTTLS.
inline connection_options default_tls_options() {
	connection_options result = default_ldaps_options();
	result.tls.starttls = true;
	return result;
}

void apply_options(LDAP * connection, connection_options::ldap_options const & options);
void apply_options(LDAP * connection, connection_options::tcp_options  const & options);
void apply_options(LDAP * connection, connection_options::tls_options  const & options);
void apply_options(LDAP * connection, connection_options const & options);

/// A small wrapper around native LDAP connections.
/**
 * Internally, the connection holds only a pointer to a native LDAP object
 * as used by the C API. This means that it is safe to copy the connection.
 *
 * For convenience, the connection is implicitly convertable to the native C handle.
 */
class connection {
	/// The native handle.
	LDAP * ldap_;

public:
	/// Construct a connection wrapper from a raw LDAP pointer.
	/**
	 * No options are set, and no TLS handshake is initiated using this constructor.
	 */
	connection(LDAP * ldap);

	/// Connect to a LDAP server and set options on the connection.
	/**
	 * The options are set just after the connection is initialized,
	 * before the connection is really opened.
	 *
	 * For a set of reasonably secure TLS options, you can use default_tls_options().
	 */
	connection(std::string const & uri, connection_options const & options);

	/// Get the native handle usable with the C API.
	LDAP * native() const { return ldap_; }

	/// Allow implicit conversion to the native C API handle.
	operator LDAP * () const { return native(); }

	/// Perform a search query.
	/**
	 * The returned result is automatically wrapped in a unique_ptr with the appropriate deleter.
	 */
	owned_result search(
		query const & query,
		std::chrono::milliseconds timeout,
		std::size_t max_response_size = default_max_response_size
	);
};

}
