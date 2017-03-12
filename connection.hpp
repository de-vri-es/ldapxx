#include <ldap.h>

#include <boost/optional.hpp>

#include <string>

namespace ldapp {

struct tcp_options {
	boost::optional<int> keepalive_idle;
	boost::optional<int> keepalive_interval;
	boost::optional<int> keepalive_probes;
};

enum class crl_check {
	none,
	peer,
	all,
};

enum class cert_check {
	never,
	hard,
	demand,
	allow,
	attempt,
};

struct tls_options {
	boost::optional<std::string> cacertdir;
	boost::optional<std::string> cacertfile;
	boost::optional<std::string> ciphersuite;
	boost::optional<crl_check>   crlcheck;
	boost::optional<std::string> crlfile;
	boost::optional<std::string> dhfile;
	boost::optional<std::string> keyfile;
	boost::optional<int>         protocol_min;
	boost::optional<std::string> random_file;
	boost::optional<cert_check>  require_cert;
};

struct connection_options {
	tcp_options tcp;
	tls_options tls;
};

void apply_options(LDAP * connection, tcp_options const & options);
void apply_options(LDAP * connection, tls_options const & options);
void apply_options(LDAP * connection, connection_options const & options);

class connection {
	LDAP * ldap_;

	connection(LDAP * ldap) : ldap_(ldap) {};

	connection(std::string const & uri, connection_options const & options);
};

}
