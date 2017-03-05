#pragma once
#include <ldap.h>

#include <stdexcept>
#include <string>

namespace ldapp {

class error : public std::runtime_error {
	int code_;

	static std::string formatMessage(int code) {
		return "error " + std::to_string(code) + ": " + ldap_err2string(code);
	}

	static std::string formatMessage(int code, std::string const & message) {
		return "error " + std::to_string(code) + " " + message + ": " + ldap_err2string(code);
	}
public:
	explicit error(int code) : std::runtime_error(formatMessage(code)), code_(code) {}
	error(int code, std::string const & message) : std::runtime_error(formatMessage(code, message)), code_(code) {}

	int code() const { return code_; }
};

}
