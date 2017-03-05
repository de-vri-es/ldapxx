#pragma once
#include <ldap.h>

#include <memory>
#include <string>
#include <vector>

namespace ldapp {

struct result_t {
	LDAPMessage * native;
	explicit result_t(LDAPMessage * native) : native{native} {};
	operator LDAPMessage const * () const { return native; }
	operator LDAPMessage       * ()       { return native; }
};

struct message_t {
	LDAPMessage * native;
	explicit message_t(LDAPMessage * native) : native{native} {};
	operator LDAPMessage const * () const { return native; }
	operator LDAPMessage       * ()       { return native; }
};

struct entry_t {
	LDAPMessage * native;
	explicit entry_t(LDAPMessage * native) : native{native} {};
	operator LDAPMessage const * () const { return native; }
	operator LDAPMessage       * ()       { return native; }
};

namespace impl {
	struct msg_deleter {
		void operator() (LDAPMessage * msg) { ldap_msgfree(msg); }
	};
}

struct owning_result : public std::unique_ptr<LDAPMessage, impl::msg_deleter> {
	using std::unique_ptr<LDAPMessage, impl::msg_deleter>::unique_ptr;
	operator result_t() { return result_t{get()}; }
};

enum class scope {
	base      = LDAP_SCOPE_BASE,
	one_level = LDAP_SCOPE_ONELEVEL,
	subtree   = LDAP_SCOPE_SUBTREE,
	children  = LDAP_SCOPE_CHILDREN,
};

struct query {
	std::string base;
	ldapp::scope scope                  = ldapp::scope::base;
	std::string filter                  = "(objectClass=*)";
	std::vector<std::string> attributes = {"*"};
	bool attributes_only                = false;
};

}
