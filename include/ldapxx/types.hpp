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

#pragma once
#include <ldap.h>

#include <memory>
#include <string>
#include <vector>

namespace ldapxx {

/// The default maximum response size for LDAP queries.
constexpr std::size_t default_max_response_size = 4 * 1024 * 1024;

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

struct owned_result : public std::unique_ptr<LDAPMessage, impl::msg_deleter> {
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
	ldapxx::scope scope                 = ldapxx::scope::base;
	std::string filter                  = "(objectClass=*)";
	std::vector<std::string> attributes = {"*"};
	bool attributes_only                = false;
};

/// Helper class to construct a query in pieces.
/**
 * You can set fields of the query with daisy-chainable setters.
 *
 * When you're done, the query_constructor can be convert to a query implicitly.
 */
struct query_constructor {
	ldapxx::query query;

	query_constructor  & base(std::string const & base)  & { query.base = base; return *this; }
	query_constructor && base(std::string const & base) && { query.base = base; return std::move(*this); }

	query_constructor  & scope(ldapxx::scope scope)  & { query.scope = scope; return *this; }
	query_constructor && scope(ldapxx::scope scope) && { query.scope = scope; return std::move(*this); }

	query_constructor  & filter(std::string const & filter)  & { query.filter = filter; return *this; }
	query_constructor && filter(std::string const & filter) && { query.filter = filter; return std::move(*this); }

	query_constructor  & attributes(std::vector<std::string> const & attributes)  & { query.attributes = attributes; return *this; }
	query_constructor && attributes(std::vector<std::string> const & attributes) && { query.attributes = attributes; return std::move(*this); }

	query_constructor  & attributes_only(bool attributes_only)  & { query.attributes_only = attributes_only; return *this; }
	query_constructor && attributes_only(bool attributes_only) && { query.attributes_only = attributes_only; return std::move(*this); }

	/// Allow implicit conversion to a query.
	operator ldapxx::query       & ()       & { return query; }
	operator ldapxx::query const & () const & { return query; }
	operator ldapxx::query      && ()      && { return std::move(query); }
};

/// Make a query using a query_constructor.
inline query_constructor make_query() { return query_constructor{}; }

enum class modification_type {
	add,
	remove_values,
	remove_attribute,
	replace,
};

struct modification {
	modification_type type;
	std::string attribute;
	std::vector<std::string> values;
};

}
