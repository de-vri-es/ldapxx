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

/// An LDAP query result containing messages.
/**
 * This is a thin wrapper around a LDAPMessage pointer with a strong type,
 * which is mainly used for overloading safely.
 */
struct result_t {
	LDAPMessage * native;
	explicit result_t(LDAPMessage * native) : native{native} {};
	operator LDAPMessage const * () const { return native; }
	operator LDAPMessage       * ()       { return native; }
};

/// A single LDAP message containing entries.
/**
 * This is a thin wrapper around a LDAPMessage pointer with a strong type,
 * which is mainly used for overloading safely.
 */
struct message_t {
	LDAPMessage * native;
	explicit message_t(LDAPMessage * native) : native{native} {};
	operator LDAPMessage const * () const { return native; }
	operator LDAPMessage       * ()       { return native; }
};

/// A single LDAP entry containing attributes and values.
/**
 * This is a thin wrapper around a LDAPMessage pointer with a strong type,
 * which is mainly used for overloading safely.
 */
struct entry_t {
	LDAPMessage * native;
	explicit entry_t(LDAPMessage * native) : native{native} {};
	operator LDAPMessage const * () const { return native; }
	operator LDAPMessage       * ()       { return native; }
};

namespace impl {
	/// Delete an LDAP message by calling ldap_msgfree().
	struct msg_deleter {
		void operator() (LDAPMessage * msg) { ldap_msgfree(msg); }
	};
}

/// An owned LDAP query result.
/**
 * The underlying LDAP message is automatically freed when the result goes out of scope.
 */
struct owned_result : public std::unique_ptr<LDAPMessage, impl::msg_deleter> {
	using std::unique_ptr<LDAPMessage, impl::msg_deleter>::unique_ptr;
	operator result_t() { return result_t{get()}; }
};

/// A qeury scope.
enum class scope {
	base      = LDAP_SCOPE_BASE,     ///< Search only the base DN.
	one_level = LDAP_SCOPE_ONELEVEL, ///< Search the direct children of the base DN.
	subtree   = LDAP_SCOPE_SUBTREE,  ///< Search the base DN and all its descendants.
	children  = LDAP_SCOPE_CHILDREN, ///< Search all the descendants of the base DN (but not the base DN itself).
};

/// An LDAP search query.
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
 * When you're done, the query_constructor can be converted to a query implicitly.
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

/// A type of entry attribute modification.
enum class modification_type {
	add,               ///< Add attribute values.
	remove_values,     ///< Remove attribute values.
	remove_attribute,  ///< Remove a whole attribute and all it's values.
	replace,           ///< Replaces the values of an attribute.
};

/// A modification of an entity attribute.
struct modification {
	modification_type type;          ///< The type of modification.
	std::string attribute;           ///< The attribute to modify.
	std::vector<std::string> values; ///< The new values (not used if the whole attribute is deleted).
};

}
