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
#include "../options.hpp"
#include "../types.hpp"

#include <utility>

namespace ldapxx {

template<typename F>
void walk_messages(LDAP * connection, result_t result, int count, F && f) {
	if (!count) return;

	LDAPMessage * message = ldap_first_message(connection, result);
	if (!message) throw error{get_result_code(connection), "retrieving first message in result"};
	f(message_t{message});

	for (int i = 1; i < count; i++) {
		message = ldap_next_message(connection, message);
		if (!message) throw error{get_result_code(connection), "retrieving next message in result"};
		f(message_t{message});
	}
}

template<typename F>
void walk_messages(LDAP * connection, result_t message, F && f) {
	int count = ldap_count_messages(connection, message);
	if (count < 0) throw error{get_result_code(connection), "counting messages in result"};
	walk_messages(connection, message, count, std::forward<F>(f));
}

template<typename F>
void walk_entries(LDAP * connection, message_t message, F && f) {
	LDAPMessage * entry = ldap_first_entry(connection, message);
	errc code = get_result_code(connection);
	if (!entry && code != errc::success) throw error{code, "retrieving first entry in message"};
	if (!entry) return;
	f(entry_t{entry});

	while (true) {
		entry = ldap_next_entry(connection, entry);
		errc code = get_result_code(connection);
		if (!entry && code != errc::success) throw error{code, "retrieving next entry in message"};
		if (!entry) return;
		f(entry_t{entry});
	}
}

template<typename F>
void walk_entries(LDAP * connection, result_t result, F && f) {
	walk_messages(connection, result, [connection, &f] (message_t message) {
		walk_entries(connection, message, f);
	});
}

template<typename F>
void walk_attributes(LDAP * connection, entry_t entry, F && f) {
	BerElement * finger = nullptr;
	char * attribute = ldap_first_attribute(connection, entry, &finger);
	auto clean_finger = at_scope_exit([&] () { ber_free(finger, 0); });

	errc code = get_result_code(connection);
	if (!attribute && code != errc::success) throw error{code, "retrieving first attribute in entry"};
	if (!attribute) return;
	f(attribute);
	ldap_memfree(attribute);

	while (true) {
		attribute = ldap_next_attribute(connection, entry, finger);
		errc code = get_result_code(connection);
		if (!attribute && code != errc::success) throw error{code, "retrieving next attribute in entry"};
		if (!attribute) return;
		f(attribute);
		ldap_memfree(attribute);
	}
}

template<typename F>
void walk_values(LDAP * connection, entry_t entry, std::string const & attribute, F && f) {
	berval * * values = ldap_get_values_len(connection, entry, attribute.data());
	if (!values) throw error{get_result_code(connection), "retrieving attribute values"};
	auto clean_finger = at_scope_exit([values] () { ldap_value_free_len(values); });
	int count = ldap_count_values_len(values);
	for (int i = 0; i < count; ++i) {
		f(std::string{values[i]->bv_val, values[i]->bv_len});
	}
}

}
