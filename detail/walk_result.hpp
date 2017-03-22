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
	int error = get_result_code(connection);
	if (!entry && error) throw ldapxx::error{error, "retrieving first entry in message"};
	if (!entry) return;
	f(entry_t{entry});

	while (true) {
		entry = ldap_next_entry(connection, entry);
		int error = get_result_code(connection);
		if (!entry && error) throw ldapxx::error{error, "retrieving next entry in message"};
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

	int error = get_result_code(connection);
	if (!attribute && error) throw ldapxx::error{error, "retrieving first attribute in entry"};
	if (!attribute) return;
	f(attribute);
	ldap_memfree(attribute);

	while (true) {
		attribute = ldap_next_attribute(connection, entry, finger);
		int error = get_result_code(connection);
		if (!attribute && error) throw ldapxx::error{get_result_code(connection), "retrieving next attribute in entry"};
		if (!attribute) return;
		f(attribute);
		ldap_memfree(attribute);
	}
}

template<typename F>
void walk_values(LDAP * connection, entry_t entry, std::string const & attribute, F && f) {
	berval * * values = ldap_get_values_len(connection, entry, attribute.data());
	if (!values) throw ldapxx::error{get_result_code(connection), "retrieving attribute values"};
	auto clean_finger = at_scope_exit([values] () { ldap_value_free_len(values); });
	int count = ldap_count_values_len(values);
	for (int i = 0; i < count; ++i) {
		f(std::string{values[i]->bv_val, values[i]->bv_len});
	}
}

}
