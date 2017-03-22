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
#include "walk_result.hpp"

#include <utility>

namespace ldapxx {

unsigned int count_messages(LDAP * connection, result_t result) {
	int count = ldap_count_messages(connection, result);
	if (count < 0) throw error{get_result_code(connection), "counting messages in result"};
	return count;
}

void collect_messages(std::vector<message_t> & output, LDAP * connection, result_t result) {
	int count = count_messages(connection, result);
	output.reserve(output.size() + count);
	walk_messages(connection, result, count, [&output] (message_t message) {
		output.push_back(message);
	});
}

std::vector<message_t> collect_messages(LDAP * connection, result_t result) {
	std::vector<message_t> output;
	collect_messages(output, connection, result);
	return output;
}

unsigned int count_entries(LDAP * connection, message_t message) {
	int count = ldap_count_entries(connection, message);
	if (count < 0) throw error{get_result_code(connection), "counting entries in message"};
	return count;
}

unsigned int count_entries(LDAP * connection, result_t result) {
	int count = 0;
	walk_messages(connection, result, [connection, &count] (message_t message) {
		count += count_entries(connection, message);
	});
	return count;
}

void collect_entries(std::vector<entry_t> & output, LDAP * connection, message_t message) {
	int count = count_entries(connection, message);
	output.reserve(output.size() + count);
	walk_entries(connection, message, [&output] (entry_t entry) {
		output.push_back(entry);
	});
}

std::vector<entry_t> collect_entries(LDAP * connection, message_t message) {
	std::vector<entry_t> ouput;
	collect_entries(ouput, connection, message);
	return ouput;
}

void collect_entries(std::vector<entry_t> & output, LDAP * connection, result_t result) {
	int count = count_entries(connection, result);
	output.reserve(output.size() + count);
	walk_entries(connection, result, [&output] (entry_t entry) {
		output.push_back(entry);
	});
}

std::vector<entry_t> collect_entries(LDAP * connection, result_t result) {
	std::vector<entry_t> ouput;
	collect_entries(ouput, connection, result);
	return ouput;
}

void collect_attributes(std::vector<std::string> & output, LDAP * connection, entry_t entry) {
	walk_attributes(connection, entry, [&output](char const * attr) {
		output.push_back(attr);
	});
}

std::vector<std::string> collect_attributes(LDAP * connection, entry_t entry) {
	std::vector<std::string> output;
	collect_attributes(output, connection, entry);
	return output;
}

std::multimap<std::string, std::string> entry_to_map(LDAP * connection, entry_t entry) {
	std::multimap<std::string, std::string> output;
	walk_attributes(connection, entry, [connection, entry, &output] (std::string const & attribute) {
		walk_values(connection, entry, attribute, [&attribute, &output] (std::string const & value) {
			output.insert(std::make_pair(attribute, value));
		});
	});
	return output;
}

}
