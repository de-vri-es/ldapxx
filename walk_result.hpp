#include "types.hpp"
#include "util.hpp"

#include <ldap.h>

#include <vector>
#include <map>

namespace ldapxx {

	/// Count the number of messages in a result.
	unsigned int count_messages(LDAP * connection, result_t result);

	/// Walk all messages in a result and invoke a user defined callback for each message.
	/**
	 * This overload also requires you to specify the number of messages in the result.
	 */
	template<typename F>
	void walk_messages(LDAP * connection, result_t result, int count, F && f);

	/// Walk all messages in a result and invoke a user defined callback for each message.
	/**
	 * This overload calculates the number of messages in the result itself.
	 */
	template<typename F>
	void walk_messages(LDAP * connection, result_t message, F && f);

	/// Collect all messages in a result, appending them to the given vector.
	void collect_messages(std::vector<message_t> & output, LDAP * connection, result_t result);

	/// Collect all messages in a result, returning them in a vector.
	std::vector<message_t> collect_messages(LDAP * connection, result_t result);

	/// Count the number of entries in a message.
	unsigned int count_entries(LDAP * connection, message_t message);

	/// Count the number of entries in all messages in a result.
	unsigned int count_entries(LDAP * connection, result_t result);

	///// Walk all entries in a message and invoke a user defined callback for each entry.
	///**
	// * This overload also requires you to specify the number of entries in the message.
	// */
	template<typename F>
	void walk_entries(LDAP * connection, message_t message, F && f);

	///// Walk all entries in all messages in a result and invoke a user defined callback for each entry.
	template<typename F>
	void walk_entries(LDAP * connection, result_t result, F && f);

	/// Collect all entries in a message, appending them to the given vector.
	void collect_entries(std::vector<entry_t> & output, LDAP * connection, message_t message);

	/// Collect all entries in a message, returning them in vector.
	std::vector<entry_t> collect_entries(LDAP * connection, message_t message);

	/// Collect all entries in all messages in a result, appending them to the given vector.
	void collect_entries(std::vector<entry_t> & output, LDAP * connection, result_t result);

	/// Collect all entries in a message, returning them in vector.
	std::vector<entry_t> collect_entries(LDAP * connection, result_t result);

	/// Walk all attributes of an entry and invoke a callback for each attribute.
	template<typename F>
	void walk_attributes(LDAP * connection, entry_t entry, F && f);

	/// Collect all attributes of an entry, adding them to a container using push_back().
	void collect_attributes(std::vector<std::string> & output, LDAP * connection, entry_t entry);

	/// Collect all attributes of an entry, returning them in a vector.
	std::vector<std::string> collect_attributes(LDAP * connection, entry_t entry);

	/// Walk all values of an attribute and invoke a callback for each value.
	template<typename F>
	void walk_values(LDAP * connection, entry_t entry, std::string const & attribute, F && f);

	/// Convert an entry to a key/value multimap.
	std::multimap<std::string, std::string> entry_to_map(LDAP * connection, entry_t entry);
}

#include "detail/walk_result.hpp"
