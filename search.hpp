#pragma once
#include "types.hpp"

#include <chrono>

namespace ldapp {

owning_result search(LDAP * connection, query query, std::chrono::milliseconds timeout, std::size_t max_response = 4 * 1024 * 1024);

}
