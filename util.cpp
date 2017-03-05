#include "util.hpp"

namespace ldapp {

std::vector<char const *> to_cstr_array(std::vector<std::string> const & input) {
	std::vector<char const *> result;
	result.reserve(input.size() + 1);
	for (std::string const & str : input) {
		result.push_back(str.c_str());
	}
	result.push_back(nullptr);
	return result;
}

}
