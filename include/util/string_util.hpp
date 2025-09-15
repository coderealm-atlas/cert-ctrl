#pragma once

#include <date/date.h>
#include <fmt/format.h>
#include <string.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fmt/base.h>
#include <stdint.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>
#include <cctype>
#include <compare>
#include <exception>
#include <functional>
#include <iterator>
#include <map>
#include <numeric>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

#include "base64.h"
#include "common_macros.hpp"

namespace fs = std::filesystem;

inline std::ostream& operator<<(std::ostream& os,
                                const std::vector<std::string>& vec) {
  os << "[";
  for (size_t i = 0; i < vec.size(); ++i) {
    os << "\"" << vec[i] << "\"";        // Print with quotes
    if (i < vec.size() - 1) os << ", ";  // Add comma between elements
  }
  os << "]";
  return os;
}

namespace cjj365 {
namespace stringutil {

std::string generate_uuid(const std::string& prefix = "", bool no_dash = false);
// Trim leading and trailing whitespace from a string
inline void trim(std::string& str) {
  auto start = std::find_if_not(str.begin(), str.end(), ::isspace);
  auto end = std::find_if_not(str.rbegin(), str.rend(), ::isspace).base();
  str = std::string(start, end);
}

class IniParser {
 public:
  // Represents the configuration data
  using SectionMap = std::map<std::string, std::map<std::string, std::string>>;

  // Parses the INI file and loads data into the configuration
  void parse(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
      throw std::runtime_error("Could not open file: " + filename);
    }

    std::string line;
    bool inDefaultSection = false;

    while (std::getline(file, line)) {
      trim(line);

      if (line.empty() || line[0] == ';' || line[0] == '#') {
        // Skip empty lines or comments
        continue;
      }

      if (line[0] == '[') {
        // Section header
        if (inDefaultSection) {
          inDefaultSection = false;  // After the first section, we're no longer
                                     // in the default section.
        }
        parseSectionHeader(line);
      } else {
        // Key-value pair
        if (!inDefaultSection) {
          // Ensure that any key-value pairs before a section are in the default
          // section
          inDefaultSection = true;
          currentSection =
              "default";  // Set to the default section when we encounter a
                          // key-value pair before any section
        }
        parseKeyValuePair(line);
      }
    }
  }

  std::map<std::string, std::string> as_map() {
    std::map<std::string, std::string> result;
    for (const auto& section : config_) {
      for (const auto& pair : section.second) {
        if (section.first == "default") {
          // If the section is "default", just use the key
          result[pair.first] = pair.second;
        } else {
          result[section.first + "." + pair.first] = pair.second;
        }
      }
    }
    return result;
  }

  // Gets the value for a specific section and key
  std::string get(const std::string& section, const std::string& key) const {
    auto sectionIter = config_.find(section);
    if (sectionIter != config_.end()) {
      auto keyIter = sectionIter->second.find(key);
      if (keyIter != sectionIter->second.end()) {
        return keyIter->second;
      }
    }
    return "";
  }

  fs::path fixture_dir() const { return fs::path(get("TEST_FIXTURES_DIR")); }

  std::string get(const std::string& key) const { return get("default", key); }

  // Print all data for debugging purposes
  void print() const {
    for (const auto& section : config_) {
      std::cout << "[" << section.first << "]\n";
      for (const auto& pair : section.second) {
        std::cout << pair.first << " = " << pair.second << "\n";
      }
      std::cout << "\n";
    }
  }

 private:
  // Data structure to hold the INI file data
  SectionMap config_;

  // Current section being processed
  std::string currentSection = "default";  // Default section at the beginning

  // Parse a section header like [SectionName]
  void parseSectionHeader(const std::string& line) {
    size_t start = line.find('[') + 1;
    size_t end = line.find(']', start);
    if (start == std::string::npos || end == std::string::npos) {
      throw std::runtime_error("Invalid section header: " + line);
    }
    currentSection = line.substr(start, end - start);
  }

  // Parse a key-value pair like key=value
  void parseKeyValuePair(const std::string& line) {
    size_t eqPos = line.find('=');
    if (eqPos == std::string::npos) {
      throw std::runtime_error("Invalid key-value pair: " + line);
    }

    std::string key = line.substr(0, eqPos);
    std::string value = line.substr(eqPos + 1);

    trim(key);
    trim(value);

    // Store the key-value pair in the appropriate section
    config_[currentSection][key] = value;
  }
};

class IniParserIt {
  // private the constructor to prevent instantiation
  IniParserIt() = default;

 public:
  using SectionMap = std::map<std::string, std::map<std::string, std::string>>;
  static IniParserIt parseContent(const std::string& content);
  static IniParserIt parseFile(const std::string& filename);

  struct Entry {
    std::string section;
    std::string key;
    std::string value;
  };

  class Iterator {
   public:
    using iterator_category = std::input_iterator_tag;
    using value_type = Entry;
    using difference_type = std::ptrdiff_t;
    using pointer = const Entry*;
    using reference = const Entry&;

    using OuterIter = SectionMap::const_iterator;
    using InnerIter = std::map<std::string, std::string>::const_iterator;

    Iterator() = default;  // ✅ default constructor for STL compatibility

    Iterator(OuterIter outer, OuterIter outer_end)
        : outer_(outer), outer_end_(outer_end) {
      if (outer_ != outer_end_) {
        inner_ = outer_->second.begin();
        advanceToValid();
      }
    }

    Iterator(OuterIter outer, OuterIter outer_end, bool /*end*/)
        : outer_(outer_end), outer_end_(outer_end) {}

    Entry operator*() const {
      return {outer_->first, inner_->first, inner_->second};
    }

    Iterator& operator++() {
      ++inner_;
      advanceToValid();
      return *this;
    }

    Iterator operator++(int) {  // ✅ optional post-increment
      Iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    bool operator==(const Iterator& other) const {
      return outer_ == other.outer_ &&
             (outer_ == outer_end_ || inner_ == other.inner_);
    }

    bool operator!=(const Iterator& other) const { return !(*this == other); }

   private:
    void advanceToValid() {
      while (outer_ != outer_end_ && inner_ == outer_->second.end()) {
        ++outer_;
        if (outer_ != outer_end_) {
          inner_ = outer_->second.begin();
        }
      }
    }

    OuterIter outer_;
    OuterIter outer_end_;
    InnerIter inner_;
  };

  class SectionIterator {
   public:
    using iterator_category = std::input_iterator_tag;
    using value_type = Entry;
    using difference_type = std::ptrdiff_t;
    using pointer = const Entry*;
    using reference = const Entry&;

    SectionIterator() = default;  // ✅ default constructor for compatibility

    SectionIterator(const std::string& section, const SectionMap& config,
                    bool is_end = false)
        : section_(section), config_(&config) {
      auto it = config_->find(section_);
      if (it != config_->end()) {
        inner_ = is_end ? it->second.end() : it->second.begin();
      } else {
        // Make inner_ point to end iterator to avoid undefined behavior
        inner_ = std::map<std::string, std::string>::const_iterator{};
      }
    }

    Entry operator*() const {
      return {section_, inner_->first, inner_->second};
    }

    SectionIterator& operator++() {
      ++inner_;
      return *this;
    }

    SectionIterator operator++(int) {  // ✅ optional post-increment
      SectionIterator tmp = *this;
      ++(*this);
      return tmp;
    }

    bool operator==(const SectionIterator& other) const {
      return inner_ == other.inner_ && section_ == other.section_;
    }

    bool operator!=(const SectionIterator& other) const {
      return !(*this == other);
    }

   private:
    std::string section_;
    const SectionMap* config_ = nullptr;
    std::map<std::string, std::string>::const_iterator inner_;
  };

  // Full iteration
  Iterator begin() const { return Iterator(config_.begin(), config_.end()); }
  Iterator end() const { return Iterator(config_.end(), config_.end(), true); }

  // Section-based iteration
  SectionIterator begin(const std::string& section) const {
    return SectionIterator(resolveSection(section), config_, false);
  }

  SectionIterator end(const std::string& section) const {
    return SectionIterator(resolveSection(section), config_, true);
  }

  bool empty() { return config_.empty(); }

  std::string get(const std::string& section, const std::string& key) const {
    auto sectionIter = config_.find(section);
    if (sectionIter != config_.end()) {
      auto keyIter = sectionIter->second.find(key);
      if (keyIter != sectionIter->second.end()) {
        return keyIter->second;
      }
    }
    return "";
  }

  std::string get(const std::string& key) const { return get("default", key); }

  std::map<std::string, std::string> as_map() const {
    std::map<std::string, std::string> result;
    for (const auto& [section, kv] : config_) {
      for (const auto& [key, value] : kv) {
        if (section == "default") {
          result[key] = value;  // Use key directly for default section
        } else {
          result[section + "." + key] = value;  // Prefix with section name
        }
      }
    }
    return result;
  }

  fs::path fixture_dir() const { return fs::path(get("TEST_FIXTURES_DIR")); }

  void print() const {
    for (const auto& [section, kv] : config_) {
      std::cout << "[" << section << "]\n";
      for (const auto& [key, value] : kv) {
        std::cout << key << " = " << value << "\n";
      }
      std::cout << "\n";
    }
  }

 private:
  SectionMap config_;
  std::string currentSection = "default";
  void parseContent_(const std::string& content);
  void parseFile_(const fs::path& filename);

  std::string resolveSection(const std::string& section) const {
    return section.empty() ? "default" : section;
  }

  void parseSectionHeader(const std::string& line) {
    size_t start = line.find('[') + 1;
    size_t end = line.find(']', start);
    if (start == std::string::npos || end == std::string::npos) {
      throw std::runtime_error("Invalid section header: " + line);
    }
    currentSection = line.substr(start, end - start);
  }

  void parseKeyValuePair(const std::string& line) {
    size_t eqPos = line.find('=');
    if (eqPos == std::string::npos) {
      throw std::runtime_error("Invalid key-value pair: " + line);
    }

    std::string key = line.substr(0, eqPos);
    std::string value = line.substr(eqPos + 1);

    trim(key);
    trim(value);

    config_[currentSection][key] = value;
  }

  void trim(std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(), ::isspace);
    auto end = std::find_if_not(str.rbegin(), str.rend(), ::isspace).base();
    str = (start < end) ? std::string(start, end) : "";
  }
};

// Case-insensitive character comparison
struct case_insensitive {
  bool operator()(char a, char b) const {
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
  }
};

// Check if content type indicates multipart form data
bool is_multipart_form_data(const std::string& content_type);

template <size_t Len>
std::optional<std::array<std::string, Len>> parse_line(
    const std::string& line, const std::string& separator,
    size_t expect_elements = Len) {
  std::array<std::string, Len> result;
  size_t count = 0;

  size_t start = 0;
  size_t end = 0;
  while ((end = line.find(separator, start)) != std::string::npos &&
         count < Len) {
    result[count++] = line.substr(start, end - start);
    start = end + separator.length();
  }

  if (count < Len && start <= line.size()) {
    result[count++] = line.substr(start);
  }

  if (count != expect_elements) {
    return std::nullopt;
  }

  return result;
}

/**
 * @brief Extract the next segment of a path
 * /a/b/c, first invoke will return "a", second "b", third "c", fourth empty
 * string. sv == "svalue" or sv.compare("svalue") == 0 to test equality.
 * sv.empty() means no more segment.
 *
 * @param path The path to extract the segment from
 * @param pos The position in the path to start extracting from, may change
 * after invoke.
 *
 */
std::string_view next_segment(std::string const& path, size_t& pos);

/**
 * @brief Extract all segments of a path
 * /a/b/c, return ["a", "b", "c"]
 *
 * @param path The path to extract the segments from
 * @return std::vector<std::string_view> The segments of the path
 */
std::vector<std::string_view> all_segments(std::string const& path);

template <class Precision>
std::string getISOCurrentTimestamp() {
  auto now = std::chrono::system_clock::now();
  return date::format("%FT%TZ",
                      date::floor<Precision>(now));  // ISO 8601 format
}

inline std::string formatISO8601(
    const std::chrono::system_clock::time_point& tp) {
  return date::format("%FT%TZ", tp);
}

inline int64_t now_in_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

inline int64_t iso8601_to_seconds(const std::string& iso8601) {
  std::istringstream ss(iso8601);
  std::chrono::system_clock::time_point tp;
  ss >> date::parse("%FT%TZ", tp);
  return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch())
      .count();
}

inline std::string now_in_iso8601() {
  return formatISO8601(std::chrono::system_clock::now());
}

inline std::string format_rfc3339(
    const std::chrono::system_clock::time_point& tp) {
  return date::format("%FT%TZ", tp);
}

inline bool starts_with(const std::string& str, const std::string& prefix) {
  return str.compare(0, prefix.length(), prefix) == 0;
}

inline bool ends_with(const std::string& str, const std::string& suffix) {
  if (str.length() < suffix.length()) return false;
  return str.compare(str.length() - suffix.length(), suffix.length(), suffix) ==
         0;
}

inline std::string generate_uint64_tSessionID() {
  std::random_device rd;
  std::mt19937_64 gen(rd());  // Mersenne Twister 64-bit generator
  std::uniform_int_distribution<uint64_t> dist;
  // if the length of the generated string is less than 20, then add 0s to the
  // left
  std::ostringstream oss;
  oss << "sss-" << std::setw(20) << std::setfill('0') << dist(gen);
  return oss.str();
}

unsigned int days_since_that_day(const std::string& created_at);
unsigned int days_since_epoch_seconds(uint64_t seconds);

std::string readFile(const std::string& filePath, std::error_code& ec);
std::string readFile(const std::string& filePath);

inline void remove_right_paddings(std::string& str, char padding = '=') {
  size_t pos = str.find_last_not_of(padding);
  if (pos != std::string::npos) {
    str.erase(pos + 1);
  }
}

inline std::string base64urlToBase64(const std::string& base64url) {
  std::string base64 = base64url;

  // Replace '-' with '+', and '_' with '/'
  std::replace(base64.begin(), base64.end(), '-', '+');
  std::replace(base64.begin(), base64.end(), '_', '/');

  // Add padding if necessary (Base64 needs padding to be a multiple of 4)
  while (base64.size() % 4 != 0) {
    base64 += '=';
  }
  return base64;
}

std::string replaceAllEfficient(const std::string& input,
                                const std::string& from, const std::string& to);

std::map<std::string_view, std::string_view> parse_attributes(
    std::string_view tag_content);

inline std::string user_id_str(uint64_t user_id) {
  return fmt::format("ur{}", user_id);
}

inline std::string gitrepo_id_str(uint64_t repo_id) {
  return fmt::format("gr{}", repo_id);
}

inline std::string website_id_str(uint64_t website_id) {
  return fmt::format("ws{}", website_id);
}

inline bool is_email(const std::string& email) {
  if (email.empty()) return false;
  // Define a regular expression for validating an email address
  const std::regex pattern(
      R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");

  // Check if the email matches the pattern
  return std::regex_match(email, pattern);
}

/**
 * @brief Parse an API key in the format "apikeyA1234567890"
 * @param apikey The API key to parse
 * @return A pair containing the APIKEY ID and the key, or {0, ""} if the key is
 * invalid
 * @note The key must be at least 38 characters long and end with "A" followed
 * by the ID
 * @note The ID must be a valid number
 * @note The key must not contain any whitespace
 * I don't need the store the apikey, so use string view.
 */
inline std::pair<uint64_t, std::string> parse_apikey(std::string_view apikey) {
  // Basic T3piNGlUNDctZGktN0hBVGtWM1Zka0FRQVhWVU43dGdjaEV1QTQwOg==
  try {
    std::string decoded;  // Store decoded string
    if (apikey.find("Basic ") == 0) {
      decoded = base64_decode(apikey.substr(6));  // Ensure decoded is valid
      apikey = decoded;  // Now apikey points to a valid owned string
    } else if (apikey.find("Bearer ") == 0) {
      apikey = apikey.substr(7);
    }
    DEBUG_PRINT("apikey size: " << apikey.size());
    if (apikey.size() < 38) return {0, ""};
    size_t pos = apikey.rfind('A');
    if (pos == std::string::npos || pos + 1 >= apikey.size() || pos != 36) {
      DEBUG_PRINT("invalid apikey 0: " << apikey << " pos: " << pos);
      return {0, ""};
    }
    uint64_t id;
    auto [p, ec] = std::from_chars(apikey.data() + pos + 1,
                                   apikey.data() + apikey.size(), id);
    DEBUG_PRINT("user id in apikey: " << id);
    if (ec != std::errc{}) {
      DEBUG_PRINT("invalid apikey 1: " << apikey);
      return {0, ""};
    } else {
      return {id, std::string{apikey.substr(0, pos)}};
    }
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return {0, ""};
  }
}

constexpr std::array<std::string_view, 3> __keysToFind = {"to-head", "to-top",
                                                          "to-bottom"};

// Compile-time function to find the first occurrence of the keys in a constant
// map
template <typename MapType, size_t N>
constexpr std::optional<typename MapType::mapped_type> __findFirstValueOf(
    const std::array<typename MapType::key_type, N>& keys, const MapType& map) {
  for (const auto& key : keys) {
    auto it = map.find(key);
    if (it != map.end()) {
      return it->second;  // Return the first matching key
    }
  }
  return std::nullopt;  // No key found
}

template <typename MapType, size_t N>
constexpr std::optional<typename MapType::key_type> __findFirstKeyOf(
    const std::array<typename MapType::key_type, N>& keys, const MapType& map) {
  for (const auto& key : keys) {
    auto it = map.find(key);
    if (it != map.end()) {
      return key;  // Return the first matching key
    }
  }
  return std::nullopt;  // No key found
}

std::string htmlUnescape(std::string_view str,
                         std::vector<std::string_view> signs);

// Function to convert ISO 8601 to HTTP Last-Modified format
std::string iso8601_to_last_modified(const std::string& iso8601);

inline bool is_directory_empty(const fs::path& dir_path) {
  if (fs::exists(dir_path) && fs::is_directory(dir_path)) {
    // Iterate over the directory and check if it's empty
    for (const auto& entry : fs::directory_iterator(dir_path)) {
      // If we find at least one entry, the directory is not empty
      return false;
    }
    return true;  // No entries found, directory is empty
  }
  return false;  // The directory doesn't exist or is not a directory
}

template <typename... Args>
inline std::string simple_format(const std::string& str, const Args&... args) {
  std::string result = str;
  auto it = result.begin();

  auto replace_once = [&result, &it](const auto& value) {
    auto pos = result.find("{}", it - result.begin());
    if (pos == std::string::npos) {
      return;  // No more placeholders, stop
    }
    std::string formatted = fmt::format("{}", value);
    result.replace(pos, 2, formatted);
    it = result.begin() + pos + formatted.size();
  };

  (replace_once(args), ...);  // fold expression
  return result;
}

// Compile-time generation of repeated "{}" pattern
template <size_t N>
constexpr auto generateFormatString() {
  std::array<char, N * 2 + 1>
      result{};  // Allocate space for "{}" pairs and null-terminator
  for (size_t i = 0; i < N; ++i) {
    result[2 * i] = '{';
    result[2 * i + 1] = '}';
  }
  result[N * 2] = '\0';  // Null-terminate the string
  return result;
}

template <typename... Args>
std::string formatConcat(const Args&... args) {
  constexpr size_t argCount = sizeof...(Args);
  constexpr auto format = generateFormatString<argCount>();
  return fmt::format(format.data(), args...);
}

template <typename... Strings>
std::string concatStrings(const Strings&... strings) {
  return (std::string{} + ... +
          strings);  // Fold expression to concatenate all strings
}

std::string replace_env_var(
    const std::string& input,
    const std::map<std::string, std::string>& extra_map = {});

inline std::string concatStrings(const std::vector<std::string>& strings) {
  if (strings.empty()) return "";
  // Calculate total size needed for the final string
  size_t totalSize = std::accumulate(
      strings.begin(), strings.end(), size_t(0),
      [](size_t sum, const std::string& s) { return sum + s.size(); });

  // Reserve memory for the final string
  std::string result;
  result.reserve(totalSize);

  // Append all strings
  for (const auto& s : strings) {
    result += s;
  }
  return result;
}

// Helper function to convert std::vector<char> or std::vector<unsigned char> to
// hex string
// std::enable_if_t as RETURN TYPE.
template <typename T>
std::enable_if_t<std::is_same_v<T, char> || std::is_same_v<T, unsigned char>,
                 std::string>
vector_to_hex_string(const std::vector<T>& vec) {
  std::stringstream ss;
  for (const auto& elem : vec) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << (int)(unsigned char)elem << " ";
  }
  return ss.str();
}

inline std::string print_vector_of_string(const std::vector<std::string>& vec) {
  std::string result{"["};
  for (const auto& s : vec) {
    result += s + ", ";
  }
  result += "]";
  return result;
}
std::string to_visible_or_hex(const std::string& str,
                              bool escape_newline = false);
inline bool first_under_second(const std::filesystem::path& p1,
                               const std::filesystem::path& p2) {
  try {
    // Canonicalize both paths
    auto canonical_p1 = std::filesystem::weakly_canonical(p1);
    auto canonical_p2 = std::filesystem::weakly_canonical(p2);

    // Check if canonical_p1 starts with canonical_p2
    return canonical_p1.string().rfind(canonical_p2.string(), 0) == 0;
  } catch (const std::exception& e) {
    // Handle invalid paths (e.g., non-existent directories)
    return false;
  }
}

template <typename T>
std::optional<size_t> findNthOccurrence(const T& str, char ch, int n) {
  if (n <= 0) return std::nullopt;  // Invalid input

  size_t pos = 0;
  for (int count = 0; count < n; ++count) {
    pos = str.find(ch, pos);
    if (pos == std::string::npos) {
      return std::nullopt;  // Character not found nth time
    }
    ++pos;  // Move to the next character for the next search
  }
  return pos - 1;  // Adjust for the final increment
}

bool is_filename_safe_string(const std::string& filename);

fs::path create_unique_temp_directory();

inline std::string toLowerCase(const std::string& str) {
  std::string result;
  result.reserve(str.size());
  for (char c : str) {
    result += std::tolower(static_cast<unsigned char>(c));
  }
  return result;
}
inline std::time_t get_next_reset_time(std::time_t from_time) {
  // std::tm start_tm = *std::localtime(&from_time);  // Convert to struct tm
  std::tm start_tm = *std::gmtime(&from_time);  // Convert to struct tm
  start_tm.tm_mon += 1;                         // Move to the next month
  return std::mktime(&start_tm);                // Convert back to epoch time
}

inline void replace_trailing_dot(std::string& str) {
  size_t last_not_dot = str.find_last_not_of('.');
  if (last_not_dot != std::string::npos) {
    str.replace(last_not_dot + 1, std::string::npos,
                std::string(str.size() - last_not_dot - 1, '='));
  }
}

fs::path biggest_name(const fs::path& dir, const std::string& prefix,
                      const std::string& ext = "IGNORE_EXT");
void lines_without_comments(const std::string& content,
                            std::vector<std::string>& lines);
void lines_without_comments(const fs::path& file,
                            std::vector<std::string>& lines);

std::vector<std::string> insert_lines_after(
    fs::path dockerfile, const std::string& after,
    const std::vector<std::string>& lines);

std::vector<std::string> split_trim(const std::string& str, char delim = ' ',
                                    size_t maxsplit = 0);

std::vector<std::string_view> split_trim_view(const std::string& str,
                                              char delim = ' ',
                                              size_t maxsplit = 0);

bool is_url_safe_string(const std::string& url);

inline std::map<std::string, std::string> parse_envrc(const fs::path& envrc) {
  // #export CMAKE_HOME=/opt/cmake
  // export HARBOR_SECRET=aekuXaeph3cohdohje9vohN5iasikeDa
  // export RABBIT_USER=La5ye0goo1miunuesooDaig8tieph1me
  std::string line;
  std::map<std::string, std::string> env;
  std::ifstream ifs(envrc);
  if (!ifs) {
    std::cerr << "Failed to open " << envrc << std::endl;
    return env;
  }
  while (std::getline(ifs, line)) {
    size_t pos = line.find_first_not_of(' ');
    if (pos == std::string::npos || line[pos] == '#') continue;
    pos = line.find("export ", pos);
    if (pos == std::string::npos) {
      std::cerr << "Invalid line: " << line << std::endl;
      continue;
    }
    pos = line.find_first_not_of(' ', pos + 7);
    if (pos == std::string::npos) {
      std::cerr << "Invalid line: " << line << std::endl;
      continue;
    }
    size_t eq_pos = line.find('=', pos);
    if (eq_pos == std::string::npos) {
      std::cerr << "Invalid line: " << line << std::endl;
      continue;
    }
    std::string key = line.substr(pos, eq_pos - pos);
    pos = line.find_first_not_of(' ', eq_pos + 1);
    if (pos == std::string::npos) {
      std::cerr << "Invalid line: " << line << std::endl;
      continue;
    }
    std::string value = line.substr(pos);
    env[key] = value;
  }
  return env;
}
}  // namespace stringutil
}  // namespace cjj365
