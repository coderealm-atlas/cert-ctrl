#include "util/string_util.hpp"

#include <stdio.h>
#include <string.h>
#include <boost/uuid/basic_random_generator.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <cstdlib>

namespace cjj365 {
namespace stringutil {
// Check if content type indicates multipart form data
bool is_multipart_form_data(const std::string& content_type) {
  const std::string search_str = "multipart/form-data";
  return std::search(content_type.begin(), content_type.end(),
                     search_str.begin(), search_str.end(),
                     case_insensitive{}) != content_type.end();
}

void lines_without_comments(const std::string& content,
                            std::vector<std::string>& lines) {
  std::string line;
  std::istringstream iss(content);
  while (std::getline(iss, line)) {
    std::string_view line_v = line;
    size_t non_space = line_v.find_first_not_of(" \t");
    if (non_space != std::string_view::npos) {
      line_v = line_v.substr(non_space);
    }
    if (line_v.empty() || line_v[0] == '#') {
      continue;
    }
    lines.push_back(std::string{line_v});
  }
}
void lines_without_comments(const fs::path& file,
                            std::vector<std::string>& lines) {
  if (!fs::exists(file)) {
    return;
  }
  std::ifstream ifs(file);
  if (!ifs.is_open()) {
    std::cerr << "Error opening file: " << file << std::endl;
    return;
  }
  std::string content{std::istreambuf_iterator<char>(ifs),
                      std::istreambuf_iterator<char>()};
  lines_without_comments(content, lines);
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
std::string_view next_segment(std::string const& path, size_t& pos) {
  if (path[pos] != '/' || pos >= path.length()) return std::string_view{};
  size_t start_pos = pos + 1;
  pos = path.find('/', start_pos) == std::string::npos
            ? path.length()
            : path.find('/', start_pos);
  return std::string_view{path.data() + start_pos, pos - start_pos};
}

/**
 * @brief Extract all segments of a path
 * /a/b/c, return ["a", "b", "c"]
 *
 * @param path The path to extract the segments from
 * @return std::vector<std::string_view> The segments of the path
 */
std::vector<std::string_view> all_segments(std::string const& path) {
  std::vector<std::string_view> segments;
  size_t pos = 0;
  while (pos < path.length()) {
    std::string_view seg = next_segment(path, pos);
    if (!seg.empty()) segments.push_back(seg);
  }
  return segments;
}

std::string readFile(const std::string& filePath) {
  std::ifstream file(filePath);

  // Check if the file is open
  if (!file.is_open()) {
    throw std::ios_base::failure("Error reading file: " + filePath);
  }

  // Read the file into a string stream buffer
  std::ostringstream ss;
  ss << file.rdbuf();  // Reading the whole buffer
  if (!file.good()) {
    throw std::ios_base::failure("Error reading file: " + filePath);
  }

  // Return the string
  return ss.str();
}

std::string readFile(const std::string& filePath, std::error_code& ec) {
  std::ifstream file(filePath);

  // Check if the file is open
  if (!file.is_open()) {
    ec = std::make_error_code(std::errc::no_such_file_or_directory);
    return "";
  }

  // Read the file into a string stream buffer
  std::ostringstream ss;
  ss << file.rdbuf();  // Reading the whole buffer

  if (!file.good()) {
    ec = std::make_error_code(std::errc::io_error);
    return "";
  }

  // Return the string
  return ss.str();
}
unsigned int days_since_that_day(const std::string& created_at) {
  std::istringstream ss(created_at);
  date::sys_time<std::chrono::seconds> tp_created;
  ss >> date::parse("%Y-%m-%dT%H:%M:%S", tp_created);

  if (ss.fail()) {
    throw std::runtime_error("Failed to parse time string: " + created_at);
  }

  auto now = std::chrono::system_clock::now();
  return std::chrono::duration_cast<std::chrono::hours>(now - tp_created)
             .count() /
         24;
}

unsigned int days_since_epoch_seconds(uint64_t seconds) {
  auto now = std::chrono::system_clock::now();
  auto tp_created = std::chrono::system_clock::from_time_t(seconds);
  return std::chrono::duration_cast<std::chrono::hours>(now - tp_created)
             .count() /
         24;
}

std::string htmlUnescape(std::string_view str,
                         std::vector<std::string_view> signs) {
  static const std::map<std::string_view, std::string_view> htmlEntities = {
      {"&quot;", "\""}, {"&amp;", "&"},  {"&lt;", "<"},   {"&gt;", ">"},
      {"&apos;", "'"},  {"&nbsp;", " "}, {"&copy;", "©"}, {"&reg;", "®"}};

  // signs: quote,amp etc
  std::map<std::string_view, std::string_view> sign_to_replace;
  for (auto sign : signs) {
    if (sign.empty()) continue;
    std::string sign_entity = "&" + std::string{sign} + ";";
    auto it = htmlEntities.find(sign_entity);
    if (it != htmlEntities.end()) {
      sign_to_replace[it->first] = it->second;
    }
  }
  std::string result;
  result.reserve(str.size());

  for (size_t i = 0; i < str.size(); ++i) {
    if (str[i] == '&') {
      size_t semicolonPos = str.find(';', i);
      if (semicolonPos != std::string::npos) {
        std::string_view entity = str.substr(i, semicolonPos - i + 1);
        auto it = sign_to_replace.find(entity);
        if (it != sign_to_replace.end()) {
          result += it->second;
          i = semicolonPos;
          continue;
        }
      }
    }
    result += str[i];
  }
  return result;
}
std::map<std::string_view, std::string_view> parse_attributes(
    std::string_view tag_content) {
  size_t pos = std::string::npos;
  std::map<std::string_view, std::string_view> attributes;
  do {
    // ' unquote="quot,amp" to-top to-head="true"'
    size_t _start_sp = tag_content.find_first_not_of(" ");
    if (_start_sp != std::string::npos) {
      tag_content = tag_content.substr(_start_sp);
    } else {
      if (tag_content.empty()) {
        break;
      }
      bool all_sp = std::all_of(tag_content.begin(), tag_content.end(),
                                [](char c) { return c == ' '; });
      if (all_sp) {
        break;
      }
    }

    // find first occurence of '=', ' ' or '>'
    size_t pos_sp = tag_content.find_first_of(" ");
    size_t pos_eq = tag_content.find_first_of("=");
    // get cloest one
    bool is_space = pos_sp != std::string::npos;
    bool is_equal = pos_eq != std::string::npos;

    if (is_space) {
      pos = pos_sp;
      size_t pos_next_none_sp = tag_content.find_first_not_of(" ", pos_sp + 1);
      if (pos_next_none_sp != std::string::npos) {
        if (tag_content[pos_next_none_sp] == '>') {
          break;
        } else if (tag_content[pos_next_none_sp] == '=') {
          is_space = false;
        }
      }
    }
    if (is_equal && (pos == std::string::npos || pos_eq < pos)) {
      pos = pos_eq;
      is_space = false;
    }

    if (is_space) {
      // get the attribute name
      std::string_view key = tag_content.substr(0, pos);
      attributes[key] = "";
      // move to the next attribute
      tag_content = tag_content.substr(pos + 1);
    } else if (is_equal) {
      // get the attribute name
      std::string_view key = tag_content.substr(0, pos);
      size_t last_sp = key.find_last_of(" ");
      if (last_sp != std::string::npos) {
        key = key.substr(last_sp + 1);
      }
      size_t quote_start = tag_content.find('"', pos + 1);
      if (quote_start == std::string::npos) {
        break;
      }
      size_t quote_end = tag_content.find('"', quote_start + 1);
      if (quote_end == std::string::npos) {
        break;
      }
      std::string_view value =
          tag_content.substr(quote_start + 1, quote_end - quote_start - 1);
      // add the attribute to the map
      attributes[key] = value;
      // move to the next attribute
      tag_content = tag_content.substr(quote_end + 1);
    } else {
      if (tag_content.empty()) {
        break;
      } else {
        std::string_view key = tag_content;
        attributes[key] = "";
        break;
      }
    }
  } while (pos != std::string::npos);
  return attributes;
}


std::string replaceAllEfficient(const std::string& input,
                                const std::string& from,
                                const std::string& to) {
  if (from.empty()) return input;  // Avoid infinite loop if 'from' is empty
  std::string result;
  result.reserve(input.size());
  size_t last = 0, next;
  while ((next = input.find(from, last)) != std::string::npos) {
    result.append(input, last, next - last);
    result += to;
    last = next + from.size();
  }
  result += input.substr(last);
  return result;
}

// Function to convert ISO 8601 to HTTP Last-Modified format
std::string iso8601_to_last_modified(const std::string& iso8601) {
  std::istringstream in{iso8601};
  std::chrono::system_clock::time_point tp;
  in >> date::parse("%Y-%m-%dT%H:%M:%S", tp);

  if (in.fail()) {
    throw std::invalid_argument("Failed to parse ISO 8601 datetime.");
  }

  // Format the time_point to HTTP date format (RFC 7231)
  std::ostringstream out;
  out << date::format("%a, %d %b %Y %H:%M:%S GMT", tp);
  return out.str();
}

std::string to_visible_or_hex(const std::string& str, bool escape_newline) {
  std::string result;
  for (char c : str) {
    if (std::isprint(c)) {
      result.push_back(c);
    } else {
      switch (c) {
        case '\r': {
          if (escape_newline) {
            result.append("\\r");
          } else {
            result.push_back(c);
          }
          break;
        }
        case '\n': {
          if (escape_newline) {
            result.append("\\n");
          } else {
            result.push_back(c);
          }
          break;
        }
        case '\t':
          result.append("\\t");
          break;
        case 0:
          result.append("\\0");
          break;
        default:
          // convert unpintable characters to hex format
          // result.push_back(printf("\\x%02x", c));
          // Correct way to format non-printable characters as hex
          char hex_repr[5];  // 4 chars for \xNN and 1 for the null terminator
          sprintf(hex_repr, "\\x%02x",
                  static_cast<unsigned char>(c));  // Format hex value
          result.append(hex_repr);  // Append the formatted string
      }
    }
  }
  return result;
}

// Helper function to replace ${VARIABLE} or ${VARIABLE:-default} with the
// environment variable
std::string replace_env_var(
    const std::string& input,
    const std::map<std::string, std::string>& extra_map) {
  std::string output = input;

  // Basic parsing for ${VARIABLE} or ${VARIABLE:-default} patterns
  size_t start = output.find("${");
  size_t end = output.find('}', start);
  if (start != std::string::npos && end != std::string::npos) {
    std::string env_var = output.substr(start + 2, end - start - 2);
    std::string default_val;

    // Check for the ":-" syntax for default values
    size_t delim = env_var.find(":-");
    if (delim != std::string::npos) {
      default_val = env_var.substr(delim + 2);
      env_var = env_var.substr(0, delim);
    }

    if (extra_map.find(env_var) != extra_map.end()) {
      output.replace(start, end - start + 1, extra_map.at(env_var));
    } else {
      // Substitute environment variable or default
      const char* env_value = std::getenv(env_var.c_str());
      if (env_value) {
        output.replace(start, end - start + 1, env_value);
      } else {
        return default_val;
      }
    }
  }
  return output;
}

std::string file_changed_tag_simple(const std::string& file) {
  // get the last modified time of the file and the size of the file
  std::error_code ec;
  auto last_write_time = fs::last_write_time(file, ec);
  if (ec) {
    std::cerr << "Failed to retrieve file time: " << ec.message() << std::endl;
    return "";
  }
  auto file_size = fs::file_size(file, ec);
  if (ec) {
    std::cerr << "Failed to retrieve file size: " << ec.message() << std::endl;
    return "";
  }
  // convert the last modified time to a consistent representation (e.g.,
  // seconds since epoch)
  auto time_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                          last_write_time.time_since_epoch())
                          .count();
  return fmt::format("{}-{}", time_seconds, file_size);
}

fs::path create_unique_temp_directory() {
  // Get the system temporary directory
  fs::path temp_dir = fs::temp_directory_path();

  // Create a unique directory name
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(100000, 999999);

  fs::path unique_dir;
  do {
    unique_dir = temp_dir / ("unique_temp_dir_" + std::to_string(dis(gen)));
  } while (fs::exists(unique_dir));

  // Create the directory
  fs::create_directories(unique_dir);

  return unique_dir;
}

bool is_url_safe_string(const std::string& url) {
  if (url.empty()) {
    return false;  // Prevent empty names
  }
  for (char ch : url) {
    if (!(std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' ||
          ch == '~' || ch == '/' || ch == '?' || ch == '=' || ch == '&' ||
          ch == '%' || ch == '#' || ch == ':' || ch == '@' || ch == '+' ||
          ch == '$' || ch == '!' || ch == '*' || ch == '(' || ch == ')' ||
          ch == ',' || ch == ';' || ch == '[' || ch == ']' || ch == '{' ||
          ch == '}' || ch == '|' || ch == '^' || ch == '`')) {
      return false;  // Invalid character found
    }
  }
  return true;
}

bool is_filename_safe_string(const std::string& filename) {
  if (filename.empty() || filename == "." || filename == "..") {
    return false;  // Prevent empty names and reserved names
  }
  // no concessive ..
  if (filename.find("..") != std::string::npos) {
    return false;
  }
  // first character must be alphatic
  if (!std::isalpha(filename[0])) {
    return false;
  }
  // don't ends with - or _
  if (filename.back() == '-' || filename.back() == '_') {
    return false;
  }
  for (char ch : filename) {
    if (!(std::isalnum(ch) || ch == '_' || ch == '-')) {
      return false;  // Invalid character found
    }
  }
  return true;
}

std::string generate_uuid(const std::string& prefix, bool no_dash) {
  static boost::uuids::random_generator generator;
  std::string v = boost::uuids::to_string(generator());
  if (no_dash) {
    // remove the dash -
    v.erase(std::remove(v.begin(), v.end(), '-'), v.end());
  }
  return prefix + v;
}

/**
 * @brief Get the lexically largest file name in a directory
 *
 * @param dir The directory to search
 * @param prefix The prefix of the file name
 * @param ext The extension of the file, or "IGNORE_EXT" to ignore extension
 *
 */
fs::path biggest_name(const fs::path& dir, const std::string& prefix,
                      const std::string& ext) {
  if (!fs::exists(dir)) {
    return fs::path{};
  }

  std::vector<fs::directory_entry> entries;
  for (const auto& entry : fs::directory_iterator(dir)) {
    if (!entry.is_regular_file()) {
      continue;
    }
    if (!(ext == "IGNORE_EXT") && entry.path().extension() != ext) {
      continue;
    }
    if (!prefix.empty() && entry.path().stem().string().find(prefix) != 0) {
      continue;
    }
    entries.push_back(entry);
  }

  // Sort entries lexicographically based on filename
  std::sort(
      entries.begin(), entries.end(),
      [&prefix](const fs::directory_entry& a, const fs::directory_entry& b) {
        auto filename_a = a.path().stem().string();
        auto filename_b = b.path().stem().string();

        DEBUG_PRINT("filename_a: " << filename_a
                                   << ", filename_b: " << filename_b);

        if (prefix.empty()) {
          return filename_a < filename_b;
        }

        bool a_starts_with_prefix = filename_a.find(prefix) == 0;
        bool b_starts_with_prefix = filename_b.find(prefix) == 0;

        if (a_starts_with_prefix && b_starts_with_prefix) {
          return filename_a < filename_b;
        }
        return a_starts_with_prefix;  // Prefer filenames that start with the
                                      // prefix
      });

  // Return the last entry (the largest based on lexicographical comparison)
  if (!entries.empty()) {
    return entries.back().path();
  }

  return fs::path{};  // Return empty path if no files found
}
std::vector<std::string> insert_lines_after(
    fs::path dockerfile, const std::string& after,
    const std::vector<std::string>& lines) {
  if (lines.empty()) {
    return {};
  }
  std::ifstream ifs(dockerfile);
  if (!ifs) {
    std::cerr << "Failed to open file: " << dockerfile << std::endl;
    return {};
  }
  std::string line;
  std::vector<std::string> content;
  while (std::getline(ifs, line)) {
    // not starts with #
    auto splitted = split_trim_view(line);
    if (!splitted.empty() && splitted[0] == after) {
      content.push_back(line);
      for (const auto& l : lines) {
        content.push_back(l);
      }
    } else {
      content.push_back(line);
    }
  }
  return content;
}

std::vector<std::string> split_trim(const std::string& str, char delim,
                                    size_t maxsplit) {
  std::vector<std::string> result;
  size_t pos = 0;
  while (pos < str.size()) {
    size_t start = str.find_first_not_of({' ', '\t', delim}, pos);
    if (start == std::string::npos) break;
    size_t end = str.find_first_of({delim, ' ', '\t'}, start);
    if (end == std::string::npos) {
      result.push_back(str.substr(start));
      break;
    }
    if (maxsplit > 0 && result.size() == maxsplit - 1) {
      result.push_back(str.substr(start));
      break;
    } else {
      result.push_back(str.substr(start, end - start));
      pos = end + 1;
    }
  }
  return result;
}

std::vector<std::string_view> split_trim_view(const std::string& str,
                                              char delim, size_t maxsplit) {
  std::vector<std::string_view> result;
  size_t pos = 0;
  while (pos < str.size()) {
    size_t start = str.find_first_not_of({' ', '\t', delim}, pos);
    if (start == std::string::npos) break;
    size_t end = str.find_first_of({delim, ' ', '\t'}, start);
    if (end == std::string::npos) {
      result.push_back(std::string_view{str}.substr(start));
      break;
    }
    if (maxsplit > 0 && result.size() == maxsplit - 1) {
      result.push_back(std::string_view{str}.substr(start));
      break;
    } else {
      result.push_back(std::string_view{str}.substr(start, end - start));
      pos = end + 1;
    }
  }
  return result;
}


void skip_http_headers(std::istream& is) {
  std::string headers;
  char prev = '\0', curr = '\0';

  while (is.get(curr)) {
    headers += curr;
    if (prev == '\r' && curr == '\n') {
      if (headers.size() >= 4 &&
          headers.substr(headers.size() - 4) == "\r\n\r\n") {
        break;  // Found the end of headers
      }
    }
    prev = curr;
  }
}


IniParserIt IniParserIt::parseContent(const std::string& content) {
  IniParserIt parser;
  parser.parseContent_(content);
  return parser;
}

IniParserIt IniParserIt::parseFile(const std::string& filename) {
  IniParserIt parser;
  parser.parseFile_(filename);
  return parser;
}

void IniParserIt::parseContent_(const std::string& content) {
  std::istringstream stream(content);
  std::string line;

  currentSection = "default";  // Start with default section

  while (std::getline(stream, line)) {
    trim(line);

    // Skip empty lines or comments
    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    if (line.front() == '[' && line.back() == ']') {
      parseSectionHeader(line);
    } else if (line.find('=') != std::string::npos) {
      parseKeyValuePair(line);
    }
    // else: ignore unrecognized lines silently or throw
  }
}

// void IniParserIt::parseContent_(const std::string& content) {
//   std::istringstream stream(content);
//   std::string line;
//   bool inDefaultSection = false;

//   while (std::getline(stream, line)) {
//     trim(line);
//     if (line.empty() || line[0] == ';' || line[0] == '#') continue;

//     if (line[0] == '[') {
//       inDefaultSection = false;
//       parseSectionHeader(line);
//     } else {
//       if (!inDefaultSection) {
//         inDefaultSection = true;
//         currentSection = "default";
//       }
//       parseKeyValuePair(line);
//     }
//   }
// }

void IniParserIt::parseFile_(const fs::path& filename) {
  std::ifstream file(filename);
  if (!file) {
    std::cerr << "Could not open file: " << filename << std::endl;
    return;
  }

  std::string line;
  bool inDefaultSection = false;

  while (std::getline(file, line)) {
    trim(line);
    if (line.empty() || line[0] == ';' || line[0] == '#') continue;

    if (line[0] == '[') {
      inDefaultSection = false;
      parseSectionHeader(line);
    } else {
      if (!inDefaultSection) {
        inDefaultSection = true;
        currentSection = "default";
      }
      parseKeyValuePair(line);
    }
  }
}
}  // namespace stringutil
}  // namespace cjj365
