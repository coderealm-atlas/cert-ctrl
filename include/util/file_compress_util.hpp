#pragma once

#include <stdint.h>
#include <minizip-ng/mz_strm_os.h>

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include "result_monad.hpp"

namespace fs = std::filesystem;

namespace cjj365 {
namespace fileprocessutil {

std::string create_zip_in_memory(
    const std::vector<std::pair<std::string, std::string>>& files);

monad::MyResult<std::string> create_zip_in_memory_monad(
    const std::vector<std::pair<std::string, std::string>>& files);

void zip_a_folder(const fs::path& folder_path, const fs::path& zip_file_path);
monad::MyVoidResult zip_a_folder_monad(const fs::path& folder_path,
                                       const fs::path& zip_file_path);

void unzip_to_folder(const fs::path& zip_file_path,
                     const fs::path& out_folder_path);
monad::MyVoidResult unzip_to_folder_monad(const fs::path& zip_file_path,
                                          const fs::path& out_folder_path);
}  // namespace fileprocessutil
}  // namespace cjj365
