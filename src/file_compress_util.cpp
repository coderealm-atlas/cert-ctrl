#include "util/file_compress_util.hpp"

#include <mz.h>
#include <mz_strm.h>
#include <mz_strm_buf.h>
#include <mz_strm_mem.h>
#include <mz_strm_os.h>
#include <mz_zip.h>
#include <stddef.h>
#include <stdint.h>

#include <filesystem>
#include <fstream>
#include <ostream>
#include <stdexcept>

#include "common_macros.hpp"
#include "result_monad.hpp"

namespace fs = std::filesystem;

namespace cjj365 {
namespace fileprocessutil {

std::string create_zip_in_memory_old(
    const std::vector<std::pair<std::string, std::string>>& namevalues) {
  void* mem_stream = mz_stream_mem_create();
  if (!mem_stream) {
    throw std::runtime_error("Failed to create memory stream.");
  }

  mz_stream_mem_set_grow_size(mem_stream, 128 * 1024);
  if (mz_stream_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE) != MZ_OK) {
    mz_stream_mem_delete(&mem_stream);
    throw std::runtime_error("Failed to open memory stream.");
  }

  void* zip_handle = mz_zip_create();
  if (!zip_handle) {
    mz_stream_mem_delete(&mem_stream);
    throw std::runtime_error("Failed to create ZIP handle.");
  }

  if (mz_zip_open(zip_handle, mem_stream, MZ_OPEN_MODE_WRITE) != MZ_OK) {
    mz_zip_delete(&zip_handle);
    mz_stream_mem_delete(&mem_stream);
    throw std::runtime_error("Failed to open ZIP writer.");
  }

  try {
    for (const auto& item : namevalues) {
      std::string filename = item.first;  // Ensure lifetime
      const std::string& content = item.second;

      mz_zip_file file_info = {};
      file_info.filename = filename.c_str();

      if (mz_zip_entry_write_open(zip_handle, &file_info,
                                  MZ_COMPRESS_METHOD_DEFLATE, 0,
                                  NULL) != MZ_OK) {
        throw std::runtime_error("Failed to open ZIP entry for: " + filename);
      }

      int bytes_written =
          mz_zip_entry_write(zip_handle, content.data(), content.size());
      if (bytes_written < 0) {
        mz_zip_entry_close(zip_handle);  // Ensure entry is closed
        throw std::runtime_error("Failed to write content for: " + filename);
      }

      mz_zip_entry_close(zip_handle);  // Close each entry properly
    }

    // **Ensure ZIP is properly finalized**
    if (mz_zip_close(zip_handle) != MZ_OK) {
      throw std::runtime_error("Failed to close ZIP writer.");
    }

    mz_zip_delete(&zip_handle);
    mz_stream_close(mem_stream);  // **Ensure stream is finalized**

  } catch (...) {
    mz_zip_close(zip_handle);
    mz_zip_delete(&zip_handle);
    mz_stream_mem_delete(&mem_stream);
    throw;  // Rethrow original exception
  }

  // **Retrieve memory buffer after closing the ZIP properly**
  void* buf = nullptr;
  int32_t len = 0;
  mz_stream_mem_get_buffer_length(mem_stream, &len);
  DEBUG_PRINT("len: " << len);
  int err =
      mz_stream_mem_get_buffer(mem_stream, const_cast<const void**>(&buf));
  if (err != MZ_OK) {
    mz_stream_mem_delete(&mem_stream);
    throw std::runtime_error("Failed to retrieve ZIP data from memory.");
  }

  if (len <= 0 || !buf) {
    mz_stream_mem_delete(&mem_stream);
    throw std::runtime_error("Failed to retrieve ZIP data from memory.");
  }

  std::string zip_data(static_cast<char*>(buf), len);
  mz_stream_mem_delete(&mem_stream);  // Clean up memory stream
  return zip_data;
}

std::string create_zip_in_memory(
    const std::vector<std::pair<std::string, std::string>>& namevalues) {
  void* mem_stream = mz_stream_mem_create();
  if (!mem_stream) {
    throw std::runtime_error("Failed to create memory stream.");
  }
  mz_stream_mem_set_grow_size(mem_stream, 128 * 1024);

  if (mz_stream_open(mem_stream, nullptr, MZ_OPEN_MODE_CREATE) != MZ_OK) {
    mz_stream_mem_delete(&mem_stream);
    throw std::runtime_error("Failed to open memory stream.");
  }

  void* zip_handle = mz_zip_create();
  if (!zip_handle) {
    mz_stream_close(mem_stream);
    mz_stream_mem_delete(&mem_stream);
    throw std::runtime_error("Failed to create ZIP handle.");
  }

  if (mz_zip_open(zip_handle, mem_stream, MZ_OPEN_MODE_WRITE) != MZ_OK) {
    mz_zip_delete(&zip_handle);
    mz_stream_close(mem_stream);
    mz_stream_mem_delete(&mem_stream);
    throw std::runtime_error("Failed to open ZIP writer.");
  }

  try {
    for (const auto& item : namevalues) {
      const std::string& filename = item.first;
      const std::string& content = item.second;

      mz_zip_file file_info = {};
      file_info.filename = filename.c_str();
      file_info.flag = MZ_ZIP_FLAG_UTF8;

      if (mz_zip_entry_write_open(zip_handle, &file_info,
                                  MZ_COMPRESS_METHOD_DEFLATE, 0,
                                  nullptr) != MZ_OK) {
        throw std::runtime_error("Failed to open ZIP entry for: " + filename);
      }

      int bytes_written = mz_zip_entry_write(
          zip_handle, content.data(), static_cast<int32_t>(content.size()));
      if (bytes_written < 0) {
        mz_zip_entry_close(zip_handle);
        throw std::runtime_error("Failed to write content for: " + filename);
      }

      mz_zip_entry_close(zip_handle);
    }

    if (mz_zip_close(zip_handle) != MZ_OK) {
      mz_zip_delete(&zip_handle);
      mz_stream_close(mem_stream);
      mz_stream_mem_delete(&mem_stream);
      throw std::runtime_error("Failed to close ZIP writer.");
    }

    mz_zip_delete(&zip_handle);

    if (mz_stream_close(mem_stream) != MZ_OK) {
      mz_stream_mem_delete(&mem_stream);
      throw std::runtime_error("Failed to close memory stream.");
    }

  } catch (...) {
    mz_zip_close(zip_handle);
    mz_zip_delete(&zip_handle);
    mz_stream_close(mem_stream);
    mz_stream_mem_delete(&mem_stream);
    throw;
  }

  void* buf = nullptr;
  int32_t len = 0;
  mz_stream_mem_get_buffer_length(mem_stream, &len);
  int err =
      mz_stream_mem_get_buffer(mem_stream, const_cast<const void**>(&buf));
  if (err != MZ_OK || len <= 0 || !buf) {
    mz_stream_mem_delete(&mem_stream);
    throw std::runtime_error("Failed to retrieve ZIP data from memory.");
  }

  std::string zip_data(static_cast<const char*>(buf), len);
  mz_stream_mem_delete(&mem_stream);
  return zip_data;
}

monad::MyResult<std::string> create_zip_in_memory_monad(
    const std::vector<std::pair<std::string, std::string>>& namevalues) {
  try {
    std::string zip_data = create_zip_in_memory(namevalues);
    return monad::MyResult<std::string>::Ok(zip_data);
  } catch (const std::exception& e) {
    return monad::MyResult<std::string>::Err(
        {.code = 1, .what = "Failed to create zip: " + std::string(e.what())});
  }
}

// Helper RAII struct for resource cleanup
struct Cleanup {
  void*& zip_handle;
  void*& buf_stream;
  void*& os_stream;
  ~Cleanup() {
    if (zip_handle) mz_zip_delete(&zip_handle);
    if (buf_stream) mz_stream_buffered_delete(&buf_stream);
    if (os_stream) mz_stream_os_delete(&os_stream);
  }
};

// Main unzip function
void unzip_to_folder(const fs::path& zip_file_path,
                     const fs::path& out_folder_path) {
  void* os_stream = nullptr;
  void* buf_stream = nullptr;
  void* zip_handle = nullptr;
  Cleanup cleanup{zip_handle, buf_stream, os_stream};

  // --- Open OS file stream ---
  os_stream = mz_stream_os_create();
  if (!os_stream) throw std::runtime_error("Failed to create OS stream.");
  int res = mz_stream_os_open(os_stream, zip_file_path.string().c_str(),
                              MZ_OPEN_MODE_READ);
  if (res != MZ_OK)
    throw std::runtime_error("Failed to open file for reading: " +
                             zip_file_path.string());

  // --- Stack buffered stream on top ---
  buf_stream = mz_stream_buffered_create();
  if (!buf_stream)
    throw std::runtime_error("Failed to create buffered stream.");
  mz_stream_set_base(buf_stream, os_stream);  // DO NOT open buf_stream

  // --- Create zip handle and open archive ---
  zip_handle = mz_zip_create();
  if (!zip_handle) throw std::runtime_error("Failed to create ZIP handle.");
  res = mz_zip_open(zip_handle, buf_stream, MZ_OPEN_MODE_READ);
  if (res != MZ_OK)
    throw std::runtime_error("Failed to open ZIP archive: " +
                             zip_file_path.string());

  // --- Extract all entries ---
  mz_zip_file* file_info = nullptr;
  int32_t err = mz_zip_goto_first_entry(zip_handle);

  while (err == MZ_OK) {
    if (mz_zip_entry_get_info(zip_handle, &file_info) == MZ_OK) {
      std::string entry_name = file_info->filename ? file_info->filename : "";
      if (entry_name.empty()) {
        err = mz_zip_goto_next_entry(zip_handle);
        continue;
      }
      fs::path out_path = out_folder_path / entry_name;
      fs::create_directories(out_path.parent_path());

      if (mz_zip_entry_is_dir(zip_handle)) {
        fs::create_directories(out_path);
      } else {
        if (mz_zip_entry_read_open(zip_handle, 0, nullptr) != MZ_OK)
          throw std::runtime_error("Failed to open ZIP entry: " + entry_name);

        std::ofstream ofs(out_path, std::ios::binary);
        if (!ofs)
          throw std::runtime_error("Failed to create file: " +
                                   out_path.string());

        std::vector<char> buffer(4096);
        int32_t bytes_read = 0;
        while ((bytes_read = mz_zip_entry_read(zip_handle, buffer.data(),
                                               buffer.size())) > 0)
          ofs.write(buffer.data(), bytes_read);

        mz_zip_entry_close(zip_handle);
      }
    }
    err = mz_zip_goto_next_entry(zip_handle);
  }
  // Explicitly close zip archive (safe even if already cleaned up)
  mz_zip_close(zip_handle);
}

monad::MyVoidResult unzip_to_folder_monad(const fs::path& zip_file_path,
                                          const fs::path& out_folder_path) {
  try {
    unzip_to_folder(zip_file_path, out_folder_path);
    return monad::MyVoidResult::Ok();
  } catch (const std::exception& e) {
    return monad::MyVoidResult::Err(
        {.code = 1, .what = "Failed to unzip: " + std::string(e.what())});
  }
}

void zip_a_folder_old(const fs::path& folder_path,
                      const fs::path& zip_file_path) {
  void* stream = NULL;
  void* buf_stream = NULL;
  void* zip_handle = NULL;

  stream = mz_stream_os_create();
  buf_stream = mz_stream_buffered_create();
  mz_stream_buffered_open(buf_stream, zip_file_path.c_str(),
                          MZ_OPEN_MODE_WRITE);

  zip_handle = mz_zip_create();
  if (!zip_handle) {
    throw std::runtime_error("Failed to create ZIP handle.");
  }

  int err = mz_zip_open(zip_handle, buf_stream, MZ_OPEN_MODE_WRITE);

  if (err != MZ_OK) {
    mz_zip_delete(&zip_handle);
    mz_stream_buffered_delete(&buf_stream);
    mz_stream_os_delete(&stream);
    throw std::runtime_error("Failed to open ZIP writer.");
  }

  for (auto& p : fs::recursive_directory_iterator(folder_path)) {
    if (fs::is_regular_file(p)) {
      std::string filename = p.path().string();
      std::string zip_path =
          p.path().string().substr(folder_path.string().size());
      mz_zip_file file_info = {};
      file_info.filename = zip_path.c_str();
      file_info.flag = MZ_ZIP_FLAG_UTF8;

      if (mz_zip_entry_write_open(zip_handle, &file_info,
                                  MZ_COMPRESS_METHOD_STORE, 0, NULL) != MZ_OK) {
        throw std::runtime_error("Failed to open ZIP entry for: " + filename);
      }

      std::ifstream ifs(filename, std::ios::binary);
      std::vector<char> buffer(8192);
      while (ifs) {
        ifs.read(buffer.data(), buffer.size());
        int bytes_read = ifs.gcount();
        if (bytes_read < 0) {
          mz_zip_entry_close(zip_handle);  // Ensure entry is closed
          throw std::runtime_error("Failed to read content for: " + filename);
        }
        if (mz_zip_entry_write(zip_handle, buffer.data(), bytes_read) < 0) {
          mz_zip_entry_close(zip_handle);  // Ensure entry is closed
          throw std::runtime_error("Failed to write content for: " + filename);
        }
      }
      mz_zip_entry_close(zip_handle);  // Close each entry properly
    }
  }
}

void zip_a_folder(const std::string& folder_path,
                  const std::string& zip_file_path) {
  void* stream = nullptr;
  void* buf_stream = nullptr;
  void* zip_handle = nullptr;

  stream = mz_stream_os_create();
  if (!stream) throw std::runtime_error("Failed to create OS stream.");

  buf_stream = mz_stream_buffered_create();
  if (!buf_stream) {
    mz_stream_os_delete(&stream);
    throw std::runtime_error("Failed to create buffered stream.");
  }

  if (mz_stream_buffered_open(buf_stream, zip_file_path.c_str(),
                              MZ_OPEN_MODE_WRITE) != MZ_OK) {
    mz_stream_buffered_delete(&buf_stream);
    mz_stream_os_delete(&stream);
    throw std::runtime_error("Failed to open buffered stream for writing.");
  }

  zip_handle = mz_zip_create();
  if (!zip_handle) {
    mz_stream_buffered_delete(&buf_stream);
    mz_stream_os_delete(&stream);
    throw std::runtime_error("Failed to create ZIP handle.");
  }

  if (mz_zip_open(zip_handle, buf_stream, MZ_OPEN_MODE_WRITE) != MZ_OK) {
    mz_zip_delete(&zip_handle);
    mz_stream_buffered_delete(&buf_stream);
    mz_stream_os_delete(&stream);
    throw std::runtime_error("Failed to open ZIP writer.");
  }

  try {
    for (auto& p : fs::recursive_directory_iterator(folder_path)) {
      if (fs::is_regular_file(p)) {
        const auto& path = p.path();
        auto rel_path = fs::relative(path, folder_path).generic_string();

        mz_zip_file file_info = {};
        file_info.filename = rel_path.c_str();
        file_info.flag = MZ_ZIP_FLAG_UTF8;

        // Use compression (DEFLATE); change to STORE if needed
        if (mz_zip_entry_write_open(zip_handle, &file_info,
                                    MZ_COMPRESS_METHOD_DEFLATE, 0,
                                    nullptr) != MZ_OK) {
          throw std::runtime_error("Failed to open ZIP entry for: " + rel_path);
        }

        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) {
          mz_zip_entry_close(zip_handle);
          throw std::runtime_error("Failed to open file for reading: " +
                                   path.string());
        }

        std::vector<char> buffer(8192);
        while (ifs) {
          ifs.read(buffer.data(), buffer.size());
          std::streamsize bytes_read = ifs.gcount();
          if (bytes_read <= 0) break;
          if (mz_zip_entry_write(zip_handle, buffer.data(),
                                 static_cast<int32_t>(bytes_read)) < 0) {
            mz_zip_entry_close(zip_handle);
            throw std::runtime_error("Failed to write content for: " +
                                     rel_path);
          }
        }
        mz_zip_entry_close(zip_handle);
      }
    }
  } catch (...) {
    mz_zip_close(zip_handle);
    mz_zip_delete(&zip_handle);
    mz_stream_buffered_close(buf_stream);
    mz_stream_buffered_delete(&buf_stream);
    mz_stream_os_delete(&stream);
    throw;  // rethrow original exception
  }

  mz_zip_close(zip_handle);
  mz_zip_delete(&zip_handle);
  mz_stream_buffered_close(buf_stream);
  mz_stream_buffered_delete(&buf_stream);
  mz_stream_os_delete(&stream);
}

monad::MyVoidResult zip_a_folder_monad(const fs::path& folder_path,
                                       const fs::path& zip_file_path) {
  try {
    zip_a_folder(folder_path.string(), zip_file_path.string());
    return monad::MyVoidResult::Ok();
  } catch (const std::exception& e) {
    return monad::MyVoidResult::Err(
        {.code = 1, .what = "Failed to zip folder: " + std::string(e.what())});
  }
}

}  // namespace fileprocessutil
}  // namespace cjj365
