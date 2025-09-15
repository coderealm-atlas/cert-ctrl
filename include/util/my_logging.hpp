#pragma once

#include "simple_data.hpp"
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/move/utility_core.hpp>
#include <boost/shared_ptr.hpp>

#include "common_macros.hpp"
// #include "models.hpp"

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace trivial = logging::trivial;

// BOOST_LOG_INLINE_GLOBAL_LOGGER_DEFAULT(my_logger, src::logger_mt)

inline void init_my_log_1() {
  boost::shared_ptr<logging::core> core = logging::core::get();

  boost::shared_ptr<sinks::text_file_backend> backend =
      boost::make_shared<sinks::text_file_backend>(
          logging::keywords::file_name = "file.log",
          logging::keywords::target_file_name = "file_%5N.log",
          logging::keywords::rotation_size = 5 * 1024 * 1024
          // ,
          // keywords::time_based_rotation =
          //     sinks::file::rotation_at_time_point(12, 0, 0)
      );

  // Wrap it into the frontend and register in the core.
  // The backend requires synchronization in the frontend.
  typedef sinks::synchronous_sink<sinks::text_file_backend> sink_t;
  boost::shared_ptr<sink_t> sink(new sink_t(backend));
  core->add_sink(sink);
}

using LoggerPtr = std::shared_ptr<
    boost::log::sources::severity_logger<boost::log::trivial::severity_level>>;

inline LoggerPtr make_logger_with_session(const std::string &session_id) {
  auto logger = std::make_shared<boost::log::sources::severity_logger<
      boost::log::trivial::severity_level>>();
  logger->add_attribute(
      "SessionID", boost::log::attributes::constant<std::string>(session_id));
  return logger;
}

inline void init_my_log(const cjj365::LoggingConfig &loggingConfig) {
  std::string logfile = std::format("{}/{}_%N.log", loggingConfig.log_dir,
                                    loggingConfig.log_file);

  auto sink = logging::add_file_log(
      logging::keywords::file_name = logfile,
      // "bbserver_%N.log", /*< file name pattern >*/
      logging::keywords::rotation_size = loggingConfig.rotation_size,
      // 10 * 1024 * 1024, /*< rotate files every 10
      // MiB... >*/ logging::keywords::time_based_rotation
      // =
      //     logging::sinks::file::rotation_at_time_point(
      //         0, 0, 0), /*< ...or at midnight >*/
      logging::keywords::format = "[%TimeStamp%] [%Severity%] [%SessionID%]: "
                                  "%Message%" /*< log record format >*/,
      logging::keywords::auto_flush = true,
      logging::keywords::open_mode = std::ios_base::app);
  // Set file collector with maximum total size or max number of files
  sink->locked_backend()->set_file_collector(
      logging::sinks::file::make_collector(
          logging::keywords::target =
              loggingConfig.log_dir, // directory to store logs
          logging::keywords::max_size = loggingConfig.rotation_size * 10,
          logging::keywords::max_files =
              10 // <== limit number of rotated log files
          ));

  // Optionally scan existing log files on startup
  sink->locked_backend()->scan_for_files();

  logging::add_common_attributes();
  if (loggingConfig.level == "trace") {
    logging::core::get()->set_filter(logging::trivial::severity >=
                                     logging::trivial::trace);
  } else if (loggingConfig.level == "debug") {
    logging::core::get()->set_filter(logging::trivial::severity >=
                                     logging::trivial::debug);
  } else if (loggingConfig.level == "info") {
    logging::core::get()->set_filter(logging::trivial::severity >=
                                     logging::trivial::info);
  } else if (loggingConfig.level == "warning") {
    logging::core::get()->set_filter(logging::trivial::severity >=
                                     logging::trivial::warning);
  } else if (loggingConfig.level == "error") {
    logging::core::get()->set_filter(logging::trivial::severity >=
                                     logging::trivial::error);
  } else if (loggingConfig.level == "fatal") {
    logging::core::get()->set_filter(logging::trivial::severity >=
                                     logging::trivial::fatal);
  } else {
    logging::core::get()->set_filter(logging::trivial::severity >=
                                     logging::trivial::info);
  }
}