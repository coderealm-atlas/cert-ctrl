#pragma once
#include "log_stream.hpp"
#include <boost/asio/thread_pool.hpp>
#include <boost/json/fwd.hpp>
#include <boost/log/trivial.hpp>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <stdexcept>
#include <string>

#include "json_util.hpp"
#include "my_error_codes.hpp"
#include "result_monad.hpp"
#include "simple_data.hpp"
#include <filesystem>
#include <iostream>

namespace certctrl
{
  namespace fs = std::filesystem;

  class ConfigFromOs; // forward declaration

  inline const std::string an_empty_str = "";

  struct CertctrlConfig
  {
    bool auto_apply_config{false};
    std::string verbose{};
    std::string base_url{"https://api.cjj365.cc"};
    std::string update_check_url{"https://install.lets-script.com/api/version/check"};
    fs::path runtime_dir{};

    friend CertctrlConfig tag_invoke(const json::value_to_tag<CertctrlConfig> &,
                                     const json::value &jv)
    {
      try
      {
        if (auto *jo_p = jv.if_object())
        {
          CertctrlConfig cc{};
          if (auto *p = jo_p->if_contains("auto_apply_config"))
          {
            cc.auto_apply_config = p->as_bool();
          }
          else
          {
            std::cerr << "Configuration key 'auto_apply_config' not found; defaulting to false"
                      << std::endl;
          }
          if (auto *p = jo_p->if_contains("verbose"))
            cc.verbose = p->as_string().c_str();
          else
            std::cerr << "verbose not found, using default empty string" << std::endl;
          if (auto *p = jo_p->if_contains("url_base"))
            cc.base_url = p->as_string().c_str();
          else
            std::cerr << "url_base not found, using default https://api.cjj365.cc" << std::endl;
          if (auto *p = jo_p->if_contains("update_check_url"))
            cc.update_check_url = p->as_string().c_str();
          else
            std::cerr << "update_check_url not found, using default https://install.lets-script.com/api/version/check" << std::endl;
          if (auto *p = jo_p->if_contains("runtime_dir"))
            cc.runtime_dir = fs::path(p->as_string().c_str());
          else
            std::cerr << "runtime_dir not found, using default empty path" << std::endl;
          return cc;
        }
        else
        {
          throw std::runtime_error("CertctrlConfig is not an object");
        }
      }
      catch (...)
      {
        throw std::runtime_error("error in parsing CertctrlConfig");
      }
    }
  };

  class ICertctrlConfigProvider
  {
  public:
    virtual ~ICertctrlConfigProvider() = default;

    virtual const CertctrlConfig &get() const = 0;
    virtual CertctrlConfig &get() = 0;

    virtual monad::MyVoidResult save(const json::object &content) = 0;
  };

  class CertctrlConfigProviderFile : public ICertctrlConfigProvider
  {
  private:
    CertctrlConfig config_;
    customio::IOutput &output_;
    cjj365::ConfigSources &config_sources_;

  public:
    CertctrlConfigProviderFile(cjj365::AppProperties &app_properties,
                               cjj365::ConfigSources &config_sources,
                               customio::IOutput &output)
        : output_(output), config_sources_(config_sources)
    {
      if (!config_sources.application_json)
      {
        output_.error() << "Failed to load App config." << std::endl;
        throw std::runtime_error("Failed to load App config.");
      }
      json::value jv = config_sources.application_json.value();
      // substitue_envs requires both CLI map and properties map. For this provider
      // we currently do not have a dedicated CLI substitution map, so pass an empty one.
      static const std::map<std::string, std::string> empty_cli_map{};
      jsonutil::substitue_envs(jv, empty_cli_map, app_properties.properties);
      config_ = json::value_to<CertctrlConfig>(std::move(jv));
    }

    const CertctrlConfig &get() const override { return config_; }
    CertctrlConfig &get() override { return config_; }

    monad::MyVoidResult save(const json::object &content) override
    {
      auto f = config_sources_.paths_.back() / "application.override.json";
      json::value jv;
      if (fs::exists(f))
      {
        std::ifstream ifs(f);
        if (!ifs)
        {
          return monad::MyVoidResult::Err(
              {.code = my_errors::GENERAL::FILE_READ_WRITE,
               .what = "Unable to open configuration file: " + f.string()});
        }
        std::string existing_content((std::istreambuf_iterator<char>(ifs)),
                                     std::istreambuf_iterator<char>());
        ifs.close();
        jv = json::parse(existing_content);
        if (!jv.is_object())
        {
          return monad::MyVoidResult::Err(
              {.code = my_errors::GENERAL::INVALID_ARGUMENT,
               .what = "Configuration file is not a JSON object: " + f.string()});
        }
        json::object &jo = jv.as_object();
        for (const auto &[key, value] : content)
        {
          jo[key] = value;
        }
      }
      else
      {
        jv = content;
      }
      std::ofstream ofs(f);
      if (!ofs)
      {
        return monad::MyVoidResult::Err(
            {.code = my_errors::GENERAL::FILE_READ_WRITE,
             .what =
                 "Unable to open configuration file for writing: " + f.string()});
      }
      ofs << content;
      ofs.close();
      return monad::MyVoidResult::Ok();
    }
  };
} // namespace certctrl

//   /**
//    * always need the parameter. so it's designed to use only once.
//    */
//   static CerttoolConfig& getInstanceByJsonValue(
//       json::value&& config_jv,
//       const std::map<std::string, std::string>& extra_map = {}) {
//     static bool initialized = false;
//     static std::unique_ptr<CerttoolConfig> instance = nullptr;
//     static std::vector<std::string> all_fields = {"misc"};
//     if (!initialized) {
//       instance = std::make_unique<CerttoolConfig>(
//           createByJsonValue(std::move(config_jv), extra_map));
//     }
//     return *instance;
//   }

//   static CerttoolConfig emptyConfig() { return CerttoolConfig(); }
//   // Gets the singleton instance
//   static CerttoolConfig& getInstance(
//       const std::string& config_file, bool is_content = false,
//       cjj365::AppwideOptions&& app_options = {}) {
//     if (config_file.empty()) {
//       std::cerr << "No configuration file specified." << std::endl;
//       throw std::runtime_error("config file is empty");
//     }
//     std::string content;
//     if (is_content) {
//       content = config_file;
//     } else {
//       auto file_size = fs::file_size(config_file);
//       if (file_size > 100 * 1024) {
//         throw std::runtime_error("File too large: " + config_file);
//       }
//       std::ifstream ifs(config_file.c_str());
//       if (!ifs) {
//         throw std::runtime_error("Unable to open configuration file: " +
//                                  config_file);
//       }
//       content = std::string((std::istreambuf_iterator<char>(ifs)),
//                             std::istreambuf_iterator<char>());
//       ifs.close();
//     }
//     std::error_code ec;
//     json::value jv = json::parse(content, ec);
//     if (ec) {
//       std::cerr << "Failed to parse configuration file: " << config_file
//                 << std::endl;
//     }
//     return getInstanceByJsonValue(std::move(jv));
//   }

//   const ToolConfig& tool_config() const {
//     if (tool_config_ == nullptr) {
//       throw std::runtime_error("tool_config is not set.");
//     }
//     return *tool_config_;
//   }

//   ToolConfig& tool_config() {
//     if (tool_config_ == nullptr) {
//       throw std::runtime_error("tool_config is not set.");
//     }
//     return *tool_config_;
//   }

//   cjj365::LoggingConfig& logging_config() const {
//     if (logging_config_ == nullptr) {
//       throw std::runtime_error("logging_config is not set.");
//     }
//     return *logging_config_;
//   }

//   cjj365::CertIssuerConfig& cert_issuer_config() const {
//     if (cert_issuer_config_ == nullptr) {
//       throw std::runtime_error("cert_issuer_config is not set.");
//     }
//     return *cert_issuer_config_;
//   }

//   json::value& mysql_config_jv() {
//     if (whole_config_jv.is_null()) {
//       throw std::runtime_error("mysql_config is not set.");
//     }
//     if (!whole_config_jv.as_object().contains("mysql_config")) {
//       throw std::runtime_error("mysql_config not found in whole_config_jv");
//     }
//     return whole_config_jv.at("mysql_config");
//   }

//   // cjj365::AcmeConfig& acme_config() const {
//   //   // DEBUG_PRINT(
//   //   //     "got called, acme_config has value: " << (acme_config_ !=
//   //   //     nullptr));
//   //   if (acme_config_ == nullptr) {
//   //     throw std::runtime_error("acme_config is not set.");
//   //   }
//   //   return *acme_config_;
//   // }

//   // cjj365::RedisConfig& redis_config() const {
//   //   if (redis_config_ == nullptr) {
//   //     throw std::runtime_error("redis_config is not set.");
//   //   }
//   //   return *redis_config_;
//   // }

//   std::string& client_id() { return client_id_; }

//   // void set_rabbit_config(
//   //     std::unique_ptr<cjj365::RabbitConfig>&& rabbit_config) {
//   //   rabbit_config_ = std::move(rabbit_config);
//   // }

//   // cjj365::RabbitConfig& rabbit_config() const {
//   //   if (rabbit_config_ == nullptr) {
//   //     throw std::runtime_error("rabbit_config is not set.");
//   //   }
//   //   return *rabbit_config_;
//   // }

//   // cjj365::CryptConfig& crypt_config() const {
//   //   if (crypt_config_ == nullptr) {
//   //     throw std::runtime_error("crypt_config is not set.");
//   //   }
//   //   return *crypt_config_;
//   // }

//   // void set_ioc_manager(int threads_num = 0) {
//   //   if (ioc_manager_ == nullptr) {
//   //     ioc_manager_ = std::make_unique<cjj365::IoContextManager>(
//   //         threads_num == 0 ? std::thread::hardware_concurrency() :
//   threads_num,
//   //         "net");
//   //   } else {
//   //     BOOST_LOG_TRIVIAL(warning)
//   //         << "ioc_manager is already set. threads_num: " << threads_num;
//   //   }
//   // }

//   void set_thread_pool(int threads_num = 0) {
//     if (thread_pool_ == nullptr) {
//       thread_pool_ = std::make_unique<asio::thread_pool>(
//           threads_num == 0 ? std::thread::hardware_concurrency() :
//           threads_num);
//     } else {
//       BOOST_LOG_TRIVIAL(warning)
//           << "thread_pool is already set. threads_num: " << threads_num;
//     }
//   }

//   asio::thread_pool& thread_pool() {
//     if (thread_pool_ == nullptr) {
//       throw std::runtime_error("thread_pool is not set.");
//     }
//     return *thread_pool_;
//   }

//   // std::optional<std::string> redis_ca_cert() {
//   //   if (redis_config_ == nullptr) {
//   //     return std::nullopt;
//   //   }
//   //   if (redis_config_->ca_str.empty()) {
//   //     return std::nullopt;
//   //   }
//   //   std::string ca_cert_decoded = base64_decode(redis_config_->ca_str);
//   //   // DEBUG_PRINT("redis ca_cert_decoded length: " <<
//   //   // ca_cert_decoded.size());
//   //   return std::make_optional(ca_cert_decoded);
//   // }

//   // asio::io_context& ioc() { return ioc_manager_->ioc(); }

//   // void stop() {
//   //   if (ioc_manager_) {
//   //     ioc_manager_->stop();
//   //     ioc_manager_.reset();
//   //     ioc_manager_ = nullptr;
//   //   }
//   // }
//   // void init() {}
// };

// }  // namespace certctrl
