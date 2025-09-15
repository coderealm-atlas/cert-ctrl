#pragma once

#include <google/protobuf/util/json_util.h>
#ifdef _WIN32
#  include <io.h>
#else
#  include <unistd.h>
#endif

#include <boost/asio/io_context.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <string>

#include "certctrl_common.hpp"
#include "certctrl_config.hpp"
#include "dicmeta.pb.h"
#include "io_context_manager.hpp"
#include "io_monad.hpp"
#include "my_error_codes.hpp"
#include "util/my_logging.hpp" // IWYU pragma: keep

namespace po = boost::program_options;

namespace certctrl {

struct MiscHandlerOptions {
};

class MiscHandler : public std::enable_shared_from_this<MiscHandler> {
  asio::io_context &ioc_;
  certctrl::ICertctrlConfigProvider &certctrl_config_provider_;
  customio::IOutput &output_hub_;
  CliCtx &cli_ctx_;
  src::severity_logger<trivial::severity_level> lg;
  std::optional<cjj365::meta::CertRecord> cert_record_;
  cjj365::meta::AcmeAccount acct_;

  po::options_description opt_desc_;
  MiscHandlerOptions options_;
  cjj365::meta::User user_;
  bool call_notify_ = true;

public:
  MiscHandler(cjj365::IoContextManager &io_context_manager,
              certctrl::ICertctrlConfigProvider &certctrl_config_provider,
              CliCtx &cli_ctx, //
              customio::IOutput &output_hub)
      : ioc_(io_context_manager.ioc()),
        certctrl_config_provider_(certctrl_config_provider),
        output_hub_(output_hub), cli_ctx_(cli_ctx),
        opt_desc_("misc subcommand options") {
    boost::program_options::options_description create_opts("conf Options");
    opt_desc_.add(create_opts);
    po::parsed_options parsed = po::command_line_parser(cli_ctx_.unrecognized)
                                    .options(opt_desc_)
                                    .allow_unregistered()
                                    .run();
    po::store(parsed, cli_ctx_.vm);
    po::notify(cli_ctx_.vm);
    output_hub_.trace() << "MiscHandler initialized with options: " << opt_desc_
                        << std::endl;
  }

  std::string print_opt_desc() const {
    std::ostringstream oss;
    oss << opt_desc_;
    return oss.str();
  }

  monad::IO<void> show_usage(const std::string &msg = "") {
    if (!msg.empty()) {
      output_hub_.error() << msg << std::endl;
    }
    return monad::IO<void>::fail(
        {.code = my_errors::GENERAL::SHOW_OPT_DESC, .what = print_opt_desc()});
  }

  monad::IO<void> start();

  inline fs::path createOrderDir(const fs::path &cert_wkdir,
                                 const std::string &user_id,
                                 const std::string &dn) {
    fs::path dn_orders_dir = cert_wkdir / "orders" / user_id / dn;
    fs::path this_order{};
    fs::create_directories(this_order);
    return this_order;
  }

  monad::IO<cjj365::meta::CertRecord> createCert(const std::string &dn);

private:
  inline std::string
  acmeOrdersToString(const google::protobuf::RepeatedPtrField<
                     cjj365::meta::AcmeOrderIdentifier> &orders) {
    std::string str;
    for (size_t i = 0; i < orders.size(); i++) {
      str += orders[i].type() + ":" + orders[i].value();
      if (i != orders.size() - 1) {
        str += ", ";
      }
    }
    return str;
  }
  monad::IO<fs::path> export_cert(const cjj365::meta::CertRecord &cert_record_);
};
} // namespace certctrl