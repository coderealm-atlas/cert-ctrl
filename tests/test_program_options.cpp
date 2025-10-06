// New tests focus on certctrl::CliCtx behavior and helpers defined in
// certctrl_common.hpp

#include <boost/program_options.hpp>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "certctrl_common.hpp"

namespace po = boost::program_options;
using certctrl::CliCtx;

// Helper to build a CliCtx similar to how the app would construct it
static CliCtx make_ctx(const std::vector<std::string> &argv_tokens) {
  po::options_description desc("Allowed options");
  po::positional_options_description p;
  std::vector<std::string> positionals;
  std::vector<std::string> unrecognized;

  // Common options simulated
  certctrl::CliParams params{};
  desc.add_options()("help,h", "produce help message")(
      "verbose,v", po::value<std::string>(&params.verbose)->default_value("info"),
      "verbosity: trace|debug|info|warning|error or v-count")(
      "silent", po::bool_switch(&params.silent)->default_value(false), "silent")(
      "offset", po::value<size_t>(&params.offset)->default_value(0), "offset")(
      "limit", po::value<size_t>(&params.limit)->default_value(10), "limit");

  // capture all leftover positionals into the option named "positionals"
  desc.add_options()(
      "positionals",
      po::value<std::vector<std::string>>(&positionals)->composing(),
      "positional args");
  p.add("positionals", -1);

  // Build argc/argv
  std::vector<const char *> argv;
  argv.reserve(argv_tokens.size());
  for (auto const &s : argv_tokens)
    argv.push_back(s.c_str());
  int argc = static_cast<int>(argv.size());

  po::variables_map vm;
  auto parsed = po::command_line_parser(argc, argv.data())
                    .options(desc)
                    .positional(p)
                    .allow_unregistered()
                    .run();
  po::store(parsed, vm);
  // Get unrecognized including positionals
  unrecognized =
      po::collect_unrecognized(parsed.options, po::include_positional);
  // notify after store
  if (!vm.count("help"))
    po::notify(vm);

  // Build CliParams minimally
  if (!positionals.empty())
    params.subcmd = positionals.front();

  return CliCtx(std::move(vm), std::move(positionals),
                std::move(unrecognized), std::move(params));
}

TEST(CliCtxTest, PositionalsAndUnrecognized) {
  // prog conf set key value --offset 5 --limit 20 -v debug
  auto ctx = make_ctx({"prog", "conf", "set", "feature", "true", "--offset",
                       "5", "--limit", "20", "-v", "debug"});

  // positionals captured in order
  ASSERT_EQ(ctx.positional_count(), 4u);
  EXPECT_TRUE(ctx.positional_contains("conf"));
  EXPECT_TRUE(ctx.positional_contains("set"));

  // get_set_kv extracts key/value after "set"
  auto kv = ctx.get_set_kv();
  ASSERT_TRUE(kv.is_ok());
  EXPECT_EQ(kv.value().first, "feature");
  EXPECT_EQ(kv.value().second, "true");

  auto [off, lim] = ctx.offset_limit();
  EXPECT_EQ(off, 5u);
  EXPECT_EQ(lim, 20u);

  // verbosity from "debug"
  EXPECT_EQ(ctx.verbosity_level(), 4u);
}

TEST(CliCtxTest, MissingSetValueProducesError) {
  auto ctx = make_ctx({"prog", "conf", "set", "only_key"});
  auto kv = ctx.get_set_kv();
  ASSERT_TRUE(kv.is_err());
  EXPECT_EQ(kv.error().code, my_errors::GENERAL::SHOW_OPT_DESC);
}

TEST(CliCtxTest, GetSubcommandValue) {
  auto ctx = make_ctx({"prog", "conf", "get", "auto_apply_config"});
  auto k = ctx.get_get_k();
  ASSERT_TRUE(k.is_ok());
  EXPECT_EQ(k.value(), std::string("auto_apply_config"));
}

TEST(CliCtxTest, MissingGetValueProducesError) {
  auto ctx = make_ctx({"prog", "conf", "get"});
  auto k = ctx.get_get_k();
  ASSERT_TRUE(k.is_err());
  EXPECT_EQ(k.error().code, my_errors::GENERAL::SHOW_OPT_DESC);
}

TEST(CliCtxTest, GetUnrecognizedHelper) {
  auto ctx =
      make_ctx({"prog", "conf", "set", "feature", "true", "--unknown", "42"});
  // get_unrecognized returns the value after the option name
  auto v = certctrl::get_unrecognized(ctx.unrecognized, "--unknown");
  EXPECT_EQ(v, std::string_view("42"));
}

TEST(CliCtxTest, VerbosityAndSilent) {
  // silent should override verbose
  auto ctx = make_ctx({"prog", "conf", "list", "--silent", "-v", "trace"});
  EXPECT_EQ(ctx.verbosity_level(), 0u);
}

TEST(CliCtxTest, IsSpecifiedByUserDetection) {
  // offset and limit have defaults in the parser; verbose has a default too.
  // Case 1: no explicit options provided
  auto ctx1 = make_ctx({"prog", "conf", "list"});
  EXPECT_FALSE(ctx1.is_specified_by_user("offset"));
  EXPECT_FALSE(ctx1.is_specified_by_user("limit"));
  EXPECT_FALSE(ctx1.is_specified_by_user("verbose"));

  // Case 2: user specifies offset and verbose
  auto ctx2 =
      make_ctx({"prog", "conf", "list", "--offset", "12", "-v", "debug"});
  EXPECT_TRUE(ctx2.is_specified_by_user("offset"));
  EXPECT_FALSE(ctx2.is_specified_by_user("limit"));
  EXPECT_TRUE(ctx2.is_specified_by_user("verbose"));

  // Case 3: user specifies limit and silent
  auto ctx3 = make_ctx({"prog", "conf", "list", "--limit", "25", "--silent"});
  EXPECT_FALSE(ctx3.is_specified_by_user("offset"));
  EXPECT_TRUE(ctx3.is_specified_by_user("limit"));
  EXPECT_TRUE(ctx3.is_specified_by_user("silent"));
}