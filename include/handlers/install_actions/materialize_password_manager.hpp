#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace certctrl::install_actions {

class IMaterializePasswordManager {
public:
  virtual ~IMaterializePasswordManager() = default;
  virtual std::optional<std::string>
  lookup(const std::string &ob_type, std::int64_t ob_id) const = 0;
  virtual void remember(const std::string &ob_type, std::int64_t ob_id,
                        std::string password) = 0;
  virtual void forget(const std::string &ob_type, std::int64_t ob_id) = 0;
  virtual void clear() = 0;
};

class MaterializePasswordManager : public IMaterializePasswordManager {
public:
  std::optional<std::string>
  lookup(const std::string &ob_type, std::int64_t ob_id) const override;
  void remember(const std::string &ob_type, std::int64_t ob_id,
                std::string password) override;
  void forget(const std::string &ob_type, std::int64_t ob_id) override;
  void clear() override;

private:
  using PasswordMap =
      std::unordered_map<std::string,
                         std::unordered_map<std::int64_t, std::string>>;
  PasswordMap passwords_;
};

} // namespace certctrl::install_actions
