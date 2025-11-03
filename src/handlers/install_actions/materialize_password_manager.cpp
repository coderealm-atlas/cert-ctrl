#include "handlers/install_actions/materialize_password_manager.hpp"

namespace certctrl::install_actions {

std::optional<std::string>
MaterializePasswordManager::lookup(const std::string &ob_type,
                                   std::int64_t ob_id) const {
  auto type_it = passwords_.find(ob_type);
  if (type_it == passwords_.end()) {
    return std::nullopt;
  }
  auto id_it = type_it->second.find(ob_id);
  if (id_it == type_it->second.end()) {
    return std::nullopt;
  }
  return id_it->second;
}

void MaterializePasswordManager::remember(const std::string &ob_type,
                                          std::int64_t ob_id,
                                          std::string password) {
  passwords_[ob_type][ob_id] = std::move(password);
}

void MaterializePasswordManager::forget(const std::string &ob_type,
                                        std::int64_t ob_id) {
  auto type_it = passwords_.find(ob_type);
  if (type_it == passwords_.end()) {
    return;
  }
  type_it->second.erase(ob_id);
  if (type_it->second.empty()) {
    passwords_.erase(type_it);
  }
}

void MaterializePasswordManager::clear() { passwords_.clear(); }

} // namespace certctrl::install_actions
