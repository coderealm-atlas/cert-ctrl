#pragma once

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <memory>
#include <string>

namespace customio {

class Spinner : public std::enable_shared_from_this<Spinner> {
 public:
  Spinner(boost::asio::any_io_executor ex, std::ostream& os,
          std::string prefix = {},
          std::chrono::milliseconds interval = std::chrono::milliseconds(120),
          bool enabled = true)
      : ex_(ex), os_(os), prefix_(std::move(prefix)), interval_(interval),
        enabled_(enabled), timer_(std::make_shared<boost::asio::steady_timer>(ex_)) {}

  void start() {
    if (!enabled_ || running_.exchange(true)) return;
    last_len_ = 0;
    schedule();
  }

  void stop(std::string final_line = {}) {
    if (!enabled_) return;
    running_.store(false);
    if (timer_) {
      timer_->cancel();
    }
    // Clear line and optionally print final message
    clear_line();
    if (!final_line.empty()) {
      os_ << final_line << std::endl;
    }
    os_.flush();
  }

 private:
  void schedule() {
    auto self = shared_from_this();
    timer_->expires_after(interval_);
    timer_->async_wait([self](const boost::system::error_code& ec) {
      if (ec) return; // cancelled
      if (!self->running_.load()) return;
      self->tick();
      self->schedule();
    });
  }

  void tick() {
    static constexpr const char* frames = "|/-\\";
    frame_idx_ = (frame_idx_ + 1) % 4;
    render(std::string(1, frames[frame_idx_]));
  }

  void render(const std::string& frame) {
    std::string line = prefix_.empty() ? frame : (prefix_ + frame);
    // Carriage return, overwrite, pad if previous was longer
    os_ << '\r' << line;
    if (line.size() < last_len_) {
      os_ << std::string(last_len_ - line.size(), ' ');
      os_ << '\r' << line; // reposition to end of current line content
    }
    os_.flush();
    last_len_ = line.size();
  }

  void clear_line() {
    if (last_len_ > 0) {
      os_ << '\r' << std::string(last_len_, ' ') << '\r';
      last_len_ = 0;
    }
  }

  boost::asio::any_io_executor ex_;
  std::ostream& os_;
  std::string prefix_;
  std::chrono::milliseconds interval_;
  bool enabled_;
  std::shared_ptr<boost::asio::steady_timer> timer_;
  std::atomic<bool> running_{false};
  std::size_t frame_idx_{0};
  std::size_t last_len_{0};
};

} // namespace customio
