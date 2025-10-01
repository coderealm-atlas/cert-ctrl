#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

// Simple ANSI color printer for terminals.
// Usage:
//   customio::ColorPrinter cp; // defaults to std::cout; auto-enables if that stream is a TTY
//   cp.blue("Server started");
//   cp.yellow("Low disk space");
//   cp.red("Failed to connect");
//   cp.green("Done");
//   cp.magenta("details...");
//
// Choose a different default stream (e.g., stderr):
//   customio::ColorPrinter err_cp(std::cerr);
//   err_cp.red("This goes to stderr");
//
// Stream-style scoped usage (auto-reset at end of expression) on the chosen stream:
//   cp.red() << "error: " << detail << std::endl; // writes reset automatically
//   cp.green() << "ok" << '\n';
//
// You can also use cp.stream() to access the configured stream directly:
//   cp.stream() << "plain message\n";

namespace customio {

class ColorPrinter {
 public:
  // A scoped color stream; emits color code on construction, reset on destruction.
  class ColorProxy {
   public:
    ColorProxy(std::ostream& os, const char* code, bool enabled)
        : os_(os), enabled_(enabled) {
      if (enabled_) os_ << code;
    }
    ~ColorProxy() {
      if (enabled_) os_ << "\033[0m"; // reset
    }
    template <typename T>
    ColorProxy& operator<<(const T& v) {
      os_ << v;
      return *this;
    }
    using Manip = std::ostream& (*)(std::ostream&);
    ColorProxy& operator<<(Manip m) {
      m(os_);
      return *this;
    }

   private:
    std::ostream& os_;
    bool enabled_;
  };
  ColorPrinter()
    : stream_(&std::cerr), enable_colors_(detect_tty_for_stream(*stream_)) {}

  explicit ColorPrinter(bool enable_colors)
    : stream_(&std::cerr), enable_colors_(enable_colors) {}

  explicit ColorPrinter(std::ostream& os)
    : stream_(&os), enable_colors_(detect_tty_for_stream(os)) {}

  ColorPrinter(std::ostream& os, bool enable_colors)
    : stream_(&os), enable_colors_(enable_colors) {}

  // Enable/disable colors explicitly
  void set_enabled(bool enabled) { enable_colors_ = enabled; }
  bool enabled() const { return enable_colors_; }

  // Color control sequences
  const char* reset() const { return enable_colors_ ? "\033[0m" : ""; }
  const char* bold() const { return enable_colors_ ? "\033[1m" : ""; }
  const char* dim() const { return enable_colors_ ? "\033[2m" : ""; }

  const char* black() const { return enable_colors_ ? "\033[30m" : ""; }
  const char* red() const { return enable_colors_ ? "\033[31m" : ""; }
  const char* green() const { return enable_colors_ ? "\033[32m" : ""; }
  const char* yellow() const { return enable_colors_ ? "\033[33m" : ""; }
  const char* blue() const { return enable_colors_ ? "\033[34m" : ""; }
  const char* magenta() const { return enable_colors_ ? "\033[35m" : ""; }
  const char* cyan() const { return enable_colors_ ? "\033[36m" : ""; }
  const char* white() const { return enable_colors_ ? "\033[37m" : ""; }

  // Streams
  std::ostream& stream() const { return *stream_; }
  std::ostream& out() const { return std::cout; }
  std::ostream& err() const { return std::cerr; }

  // Convenience printers using color names
  // All messages go to the configured stream() selected at construction time.
  void black(const std::string& msg) const {
    stream() << (enable_colors_ ? this->black() : "") << msg << reset() << std::endl;
  }
  void red(const std::string& msg) const {
    stream() << (enable_colors_ ? this->red() : "") << msg << reset() << std::endl;
  }
  void green(const std::string& msg) const {
    stream() << (enable_colors_ ? this->green() : "") << msg << reset() << std::endl;
  }
  void yellow(const std::string& msg) const {
    stream() << (enable_colors_ ? this->yellow() : "") << msg << reset() << std::endl;
  }
  void blue(const std::string& msg) const {
    stream() << (enable_colors_ ? this->blue() : "") << msg << reset() << std::endl;
  }
  void magenta(const std::string& msg) const {
    stream() << (enable_colors_ ? this->magenta() : "") << msg << reset() << std::endl;
  }
  void cyan(const std::string& msg) const {
    stream() << (enable_colors_ ? this->cyan() : "") << msg << reset() << std::endl;
  }
  void white(const std::string& msg) const {
    stream() << (enable_colors_ ? this->white() : "") << msg << reset() << std::endl;
  }

  // Stream-style color proxies (auto-reset at end of expression)
  ColorProxy black() { return ColorProxy(stream(), static_cast<const ColorPrinter*>(this)->black(), enable_colors_); }
  ColorProxy red() { return ColorProxy(stream(), static_cast<const ColorPrinter*>(this)->red(), enable_colors_); }
  ColorProxy green() { return ColorProxy(stream(), static_cast<const ColorPrinter*>(this)->green(), enable_colors_); }
  ColorProxy yellow() { return ColorProxy(stream(), static_cast<const ColorPrinter*>(this)->yellow(), enable_colors_); }
  ColorProxy blue() { return ColorProxy(stream(), static_cast<const ColorPrinter*>(this)->blue(), enable_colors_); }
  ColorProxy magenta() { return ColorProxy(stream(), static_cast<const ColorPrinter*>(this)->magenta(), enable_colors_); }
  ColorProxy cyan() { return ColorProxy(stream(), static_cast<const ColorPrinter*>(this)->cyan(), enable_colors_); }
  ColorProxy white() { return ColorProxy(stream(), static_cast<const ColorPrinter*>(this)->white(), enable_colors_); }

 private:
  std::ostream* stream_;
  bool enable_colors_;

  static bool detect_tty_for_stream(std::ostream& os) {
#if defined(_WIN32)
    if (&os == &std::cout) {
      return _isatty(_fileno(stdout)) != 0;
    } else if (&os == &std::cerr) {
      return _isatty(_fileno(stderr)) != 0;
    }
    // Unknown stream, be conservative
    return false;
#else
    // Heuristic: enable when connected to a TTY and TERM isn't dumb
    bool is_tty = false;
    if (&os == &std::cout) {
      is_tty = ::isatty(fileno(stdout));
    } else if (&os == &std::cerr) {
      is_tty = ::isatty(fileno(stderr));
    }
    const char* term = std::getenv("TERM");
    bool term_ok = term && std::strcmp(term, "dumb") != 0;
    return is_tty && term_ok;
#endif
  }
};

} // namespace customio
