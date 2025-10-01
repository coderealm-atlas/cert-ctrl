#pragma once
#include "customio/color_printer.hpp"
#include "log_stream.hpp"

namespace customio {

class ConsoleOutput {

  customio::IOutput &logger_;
  ColorPrinter printer_{};

public:
  ConsoleOutput(customio::IOutput &logger) : logger_(logger) {}

  customio::IOutput &logger() { return logger_; }
  ColorPrinter &printer() { return printer_; }
};

} // namespace customio