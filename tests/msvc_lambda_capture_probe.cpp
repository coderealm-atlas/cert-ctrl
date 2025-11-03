#include <chrono>
#include <memory>

namespace sample {

struct Fetcher {
  static constexpr int kClassMaxAttempts = 3;
  static constexpr auto kBaseDelay = std::chrono::seconds{1};

  void run_class_constant() {
    auto attempts = std::make_shared<int>(0);

    auto configure_request = [this, attempts](auto token) {
      ++(*attempts);
      return token + kClassMaxAttempts; // OK on both GCC and MSVC
    };

    auto should_retry = [attempts](int code) {
      return code == 503 && *attempts < kClassMaxAttempts;
    };

    (void)configure_request(1);
    (void)should_retry(503);
  }

  void run_local_constant() {
    constexpr int kMaxAttempts = 3;
    auto attempts = std::make_shared<int>(0);

    auto configure_request = [this, attempts, kMaxAttempts](auto token) {
      ++(*attempts);
      return token + kMaxAttempts; // Capture explicitly for MSVC compatibility
    };

    auto should_retry = [attempts, kMaxAttempts](int code) {
      return code == 503 && *attempts < kMaxAttempts; // Capture explicitly
    };

    (void)configure_request(1);
    (void)should_retry(503);
  }

  void run_captured_constant() {
    constexpr int kMaxAttempts = 3;
    auto attempts = std::make_shared<int>(0);

    auto configure_request = [this, attempts, kMaxAttempts](auto token) {
      ++(*attempts);
      return token + kMaxAttempts; // Works when captured explicitly
    };

    auto should_retry = [attempts, kMaxAttempts](int code) {
      return code == 503 && *attempts < kMaxAttempts;
    };

    (void)configure_request(1);
    (void)should_retry(503);
  }
};

} // namespace sample

int main() {
  sample::Fetcher fetcher;
  fetcher.run_class_constant();
#ifdef PROVOKE_CAPTURE_ERROR
  fetcher.run_local_constant();
#endif
  fetcher.run_captured_constant();
  return 0;
}
