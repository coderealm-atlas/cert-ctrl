#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/http.hpp>
#include <boost/url/parse.hpp>

#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "http_client_monad.hpp"
#include "result_monad.hpp"

namespace certctrl::async_support {

namespace asio = boost::asio;
namespace http = boost::beast::http;
namespace urls = boost::urls;

template <typename Tag>
monad::MyResult<monad::ExchangePtrFor<Tag>>
make_http_exchange(std::string_view raw_url) {
  using Req = typename monad::TagTraits<Tag>::Request;
  using Res = typename monad::TagTraits<Tag>::Response;
  using Exchange = monad::HttpExchange<Req, Res>;
  using Result = monad::MyResult<monad::ExchangePtrFor<Tag>>;

  auto parsed = urls::parse_uri(raw_url);
  if (!parsed) {
    return Result::Err(
        monad::Error{1, "Invalid HTTP URL: " + std::string(raw_url)});
  }

  Req request;
  if constexpr (std::is_same_v<Tag, monad::GetStatusTag> ||
                std::is_same_v<Tag, monad::GetHeaderTag>) {
    request = Req{http::verb::head, monad::DEFAULT_TARGET, 11};
  } else if constexpr (std::is_same_v<Tag, monad::GetStringTag> ||
                       std::is_same_v<Tag, monad::GetFileTag>) {
    request = Req{http::verb::get, monad::DEFAULT_TARGET, 11};
  } else if constexpr (std::is_same_v<Tag, monad::DeleteTag>) {
    request = Req{http::verb::delete_, monad::DEFAULT_TARGET, 11};
  } else if constexpr (std::is_same_v<Tag, monad::PostJsonTag>) {
    request = Req{http::verb::post, monad::DEFAULT_TARGET, 11};
    request.set(http::field::content_type, "application/json");
  } else {
    static_assert(monad::always_false<Tag>, "Unsupported HTTP tag");
  }

  return Result::Ok(
      std::make_shared<Exchange>(urls::url(*parsed), std::move(request)));
}

template <typename Tag>
asio::awaitable<monad::MyResult<monad::ExchangePtrFor<Tag>>>
http_exchange_awaitable(client_async::HttpClientManager &client,
                        monad::ExchangePtrFor<Tag> exchange, int verbose = 0) {
  co_return co_await monad::async_http_exchange<Tag>(
      client, std::move(exchange), verbose, asio::use_awaitable);
}

} // namespace certctrl::async_support
