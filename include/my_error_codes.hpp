// Auto-generated from error_codes.ini
#pragma once

namespace my_errors {

namespace GENERAL {  // General errors

constexpr int INVALID_ARGUMENT = 5000;  // Invalid argument
constexpr int INVALID_ENTITY = 5001;  // Invalid entity
constexpr int SHOW_OPT_DESC = 5002;  // Show options description
constexpr int NOT_FOUND = 5003;  // Not found
constexpr int MISSING_PARAM = 5004;  // Missing parameter
constexpr int MISSING_QUERY_PARAM = 5005;  // Missing query parameter
constexpr int MISSING_HEADER = 5006;  // Missing header
constexpr int MISSING_BODY = 5007;  // Missing body
constexpr int MISSING_FIELD = 5008;  // Missing field
constexpr int TYPE_CONVERT_FAILED = 5009;  // Type conversion failed
constexpr int NOT_IMPLEMENTED = 5010;  // Not implemented
constexpr int POINTER_IS_NULL = 5011;  // Pointer is null
constexpr int PARSE_PROTOBUF_FAILED = 5012;  // Parse protobuf failed
constexpr int RATE_LIMITED = 5013;  // Rate limit exceeded
constexpr int CREATE_FAILED = 5014;  // Create failed
constexpr int UPDATE_FAILED = 5015;  // Update failed
constexpr int DELETE_FAILED = 5016;  // Delete failed
constexpr int UNEXPECTED_RESULT = 5017;  // Unexpected result
constexpr int UNAUTHORIZED = 5018;  // Unauthorized
constexpr int FILE_NOT_FOUND = 5019;  // File not found
constexpr int FILE_READ_WRITE = 5020;  // File read/write error
constexpr int JSON_PARSE_ERROR = 5021;  // JSON parse error
constexpr int FORBIDDEN = 5022;  // Forbidden
}  // namespace GENERAL

namespace HTTPSERVER {  // HttpServer errors

constexpr int WRITE_RESPONSE_FAILED = 5100;  // Write response failed
constexpr int PARSE_HEADER_FAILED = 5101;  // Parse header failed
constexpr int SESSION_NOT_FOUND = 5102;  // Session not found
constexpr int HEADER_NOT_PARSED = 5103;  // Header not parsed
constexpr int NOT_LOGIN = 5104;  // Not logged in
constexpr int STREAM_CLOSED = 5105;  // Stream closed
constexpr int MISSING_HEADER = 5106;  // Missing header
}  // namespace HTTPSERVER

namespace NETWORK {  // Network errors

constexpr int CONNECT_ERROR = 5200;  // Connect error
constexpr int READ_ERROR = 5201;  // Read error
constexpr int WRITE_ERROR = 5202;  // Write error
constexpr int TIMEOUT_ERROR = 5203;  // Timeout error
constexpr int SSL_ERROR = 5204;  // SSL error
constexpr int SSL_HANDSHAKE_ERROR = 5205;  // SSL handshake error
}  // namespace NETWORK

namespace JSON {  // Json errors

constexpr int MALFORMED = 9000;  // Malformed JSON text
constexpr int DECODE_ERROR = 9001;  // Failed to decode/parse JSON (low-level)
constexpr int ENCODE_ERROR = 9002;  // Failed to encode/serialize JSON
constexpr int TYPE_MISMATCH = 9003;  // JSON type mismatch
constexpr int MISSING_JSON_FIELD = 9004;  // Required JSON field missing
constexpr int INVALID_SCHEMA = 9005;  // JSON does not conform to expected schema
}  // namespace JSON

namespace ACME {  // ACME errors

constexpr int NO_KID = 6000;  // For account can only update the KID
}  // namespace ACME

namespace PROTOBUF {  // PROTOBUF errors

constexpr int PARSE_ERROR = 7000;  // Protobuf parse error
constexpr int SERIALIZE_ERROR = 7001;  // Protobuf serialize error
}  // namespace PROTOBUF

namespace CONTROL {  // Control errors

constexpr int NOT_AN_ERROR = 999999;  // Not an error
}  // namespace CONTROL

namespace OPENSSL {  // OPENSSL errors

constexpr int UNEXPECTED_RESULT = 8000;  // Unexpected result
constexpr int INVALID_KEY = 8001;  // Invalid key
constexpr int UNSUPPORTED_ALGORITHM = 8002;  // Unsupported algorithm
}  // namespace OPENSSL

}  // namespace my_errors