/*
+----------------------------------------------------------------------+
| HipHop for PHP                                                       |
+----------------------------------------------------------------------+
| Copyright (c) 2010-2015 Facebook, Inc. (http://www.facebook.com)     |
| Copyright (c) 1997-2010 The PHP Group                                |
+----------------------------------------------------------------------+
| This source file is subject to version 3.01 of the PHP license,      |
| that is bundled with this package in the file LICENSE, and is        |
| available through the world-wide-web at the following url:           |
| http://www.php.net/license/3_01.txt                                  |
| If you did not receive a copy of the PHP license and are unable to   |
| obtain it through the world-wide-web, please send a note to          |
| license@php.net so we can mail you a copy immediately.               |
+----------------------------------------------------------------------+
*/
#ifndef incl_HPHP_EXT_OAUTH_H_
#define incl_HPHP_EXT_OAUTH_H_
#include "hphp/runtime/ext/extension.h"
#include "hphp/hphp-config.h"

#define PHP_OAUTH_VERSION "1.2.3"

#define OAUTH_USER_AGENT "PECL-OAuth/" PHP_OAUTH_VERSION
#define OAUTH_HTTP_PORT 80
#define OAUTH_HTTPS_PORT 443
#define OAUTH_MAX_REDIRS 4L
#define OAUTH_MAX_HEADER_LEN 512L

#define OAUTH_AUTH_TYPE_URI 0x01
#define OAUTH_AUTH_TYPE_FORM 0x02
#define OAUTH_AUTH_TYPE_AUTHORIZATION 0x03
#define OAUTH_AUTH_TYPE_NONE 0x04

#define OAUTH_SIG_METHOD_HMACSHA1 "HMAC-SHA1"
#define OAUTH_SIG_METHOD_HMACSHA256 "HMAC-SHA256"
#define OAUTH_SIG_METHOD_RSASHA1 "RSA-SHA1"
#define OAUTH_SIG_METHOD_PLAINTEXT "PLAINTEXT"

#define OAUTH_HTTP_METHOD_GET "GET"
#define OAUTH_HTTP_METHOD_POST "POST"
#define OAUTH_HTTP_METHOD_PUT "PUT"
#define OAUTH_HTTP_METHOD_HEAD "HEAD"
#define OAUTH_HTTP_METHOD_DELETE "DELETE"

#define OAUTH_REQENGINE_STREAMS 1
#define OAUTH_REQENGINE_CURL 2

#define OAUTH_SSLCHECK_NONE 0
#define OAUTH_SSLCHECK_HOST 1
#define OAUTH_SSLCHECK_PEER 2
#define OAUTH_SSLCHECK_BOTH (OAUTH_SSLCHECK_HOST | OAUTH_SSLCHECK_PEER)

/* errors */
#define OAUTH_ERR_CONTENT_TYPE "invalidcontentttype"
#define OAUTH_ERR_BAD_REQUEST 400
#define OAUTH_ERR_BAD_AUTH 401
#define OAUTH_ERR_INTERNAL_ERROR 503

/* values */
#define OAUTH_CALLBACK_OOB "oob"

#define OAUTH_PARAM_PREFIX "oauth_"
#define OAUTH_PARAM_PREFIX_LEN 6

#define OAUTH_OK 0
#define OAUTH_BAD_NONCE (1<<2)
#define OAUTH_BAD_TIMESTAMP (1<<3)
#define OAUTH_CONSUMER_KEY_UNKNOWN (1<<4)
#define OAUTH_CONSUMER_KEY_REFUSED (1<<5)
#define OAUTH_INVALID_SIGNATURE (1<<6)
#define OAUTH_TOKEN_USED (1<<7)
#define OAUTH_TOKEN_EXPIRED (1<<8)
#define OAUTH_TOKEN_REVOKED (1<<9)
#define OAUTH_TOKEN_REJECTED (1<<10)
#define OAUTH_VERIFIER_INVALID (1<<11)
#define OAUTH_PARAMETER_ABSENT (1<<12)
#define OAUTH_SIGNATURE_METHOD_REJECTED (1<<13)

namespace HPHP {

enum class OAuthFetchFlags {
  None = 0x00,
  UseToken = 0x01,
  SigOnly = 0x02,
  HeadOnly = 0x04,
  OverrideHttpMethod = 0x08,
};

inline OAuthFetchFlags operator |(OAuthFetchFlags lhs, OAuthFetchFlags rhs) {
  using T = std::underlying_type<OAuthFetchFlags>::type;
  return (OAuthFetchFlags)(static_cast<T>(lhs) | static_cast<T>(rhs));
}

inline OAuthFetchFlags operator &(OAuthFetchFlags lhs, OAuthFetchFlags rhs) {
  using T = std::underlying_type<OAuthFetchFlags>::type;
  return (OAuthFetchFlags)(static_cast<T>(lhs) & static_cast<T>(rhs));
}

struct OAuthSignatureContext {
  enum class Type {
    None,
    HMAC,
    RSA,
    Plaintext,
  };

  Type type{ Type::None };
  const char* hash_algorithm{ nullptr };
  Variant private_key{ null_variant };

  OAuthSignatureContext(const String& sigMethod);

  String sign(const String& msg, const Variant& consSec, const Variant& tokSec);
};

struct OAuth {
  String lastresponse{ null_string };
  String headers_in{ null_string };
  String headers_out{ null_string };
  String last_location_header{ null_string };
  uint32_t redirects{ 0 };
  // whether we check for SSL verification or not
  int32_t sslcheck{ OAUTH_SSLCHECK_BOTH };
  // verbose output
  bool debug{ false };
  // follow sign redirects?
  bool follow_redirects{ true };
  // streams or curl
  uint32_t reqengine{
#ifdef ENABLE_EXTENSION_CURL
    OAUTH_REQENGINE_CURL
#else
    OAUTH_REQENGINE_STREAMS
#endif
  };
  // timeout in milliseconds
  int64_t timeout{ 0 };
  String nonce{  null_string };
  String timestamp{ null_string };
  String signature{ null_string };
  Array debugArr{ null_array };
  OAuthSignatureContext* sig_ctx{ nullptr };
  req::vector<String> multipart_files{ };
  req::vector<String> multipart_params{ };
  bool is_multipart{ false };

  // Originally a separately allocated struct,
  // but this is easier.
  struct {
    String sbs{ null_string };
    String headers_in{ null_string };
    String headers_out{ null_string };
    String body_in{ null_string };
    String body_out{ null_string };
    String curl_info{ null_string };

    void sweep() {
      sbs = headers_in = headers_out =
      body_in = body_out = curl_info = null_string;
    }
  } debug_info;

  ~OAuth() {
    sweep();
  }
  void sweep();


  int fetch(const String& url,
            const String& httpMethod,
            const Variant& requestParams,
            const Array& requestHeaders,
            const Array& initialOAuthArgs,
            OAuthFetchFlags flags);
#ifdef ENABLE_EXTENSION_CURL
  int makeRequestCurl(const String& url,
                      const String& payload,
                      const String& httpMethod,
                      const Array& requestHeaders);
#endif
  int makeRequestStreams(const String& url,
                         const String& payload,
                         const String& httpMethod,
                         const Array& requestHeaders);
  void makeStandardQuery(Array& args);
  void setDebugInfo();
  void setResponseArgs(Array* dest);


  static void addSignatureHeader(Array& requestHeaders,
                                 const Array& oauthArgs,
                                 String* headersOut = nullptr);
  static void applyUrlRedirect(String& surl, const String& location);
  static String generateSigBase(OAuth* oa,
                                const String& httpMethod,
                                const String& uri,
                                const Array& postParams,
                                const Variant& extraArgs);
  ATTRIBUTE_NORETURN
  static void handleError(const OAuth* oa,
                          const char* msg,
                          const char* request = nullptr,
                          char* additionalInfo = nullptr,
                          int err = OAUTH_ERR_INTERNAL_ERROR);
  static int httpBuildQuery(OAuth* oa,
                            String& str,
                            const Array& args,
                            bool prependAmp);
  static bool isRedirectCode(int code) {
    return code > 300 && code < 304;
  }
  static void parseQueryString(String& params, Array& dest);
  static void prepareUrlConcat(String& url);
  static String urlEncode(const String& url);
};

enum class OAuthProviderCallback {
  Consumer,
  Token,
  TSNonce
};

struct OAuthProvider {
  Array missing_params{ empty_array() };
  Array oauth_params{ empty_array() };
  Array required_params{ empty_array() };
  Array custom_params{ empty_array() };
  String requestEndpointPath{ null_string };
  Variant zrequired_params{ null_variant };

  Variant consumer_handler{ null_variant };
  Variant token_handler{ null_variant };
  Variant tsnonce_handler{ null_variant };
  unsigned int params_via_method{ 0 };
  // Will ext/oauth set the proper header and error message?
  bool handle_errors{ true };

  Variant callCallback(OAuthProviderCallback cbType);
  bool parseAuthHeader(const String& authHeader);
  void setStdParam(Array& arr,
                   const StaticString& authParam,
                   const StaticString& providerParam);
};

class OAuthExtension final : public Extension {
public:
  static Class* OAuthExceptionClass;

  OAuthExtension() : Extension("oauth", PHP_OAUTH_VERSION) {}
  void moduleInit() override;
};

}
#endif
