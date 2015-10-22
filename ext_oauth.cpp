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
#include "hphp/runtime/ext/oauth/ext_oauth.h"

#include "hphp/hphp-config.h"
#include "hphp/runtime/base/array-init.h"
#include "hphp/runtime/base/builtin-functions.h"
#include "hphp/runtime/base/execution-context.h"
#include "hphp/runtime/base/file.h"
#include "hphp/runtime/base/php-globals.h"
#include "hphp/runtime/base/stream-wrapper.h"
#include "hphp/runtime/base/stream-wrapper-registry.h"
#include "hphp/runtime/base/string-util.h"
#include "hphp/runtime/base/url-file.h"
#include "hphp/runtime/base/zend-url.h"
#include "hphp/runtime/ext/apache/ext_apache.h"
#include "hphp/runtime/ext/hash/ext_hash.h"
#include "hphp/runtime/ext/openssl/ext_openssl.h"
#include "hphp/runtime/ext/std/ext_std_math.h"
#include "hphp/runtime/ext/stream/ext_stream.h"
#include "hphp/runtime/ext/string/ext_string.h"
#include "hphp/runtime/server/http-protocol.h"
#include "hphp/runtime/vm/native-data.h"
#include "hphp/runtime/vm/native-prop-handler.h"
#include "hphp/runtime/vm/vm-regs.h"
#include "hphp/system/constants.h"

#include <folly/Random.h>

#ifdef ENABLE_EXTENSION_CURL
#include <curl/curl.h>
#endif

namespace HPHP {

static const StaticString
  s__ENV("_ENV"),
  s__GET("_GET"),
  s__SERVER("_SERVER"),
  s__POST("_POST"),
  s_additionalInfo("additionalInfo"),
  s_Authorization("Authorization"),
  s_body_recv("body_recv"),
  s_body_sent("body_sent"),
  s_ca_info("ca_info"),
  s_ca_path("ca_path"),
  s_code("code"),
  s_Content_Length__("Content-Length: "),
  s_Content_Type__("Content-Type: "),
  s_header("header"),
  s_headers_recv("headers_recv"),
  s_headers_sent("headers_sent"),
  s_http("http"),
  s_https("https"),
  s_HTTP_("HTTP/"),
  s_HTTP_AUTHORIZATION("HTTP_AUTHORIZATION"),
  s_HTTP_METHOD("HTTP_METHOD"),
  s_ignore_errors("ignore_errors"),
  s_info("info"),
  s_Location__("Location: "),
  s_max_redirects("max_redirects"),
  s_method("method"),
  s_OAuth("OAuth"),
  s_OAuthProvider("OAuthProvider"),
  s_oob("oob"),
  s_rb("rb"),
  s_REQUEST_METHOD("REQUEST_METHOD"),
  s_sbs("sbs")
;

namespace OAuthAttr {
  static const StaticString
    AccessToken("oauth_access_token"),
    AuthMethod("oauth_auth_method"),
    CAPath("oauth_ssl_ca_path"),
    CAInfo("oauth_ssl_ca_info"),
    ConsumerKey("oauth_consumer_key"),
    ConsumerSecret("oauth_consumer_secret"),
    LastResInfo("oauth_last_response_info"),
    OAuthNonce("oauth_nonce"),
    OAuthUserNonce("oauth_user_nonce"),
    OAuthVersion("oauth_version"),
    RawLastRes("oauth_last_response_raw"),
    SigMethod("oauth_sig_method"),
    Token("oauth_token"),
    TokenSecret("oauth_token_secret")
  ;
}

namespace OAuthHTTPMethod {
  static const StaticString
    Get("GET"),
    Post("POST"),
    Put("PUT"),
    Head("HEAD"),
    Delete("DELETE")
  ;

  static String getMethod(const Object& obj, const String& meth) {
    if (meth.length()) {
      return meth;
    }

    auto authType = Native::getProp(obj, OAuthAttr::AuthMethod).asInt64Val();
    if (authType == OAUTH_AUTH_TYPE_FORM) {
      return OAuthHTTPMethod::Post;
    } else {
      return OAuthHTTPMethod::Get;
    }
  }
}

namespace OAuthInfo {
  static const StaticString
    connect_time("connect_time"),
    content_type("content_type"),
    download_content_length("download_content_length"),
    filetime("filetime"),
    headers_recv("headers_recv"),
    header_size("header_size"),
    http_code("http_code"),
    namelookup_time("namelookup_time"),
    pretransfer_time("pretransfer_time"),
    redirect_count("redirect_count"),
    redirect_time("redirect_time"),
    redirect_url("redirect_url"),
    request_size("request_size"),
    size_download("size_download"),
    size_upload("size_upload"),
    speed_download("speed_download"),
    speed_upload("speed_upload"),
    ssl_verify_result("ssl_verify_result"),
    starttransfer_time("starttransfer_time"),
    total_time("total_time"),
    upload_content_length("upload_content_length"),
    url("url")
  ;
}

namespace OAuthParam {
  static const StaticString
    Ash("oauth_session_handle"),
    Callback("oauth_callback"),
    ConsumerKey("oauth_consumer_key"),
    Nonce("oauth_nonce"),
    Signature("oauth_signature"),
    SignatureMethod("oauth_signature_method"),
    Timestamp("oauth_timestamp"),
    Token("oauth_token"),
    Verifier("oauth_verifier"),
    Version("oauth_version")
  ;
}

namespace OAuthProblem {
  static const StaticString
    _400_BadRequest("HTTP/1.1 400 Bad Request"),
    _401_Unauthorized("HTTP/1.1 401 Unauthorized"),
    BadTimestamp("oauth_problem=timestamp_refused"),
    BadNonce("oauth_problem=nonce_used"),
    ConsumerKeyUnknown("oauth_problem=consumer_key_unknown"),
    ConsumerKeyRefused("oauth_problem=consumer_key_refused"),
    SignatureMethodRejected("oauth_problem=signature_method_rejected"),
    TokenUsed("oauth_problem=token_used"),
    TokenExpired("oauth_problem=token_expired"),
    TokenRevoked("oauth_problem=token_revoked"),
    TokenRejected("oauth_problem=token_rejected"),
    VerifierInvalid("oauth_problem=verifier_invalid")
  ;
}

namespace OAuthProviderAttr {
  static const StaticString
    Callback("callback"),
    ConsumerKey("consumer_key"),
    ConsumerSecret("consumer_secret"),
    Nonce("nonce"),
    RequestTokenEndpoint("request_token_endpoint"),
    Signature("signature"),
    SignatureMethod("signature_method"),
    Timestamp("timestamp"),
    Token("token"),
    TokenSecret("token_secret"),
    Verifier("verifier"),
    Version("version")
  ;
}

namespace OAuthSignatureMethod {
  static const StaticString
    HMACSHA1(OAUTH_SIG_METHOD_HMACSHA1),
    HMACSHA256(OAUTH_SIG_METHOD_HMACSHA256),
    RSASHA1(OAUTH_SIG_METHOD_RSASHA1),
    Plaintext(OAUTH_SIG_METHOD_PLAINTEXT)
  ;
}

static Object createAndConstruct(Class* cls, const Variant& args) {
  Object inst{ cls };
  TypedValue ret;
  g_context->invokeFunc(&ret, cls->getCtor(), args, inst.get());
  tvRefcountedDecRef(&ret);
  return inst;
}

void to_do_implement_me() {
  throw Exception("");
}

///////////////////////////////////////////////////////////////////////////////
// Global Functions
///////////////////////////////////////////////////////////////////////////////

Variant HHVM_FUNCTION(oauth_urlencode, const String& uri) {
  if (!uri.size()) {
    raise_warning("Invalid uri length (0)");
    return false;
  }

  return OAuth::urlEncode(uri);
}

Variant HHVM_FUNCTION(oauth_get_sbs,
                      const String& method,
                      const String& uri,
                      const Array& params) {
  if (!uri.length()) {
    raise_warning("Invalid uri length (0)");
    return false;
  }

  if (!method.length()) {
    raise_warning("Invalid http method length (0)");
    return false;
  }

  auto sbs = OAuth::generateSigBase(nullptr, method, uri, null_array, params);
  if (sbs.isNull()) {
    return false;
  }
  return sbs;
}

///////////////////////////////////////////////////////////////////////////////
// OAuthSignatureContext
///////////////////////////////////////////////////////////////////////////////

OAuthSignatureContext::OAuthSignatureContext(const String& sigMethod) {
  if (sigMethod == OAuthSignatureMethod::HMACSHA1) {
    this->type = Type::HMAC;
    this->hash_algorithm = "sha1";
  } else if (sigMethod == OAuthSignatureMethod::HMACSHA256) {
    this->type = Type::HMAC;
    this->hash_algorithm = "sha256";
  } else if (sigMethod == OAuthSignatureMethod::RSASHA1) {
    this->type = Type::RSA;
    this->hash_algorithm = "sha1";
  } else if (sigMethod == OAuthSignatureMethod::Plaintext) {
    this->type = Type::Plaintext;
  }
}

String OAuthSignatureContext::sign(const String& msg,
                                   const Variant& consSecret,
                                   const Variant& tokenSecret) {
  auto cs = consSecret.isNull() ? empty_string() : consSecret.asCStrRef();
  auto ts = tokenSecret.isNull() ? empty_string() : tokenSecret.asCStrRef();
  switch (this->type) {
    case Type::HMAC: {
      // Unfortunately, hash_hmac is implemented in the systemlib, so we can't
      // just call it directly :(
      auto key = cs + "&" + ts;
      auto ctx = HHVM_FN(hash_init)(this->hash_algorithm, k_HASH_HMAC, key);
      HHVM_FN(hash_update)(ctx.asResRef(), msg);
      return StringUtil::Base64Encode(
        HHVM_FN(hash_final)(ctx.asResRef(), true).asStrRef()
      );
    }
    case Type::RSA: {
      String ret;
      if (!HHVM_FN(openssl_sign)(msg, ret, this->private_key)) {
        return null_string;
      }
      return StringUtil::Base64Encode(ret);
    }
    case Type::Plaintext:
      return cs + "&" + ts;
    default:
      return null_string;
  }
}

///////////////////////////////////////////////////////////////////////////////
// OAuth - Instance Functions
///////////////////////////////////////////////////////////////////////////////

void OAuth::sweep() {
  // Note that the only reason we are setting these to null_* values is
  // because OAuth has a __destroy method that allows for early destruction
  // of the data, so we're matching the behaviour of the original PECL
  // extension in what data gets freed.
  debug_info.sweep();
  headers_in = null_string;
  headers_out = null_string;
  nonce = null_string;
  timestamp = null_string;
  signature = null_string;
  debugArr = null_array;
  if (sig_ctx) {
    req::destroy_raw(sig_ctx);
    sig_ctx = nullptr;
  }
}

int OAuth::fetch(const String& url,
                 const String& httpMethod,
                 const Variant& requestParams,
                 const Array& requestHeaders,
                 const Array& initialOAuthArgs,
                 OAuthFetchFlags flags) {
  auto thisObj = Object(Native::object(this));
  int64_t authType = Native::getProp(thisObj, OAuthAttr::AuthMethod).toInt64();

  String finalHttpMethod;
  if ((flags & OAuthFetchFlags::OverrideHttpMethod) != OAuthFetchFlags::None) {
    finalHttpMethod = httpMethod;
  } else {
    finalHttpMethod = OAuthHTTPMethod::getMethod(thisObj,
                    httpMethod.isNull() ? OAuthHTTPMethod::Post : httpMethod);

    if (authType == OAUTH_AUTH_TYPE_FORM
        && finalHttpMethod != OAuthHTTPMethod::Post) {
      OAuth::handleError(this, "auth type is set to HTTP POST with a non-POST"
        " http method, use setAuthType to put OAuth parameters somewhere else"
        " in the request");
    }
  }

  if (finalHttpMethod.isNull()) {
    finalHttpMethod = OAuthHTTPMethod::Get;
  }

  bool isRedirect = false;
  this->redirects = 0;
  this->multipart_files.clear();
  this->multipart_params.clear();
  this->is_multipart = false;

  String postData = "";
  if (!requestParams.isNull()) {
    if (requestParams.isString()) {
      postData += requestParams.asCStrRef();
    } else if (requestParams.isArray()) {
      this->httpBuildQuery(this, postData, requestParams.asCArrRef(), false);
    }
  }

  Array rHeaders = requestHeaders;
  if (requestHeaders.isNull()) {
    rHeaders = Array::Create();
  }

  String surl = url;
  int httpResponseCode = -1;
  do {
    httpResponseCode = -1;

    Array oauthArgs = Array::Create();
    oauthArgs.merge(initialOAuthArgs);
    this->makeStandardQuery(oauthArgs);

    Variant token = null_variant;
    if ((flags & OAuthFetchFlags::UseToken) != OAuthFetchFlags::None) {
      token = Native::getProp(thisObj, OAuthAttr::Token);
      if (!token.isNull()) {
        oauthArgs.set(OAuthParam::Token, token);
      }
    }

    auto sigBaseStr = OAuth::generateSigBase(this, finalHttpMethod, surl,
                                       oauthArgs, requestParams);
    if (sigBaseStr.isNull()) {
      OAuth::handleError(this, "Invalid protected resource url, unable"
                               " to generate signature base string");
    }

    auto consumerSecret = Native::getProp(thisObj, OAuthAttr::ConsumerSecret);
    Variant tokenSecret = null_variant;
    if ((flags & OAuthFetchFlags::UseToken) != OAuthFetchFlags::None) {
      tokenSecret = Native::getProp(thisObj, OAuthAttr::TokenSecret);
      if (!tokenSecret.isNull() && tokenSecret.asCStrRef().length() == 0) {
        tokenSecret = null_variant;
      }
    }

    auto sig = this->sig_ctx->sign(sigBaseStr, consumerSecret, tokenSecret);
    this->signature = sig;

    if ((flags & OAuthFetchFlags::SigOnly) != OAuthFetchFlags::None) {
      return 0;
    }

    if (sig.isNull()) {
      OAuth::handleError(this, "Signature generation failed");
    }

    oauthArgs.set(OAuthParam::Signature, sig);

    if ((flags & OAuthFetchFlags::HeadOnly) != OAuthFetchFlags::None) {
      OAuth::addSignatureHeader(rHeaders, oauthArgs, &this->headers_out);
      return 0;
    }

    String payload = "";
    if (finalHttpMethod == OAuthHTTPMethod::Get) {
      if (!isRedirect && postData.length()) {
        OAuth::prepareUrlConcat(surl);
        surl += postData;
      }
    } else {
      payload += postData;
    }

    switch (authType) {
      case OAUTH_AUTH_TYPE_FORM:
        this->httpBuildQuery(this, payload, oauthArgs, payload.length() > 0);
        break;
      case OAUTH_AUTH_TYPE_URI:
        if (!isRedirect) {
          OAuth::prepareUrlConcat(surl);
          this->httpBuildQuery(this, surl, oauthArgs, false);
        }
        break;
      case OAUTH_AUTH_TYPE_AUTHORIZATION:
        OAuth::addSignatureHeader(rHeaders, oauthArgs);
        break;
      default:
        break;
    }

    if (this->debug) {
      this->debug_info.sweep();
    }

    switch (this->reqengine) {
      case OAUTH_REQENGINE_STREAMS:
        httpResponseCode = this->makeRequestStreams(surl, payload,
                                                    finalHttpMethod, rHeaders);
        break;
#ifdef ENABLE_EXTENSION_CURL
      case OAUTH_REQENGINE_CURL:
        httpResponseCode = this->makeRequestCurl(surl, payload,
                                                 finalHttpMethod, rHeaders);
        if (this->multipart_files.size()) {
          this->multipart_files.clear();
          this->multipart_params.clear();
          this->is_multipart = false;
        }
        break;
#endif
      default:
        break;
    }

    isRedirect = OAuth::isRedirectCode(httpResponseCode);
    this->setDebugInfo();

    if (isRedirect) {
      if (follow_redirects) {
        if (this->redirects >= OAUTH_MAX_REDIRS) {
          this->setResponseArgs(nullptr);
          OAuth::handleError(this,
            folly::format("max redirections exceeded (max: {} last redirect"
                          " url: {})", OAUTH_MAX_REDIRS,
                          this->last_location_header).str().c_str(),
            this->lastresponse.c_str(),
            nullptr,
            httpResponseCode
          );
        } else {
          this->redirects++;
          OAuth::applyUrlRedirect(surl, this->last_location_header);
        }
      }
    } else if (httpResponseCode < 200 || httpResponseCode > 206) {
      this->setResponseArgs(nullptr);
      OAuth::handleError(this, 
        folly::format("Invalid auth/bad request (got a {}, expected HTTP/1.1"
                      " 20X or a redirect)", httpResponseCode).str().c_str(),
        this->lastresponse.c_str(),
        nullptr,
        httpResponseCode);
    }
  } while (isRedirect && follow_redirects);
  
  return httpResponseCode;
}

#ifdef ENABLE_EXTENSION_CURL
static size_t oauth_read_curl_response(char* ptr,
                                       size_t size,
                                       size_t nb,
                                       void* ctx) {
  ((OAuth*)ctx)->lastresponse += String(ptr, size * nb, CopyString);
  return size * nb;
}

static int oauth_debug_handler(CURL* ch,
                               curl_infotype type,
                               char* data,
                               size_t data_len,
                               void* ctx) {
  if (data_len > 1 && data[0] == '\r' && data[1] == '\n') {
    return 0;
  }

  OAuth* oa = (OAuth*)ctx;
  String* dest;
  switch (type) {
    case CURLINFO_TEXT:
      dest = &oa->debug_info.curl_info;
      break;
    case CURLINFO_HEADER_OUT:
      dest = &oa->debug_info.headers_out;
      break;
    case CURLINFO_DATA_IN:
      dest = &oa->debug_info.body_in;
      break;
    case CURLINFO_DATA_OUT:
      dest = &oa->debug_info.body_out;
      break;
    default:
      dest = nullptr;
      break;
  }
  *dest += String(data, data_len, CopyString);
  return 0;
}

static size_t oauth_read_curl_header(char* ptr,
                                     size_t size,
                                     size_t nb,
                                     void* ctx) {
  auto oa = (OAuth*)ctx;
  auto hdr = String(ptr, size * nb, CopyString);
  if (hdr.length() > 9 && !HHVM_FN(strcasecmp(hdr.substr(0, 9), "Location:"))) {
    size_t vpos = 9;
    size_t hlen = hdr.length();
    size_t eol = hlen;
    while (vpos != eol && hdr[vpos] == ' ') {
      vpos++;
    }

    while (vpos != eol && strchr("\r\n\0", hdr[eol - 1])) {
      eol--;
    }

    if (vpos != eol) {
      oa->last_location_header = hdr.substr(vpos, eol - vpos);
    }
  }
  if (HHVM_FN(strcasecmp)(hdr.substr(0, 2), "\r\n")) {
    oa->headers_in += hdr;
  }
  return hdr.length();
}

int OAuth::makeRequestCurl(const String& url,
                           const String& payload,
                           const String& httpMethod,
                           const Array& requestHeaders) {
  auto thisObj = Object(Native::object(this));
  curl_slist* curlHeaders = nullptr;
  CURL* curl = curl_easy_init();
  SCOPE_EXIT {
    if (curlHeaders != nullptr) {
      curl_slist_free_all(curlHeaders);
    }
    curl_easy_cleanup(curl);
  };

  if (!requestHeaders.empty()) {
    for (ArrayIter iter(requestHeaders); iter; ++iter) {
      String shead = "";
      if (!iter.first().isString()) {
        continue;
      }
      shead += iter.first().asStrRef();
      shead += ": ";
      if (!iter.second().isString()) {
        continue;
      }
      shead += iter.secondRef().asCStrRef();
      curlHeaders = curl_slist_append(curlHeaders, shead.c_str());
    }
  }

  if(this->is_multipart) {
    curl_httppost* ff = nullptr;
    curl_httppost* lf = nullptr;

    for (int i = 0; i < this->multipart_files.size(); i++) {
      auto& postVal = this->multipart_files[i];
      if (postVal[0] == '@' && this->multipart_params[i][0] == '@') {
        char* mutablePostval = const_cast<char*>(postVal.c_str()) + 1;
        char* type = strstr(mutablePostval, ";type=");
        char* filename = strstr(mutablePostval, ";filename=");

        if (type) {
          *type = '\0';
        }
        if (filename) {
          *filename = '\0';
        }

        String localName = File::TranslatePath(mutablePostval);

        curl_formadd(&ff, &lf,
          CURLFORM_COPYNAME, this->multipart_params[i],
          CURLFORM_NAMELENGTH, (long)this->multipart_params[i].length(),
          CURLFORM_FILENAME, filename ?
                     filename + sizeof(";filename=") - 1 : (mutablePostval - 1),
          CURLFORM_CONTENTTYPE, type ?
                     type + sizeof(";type=") - 1 : "application/octet-stream",
          CURLFORM_FILE, localName.c_str(),
          CURLFORM_END);

        if (type) {
          *type = ';';
        }
        if (filename) {
          *filename = ';';
        }
      } else {
        curl_formadd(&ff, &lf,
          CURLFORM_COPYNAME, this->multipart_params[i].c_str(),
          CURLFORM_NAMELENGTH, (long)this->multipart_params[i].length(),
          CURLFORM_COPYCONTENTS, postVal.c_str(),
          CURLFORM_CONTENTSLENGTH, (long)postVal.length(),
          CURLFORM_END);
      }
    }

    curl_easy_setopt(curl, CURLOPT_HTTPPOST, ff);
  } else if (payload.length()) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.length());
  }

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, httpMethod.c_str());
  curlHeaders = curl_slist_append(curlHeaders, "Expect:");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curlHeaders);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, OAUTH_USER_AGENT);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oauth_read_curl_response);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
  if (this->sslcheck == OAUTH_SSLCHECK_NONE) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  } else {
    if (!(this->sslcheck & OAUTH_SSLCHECK_HOST)) {
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if (!(this->sslcheck & OAUTH_SSLCHECK_PEER)) {
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    }

    auto caInfo = Native::getProp(thisObj, OAuthAttr::CAInfo);
    auto caPath = Native::getProp(thisObj, OAuthAttr::CAPath);
    if (!caPath.isNull() && caPath.asCStrRef().length()) {
      curl_easy_setopt(curl, CURLOPT_CAPATH, caPath.asCStrRef().c_str());
    }
    if (!caInfo.isNull() && caInfo.asCStrRef().length()) {
      curl_easy_setopt(curl, CURLOPT_CAINFO, caInfo.asCStrRef().c_str());
    }
  }
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, oauth_read_curl_header);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, this);
  if (this->debug) {
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
  }
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
#if LIBCURL_VERSION_NUM >= 0x071304
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
#if LIBCURL_VERSION_NUM > 0x071002
  if (this->timeout) {
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, this->timeout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, this->timeout);
  }
#endif

  this->lastresponse = null_string;
  this->headers_in = null_string;

  if (this->debug) {
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, oauth_debug_handler);
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, this);
  }

  auto cres = curl_easy_perform(curl);
  if (cres != CURLE_OK) {
    OAuth::handleError(this, folly::format("making the request failed ({})",
      curl_easy_strerror(cres)).str().c_str(), this->lastresponse.c_str());
  }

  char* contentType = nullptr;
  int responseCode = -1;
  auto ctres = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &contentType);
  auto crres = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
  if (ctres == CURLE_OK && crres == CURLE_OK) {
    Array info = Array::Create();

    info.set(OAuthInfo::http_code, responseCode);
    if (OAuth::isRedirectCode(responseCode) &&
        !this->last_location_header.isNull()) {
      info.set(OAuthInfo::redirect_url, this->last_location_header);
    }
    if (contentType != nullptr) {
      info.set(OAuthInfo::content_type, contentType);
    }

    char* s_code = nullptr;
    long l_code;
    double d_code;

#define SET_INFO(sdl, name, opt) \
  if (curl_easy_getinfo(curl, CURLINFO_##opt, &sdl##_code) == CURLE_OK) { \
    info.set(OAuthInfo::name, sdl##_code); \
  }
    SET_INFO(s, url, EFFECTIVE_URL);
    SET_INFO(l, header_size, HEADER_SIZE);
    SET_INFO(l, request_size, REQUEST_SIZE);
    SET_INFO(l, filetime, FILETIME);
    SET_INFO(l, ssl_verify_result, SSL_VERIFYRESULT);
    SET_INFO(l, redirect_count, REDIRECT_COUNT);
    SET_INFO(d, total_time, TOTAL_TIME);
    SET_INFO(d, namelookup_time, NAMELOOKUP_TIME);
    SET_INFO(d, connect_time, CONNECT_TIME);
    SET_INFO(d, pretransfer_time, PRETRANSFER_TIME);
    SET_INFO(d, size_upload, SIZE_UPLOAD);
    SET_INFO(d, size_download, SIZE_DOWNLOAD);
    SET_INFO(d, speed_download, SPEED_DOWNLOAD);
    SET_INFO(d, speed_upload, SPEED_UPLOAD);
    SET_INFO(d, download_content_length, CONTENT_LENGTH_DOWNLOAD);
    SET_INFO(d, upload_content_length, CONTENT_LENGTH_UPLOAD);
    SET_INFO(d, starttransfer_time, STARTTRANSFER_TIME);
    SET_INFO(d, redirect_time, REDIRECT_TIME);
#undef SET_INFO

    info.set(OAuthInfo::headers_recv, this->headers_in);
    Native::setProp(thisObj, OAuthAttr::LastResInfo, info);
  }

  return responseCode;
}
#endif


int OAuth::makeRequestStreams(const String& url,
                              const String& payload,
                              const String& httpMethod,
                              const Array& requestHeaders) {
  auto ctx = HHVM_FN(stream_context_create)();

  bool setFormContentType = false;
  if (payload.length()) {
    HHVM_FN(stream_context_set_option)(ctx, s_http, "content", payload);
    setFormContentType = true;
  }

  if (!requestHeaders.empty()) {
    String headers = "";

    bool first = true;
    for (ArrayIter iter(requestHeaders); iter; ++iter) {
      String hLine = "";
      if (!iter.first().isString()) {
        continue;
      }
      hLine += iter.first().asStrRef();
      if (!HHVM_FN(strcasecmp(iter.first().asCStrRef(), "content-type"))) {
        setFormContentType = false;
      }
      hLine += ": ";
      if (!iter.second().isString()) {
        continue;
      }
      hLine += iter.secondRef().asCStrRef();
      if (!first) {
        headers += "\r\n";
      }
      first = false;
      headers += hLine;
    }

    if (setFormContentType) {
      if (!first) {
        headers += "\r\n";
      }
      headers += "Content-Type: application/x-www-form-urlencoded";
    }

    if (headers.length()) {
      HHVM_FN(stream_context_set_option(ctx, s_http, s_header, headers));
      if (this->debug) {
        this->debug_info.headers_out += headers;
      }
    }
  }

  HHVM_FN(stream_context_set_option)(ctx, s_http, s_method, httpMethod);
  HHVM_FN(stream_context_set_option)(ctx, s_http, s_max_redirects, 1);
  HHVM_FN(stream_context_set_option)(ctx, s_http, s_ignore_errors, true);

  Array info = Array::Create();
  info.set(OAuthInfo::url, url);

  this->lastresponse = null_string;
  this->headers_in = null_string;

  HPHP::Stream::Wrapper* w = HPHP::Stream::getWrapperFromURI(url);
  auto file = w->open(url, s_rb,
                      k_STREAM_REPORT_ERRORS | k_STREAM_ENFORCE_SAFE_MODE,
                      cast<StreamContext>(ctx.asCResRef()));
  SCOPE_EXIT {
    file->close();
  };

  auto urlFile = dynamic_cast<HPHP::UrlFile*>(file.get());
  if (!urlFile) {
    OAuth::handleError(this, "making the request failed (dunno why)");
  }

  int responseCode = -1;
  auto wrapperData = urlFile->getWrapperMetaData().asArrRef();
  if (!wrapperData.empty()) {
    for (ArrayIter iter(wrapperData); iter; ++iter) {
      auto v = iter.secondRef().asCStrRef();
      this->headers_in += v;
      this->headers_in += "\r\n";

      if (responseCode < 0 &&
          !HHVM_FN(strcasecmp)(v.substr(0, 5), s_HTTP_) && v.length() >= 12) {
        responseCode = v.substr(9).toInt64();
        info.set(OAuthInfo::http_code, responseCode);
      } else if (!HHVM_FN(strcasecmp)(v.substr(0, 10), s_Location__)) {
        this->last_location_header = v.substr(10);
      } else if (!HHVM_FN(strcasecmp)(v.substr(0, 14), s_Content_Type__)) {
        info.set(OAuthInfo::content_type, v.substr(14));
      } else if (!HHVM_FN(strcasecmp)(v.substr(0, 16), s_Content_Length__)) {
        info.set(OAuthInfo::download_content_length, v.substr(16).toInt16());
      }
    }

    if (OAuth::isRedirectCode(responseCode) &&
        this->last_location_header.length()) {
      info.set(OAuthInfo::redirect_url, this->last_location_header);
    }
  }
  
  if (this->timeout) {
    urlFile->setTimeout(this->timeout);
  }

  HPHP::StringBuffer sb;
  sb.read(file.get());
  auto thisResponse = sb.detach();
  lastresponse += thisResponse;

  info.set(OAuthInfo::size_download, thisResponse.length());
  info.set(OAuthInfo::size_upload, payload.length());
  Native::setProp(Object(Native::object(this)), OAuthAttr::LastResInfo, info);

  if (this->debug) {
    this->debug_info.body_in += this->lastresponse;
    this->debug_info.body_out += payload;
  }
  return responseCode;
}

void OAuth::makeStandardQuery(Array& args) {
  auto thisObj = Object(Native::object(this));
  
  args.set(OAuthParam::ConsumerKey,
           Native::getProp(thisObj, OAuthAttr::ConsumerKey));
  args.set(OAuthParam::SignatureMethod,
           Native::getProp(thisObj, OAuthAttr::SigMethod));

  if (!nonce.isNull()) {
    args.set(OAuthParam::Nonce, nonce);
  } else {
    timeval tv;
    gettimeofday(&tv, nullptr);
    char* no = nullptr;
    auto noLen = spprintf(&no, 0, "%ld%08x%05x%.8f",
                          HHVM_FN(rand)(),
                          (int)tv.tv_sec,
                          (int)(tv.tv_usec % 0x100000),
                          (float)folly::Random::randDouble01());
    args.set(OAuthParam::Nonce, String(no, noLen, AttachString));
  }

  if (!timestamp.isNull()) {
    args.set(OAuthParam::Timestamp, timestamp);
  } else {
    time_t now = time(nullptr);
    char* ts = nullptr;
    auto tsLen = spprintf(&ts, 0, "%d", (int)now);
    args.set(OAuthParam::Timestamp, String(ts, tsLen, AttachString));
  }

  args.set(OAuthParam::Version,
           Native::getProp(thisObj, OAuthAttr::OAuthVersion));
}

void OAuth::setDebugInfo() {
  if (debug) {
    if (debugArr.isNull()) {
      debugArr = Array::Create();
    }

    if (debug_info.sbs) {
      debugArr.set(s_sbs, String(debug_info.sbs, CopyString));
    }
    
    debugArr.set(s_headers_sent, HHVM_FN(trim)(debug_info.headers_out));
    debugArr.set(s_headers_recv, HHVM_FN(trim)(headers_in));
    debugArr.set(s_body_sent, debug_info.body_out);
    debugArr.set(s_body_recv, debug_info.body_in);
    debugArr.set(s_info, debug_info.curl_info);
  }
}

void OAuth::setResponseArgs(Array* dest) {
  if (!lastresponse) {
    if (dest != nullptr) {
      HPHP::HttpProtocol::DecodeParameters(*dest,
                                           lastresponse.data(),
                                           lastresponse.length());
    }
    Native::setProp(
      Object(Native::object(this)), OAuthAttr::RawLastRes, lastresponse);
  }
}

///////////////////////////////////////////////////////////////////////////////
// OAuth - Static Functions
///////////////////////////////////////////////////////////////////////////////

void OAuth::addSignatureHeader(Array& requestHeaders,
                               const Array& oauthArgs,
                               String* headersOut /* = nullptr */) {
  String ret = "OAuth ";

  bool prependComma = false;
  for (ArrayIter iter(oauthArgs); iter; ++iter) {
    if (prependComma) {
      ret += ",";
    }

    ret += OAuth::urlEncode(iter.first().asCStrRef());
    ret += "=\"";
    ret += OAuth::urlEncode(iter.second().asCStrRef());
    ret += "\"";
    prependComma = true;
  }

  if (!headersOut) {
    requestHeaders.set(s_Authorization, ret);
  } else {
    *headersOut += ret;
  }
}

void OAuth::applyUrlRedirect(String& surl, const String& location) {
  if (location[0] == '/') {
    Url parts;
    url_parse(parts, location.data(), location.size());

    surl = "";
    if (parts.scheme.length()) {
      surl += parts.scheme;
      surl += "://";
    }
    surl += parts.host;
    if (parts.port) {
      surl += ":";
      surl += Variant(parts.port).toString();
    }
    surl += location;
  } else {
    surl = String(location, CopyString);
  }
}

String OAuth::generateSigBase(OAuth* oa,
                              const String& httpMethod,
                              const String& uri,
                              const Array& postParams,
                              const Variant& extraArgs) {
  Url parts;
  if (!url_parse(parts, uri.data(), uri.length())) {
    return null_string;
  }
  if (!parts.host.length() || !parts.scheme.length()) {
    OAuth::handleError(oa, "Invalid url when trying to build base"
                           " signature string");
  }

  String sbuf = "";
  sbuf += parts.scheme;
  sbuf += "://";
  sbuf += parts.host;
  if (parts.port && (
    (parts.port != OAUTH_HTTP_PORT && parts.scheme != s_http) ||
    (parts.port != OAUTH_HTTPS_PORT && parts.scheme != s_https))) {
    sbuf += ":";
    sbuf += Variant(parts.port).toString();
  }

  if (!parts.path.length()) {
    OAuth::handleError(oa, "Invalid path (perhaps you only specified the"
                           " hostname? try adding a slash at the end)");
  }

  Array params = Array::Create();
  if (!postParams.isNull()) {
    params.merge(postParams);
  }

  if (!extraArgs.isNull() && extraArgs.isArray()) {
    params.merge(extraArgs.asCArrRef());
  }

  if (parts.query) {
    OAuth::parseQueryString(parts.query, params);
  }

  if (params.exists(OAuthParam::Signature)) {
    params.remove(OAuthParam::Signature);
  }
  
  String squery;
  params.sort(&Array::SortStringDescending, true, false);
  OAuth::httpBuildQuery(oa, squery, params, false);
  auto ret = httpMethod + "&" + OAuth::urlEncode(squery);
  ret += "&" + OAuth::urlEncode(sbuf);
  if (oa && oa->debug) {
    oa->debug_info.sbs = ret;
  }
  return ret;
}

ATTRIBUTE_NORETURN
void OAuth::handleError(const OAuth* oa,
                        const char* msg,
                        const char* response,
                        char* additionalInfo,
                        int err) {
  if (!err) {
    raise_warning("caller did not pass an errorcode!");
  }

  throw createAndConstruct(OAuthExtension::OAuthExceptionClass,
    make_packed_array(
      msg,
      err,
      response ? String(response, CopyString) : null_string,
      (oa && oa->debug && !oa->debugArr.isNull()) ? oa->debugArr : null_array,
      additionalInfo ? String(additionalInfo, CopyString) : null_string
  ));
}

int OAuth::httpBuildQuery(OAuth* oa,
                          String& str,
                          const Array& args,
                          bool prependAmp) {
  int numArgs = 0;
  if (!args.isNull()) {
    if (oa && !oa->is_multipart) {
      for (ArrayIter iter(args); iter; ++iter) {
        if (iter.first().isString() &&
            iter.first().asCStrRef().length() &&
            iter.first().asCStrRef()[0] == '@' &&
            iter.secondRef().isString() &&
            iter.secondRef().asCStrRef().length() &&
            iter.secondRef().asCStrRef()[0] == '@') {
          oa->is_multipart = true;
          break;
        }
      }
    }

    for (ArrayIter iter(args); iter; ++iter) {
      String argKey = null_string;
      bool skipAppend = false;

      if (iter.first().isString()) {
        if (oa && oa->is_multipart &&
            !iter.first().asCStrRef().slice().startsWith("oauth_")) {
          bool found = false;
          for (auto& a : oa->multipart_params) {
            if (a == iter.first().asCStrRef()) {
              found = true;
              break;
            }
          }
          if (found) {
            continue;
          }

          oa->multipart_files.push_back(iter.secondRef().toString());
          oa->multipart_params.push_back(iter.first().asCStrRef());
          skipAppend = true;
        } else {
          argKey = OAuth::urlEncode(iter.first().asCStrRef());
        }
      } else if (!iter.first().isInteger()) {
        continue;
      }

      if (skipAppend) {
        continue;
      }

      if (argKey.isNull()) {
        argKey = iter.first().toString();
      }

      if (iter.secondRef().isArray()) {
        auto arr = iter.second().asArrRef().copy();
        arr.sort(&Array::SortStringDescending, true, false);

        for (ArrayIter iter2(arr); iter2; ++iter2) {
          if (prependAmp) {
            str += "&";
          }
          str += argKey;
          auto paramVal = OAuth::urlEncode(iter2.secondRef().toString());
          if (!paramVal.isNull()) {
            str += "=";
            str += paramVal;
          }
          prependAmp = true;
          numArgs++;
        }
      } else {
        if (prependAmp) {
          str += "&";
        }
        str += argKey;
        auto paramVal = OAuth::urlEncode(iter.secondRef().toString());
        if (!paramVal.isNull()) {
          str += "=";
          str += paramVal;
        }
        prependAmp = true;
        numArgs++;
      }
    }
  }
  return numArgs;
}

void OAuth::parseQueryString(String& params, Array& dest) {
  char* buf = nullptr;

  auto var = strtok_r((char*)params.data(), "&", &buf);
  while (var != nullptr) {
    auto val = strchr(var, '=');
    if (val != nullptr) {
      *val++ = '\0';
      dest.set(url_decode(var, strlen(var)), String(val, CopyString));
    } else {
      dest.set(url_decode(var, strlen(var)), empty_string_ref);
    }
    var = strtok_r(nullptr, "&", &buf);
  }
}

void OAuth::prepareUrlConcat(String& url) {
  if (!strchr(url.data(), '?')) {
    url += "?";
  } else {
    url += "&";
  }
}

String OAuth::urlEncode(const String& url) {
  auto str = StringUtil::UrlEncode(url);
  return HHVM_FN(str_replace)("%7E", "~", str).toString();
}

///////////////////////////////////////////////////////////////////////////////
// OAuth - PHP Functions
///////////////////////////////////////////////////////////////////////////////

static Variant oauth_debug_read(const Object& this_) {
  return Native::data<OAuth>(this_)->debug;
}
static void oauth_debug_write(const Object& this_, Variant& value) {
  Native::data<OAuth>(this_)->debug = value.toBoolean();
}
static Variant oauth_sslChecks_read(const Object& this_) {
  return Variant(Native::data<OAuth>(this_)->sslcheck);
}
static void oauth_sslChecks_write(const Object& this_, Variant& value) {
  Native::data<OAuth>(this_)->sslcheck = value.toInt32();
}

static Variant oauth_debugInfo_read(const Object& this_) {
  return Native::data<OAuth>(this_)->debugArr;
}

static Native::PropAccessor oauth_properties[] {
  { "debug", oauth_debug_read, oauth_debug_write },
  { "sslChecks", oauth_sslChecks_read, oauth_sslChecks_write },
  { "debugInfo", oauth_debugInfo_read, nullptr },
  { nullptr }
};
static Native::PropAccessorMap oauth_properties_map{ oauth_properties };
struct OAuthPropHandler : public Native::MapPropHandler<OAuthPropHandler> {
  static constexpr Native::PropAccessorMap& map = oauth_properties_map;
};


void HHVM_METHOD(OAuth, __construct,
                 const String& consumerKey,
                 const String& consumerSecret,
                 const String& signatureMethod,
                 int64_t authMethod) {
  auto oa = Native::data<OAuth>(this_);

  if (!consumerKey.length()) {
    OAuth::handleError(oa, "The consumer key cannot be empty");
  }

  auto sigMeth = signatureMethod.length() ? signatureMethod :
    OAuthSignatureMethod::HMACSHA1;
  if (!authMethod) {
    authMethod = OAUTH_AUTH_TYPE_AUTHORIZATION;
  }
  auto consSecret = empty_string();
  if (consumerSecret.length()) {
    consSecret = OAuth::urlEncode(consumerSecret);
  }

  oa->sig_ctx = req::make_raw<OAuthSignatureContext>(sigMeth);
  auto thisObj = Object(this_);
  Native::setProp(thisObj, OAuthAttr::ConsumerKey, consumerKey);
  Native::setProp(thisObj, OAuthAttr::ConsumerSecret, consSecret);
  Native::setProp(thisObj, OAuthAttr::SigMethod, sigMeth);
  Native::setProp(thisObj, OAuthAttr::AuthMethod, authMethod);
  Native::setProp(thisObj, OAuthAttr::OAuthNonce, "1.0");
}

void HHVM_METHOD(OAuth, __destruct) {
  Native::data<OAuth>(this_)->sweep();
}

bool HHVM_METHOD(OAuth, disableDebug) {
  Native::data<OAuth>(this_)->debug = false;
  return true;
}

bool HHVM_METHOD(OAuth, disableRedirects) {
  Native::data<OAuth>(this_)->follow_redirects = false;
  return true;
}

bool HHVM_METHOD(OAuth, disableSSLChecks) {
  Native::data<OAuth>(this_)->sslcheck = OAUTH_SSLCHECK_NONE;
  return true;
}

bool HHVM_METHOD(OAuth, enableDebug) {
  Native::data<OAuth>(this_)->debug = true;
  return true;
}

bool HHVM_METHOD(OAuth, enableRedirects) {
  Native::data<OAuth>(this_)->follow_redirects = true;
  return true;
}

bool HHVM_METHOD(OAuth, enableSSLChecks) {
  Native::data<OAuth>(this_)->sslcheck = OAUTH_SSLCHECK_BOTH;
  return true;
}

bool HHVM_METHOD(OAuth, fetch,
                 const String& protectedResourceURL,
                 const Variant& extraParameters,
                 const String& httpMethod,
                 const Array& requestHeaders) {
  auto oa = Native::data<OAuth>(this_);
  if (!protectedResourceURL.length()) {
    OAuth::handleError(oa, "Invalid protected resource url length");
  }

  auto retcode = oa->fetch(protectedResourceURL, httpMethod, extraParameters,
    requestHeaders, null_array,
    OAuthFetchFlags::UseToken | OAuthFetchFlags::OverrideHttpMethod);
  oa->setResponseArgs(nullptr);
  return retcode >= 200 && retcode <= 206;
}

Variant HHVM_METHOD(OAuth, generateSignature,
                    const String& httpMethod,
                    const String& url,
                    const Variant& extraParams) {
  auto oa = Native::data<OAuth>(this_);
  if (!url.length()) {
    return false;
  }

  if (oa->fetch(url, httpMethod, extraParams, null_array, null_array,
                OAuthFetchFlags::UseToken | OAuthFetchFlags::SigOnly) < 0) {
    return false;
  } else {
    return String(oa->signature, CopyString);
  }
}

Variant HHVM_METHOD(OAuth, getAccessToken,
                    const String& accessTokenURL,
                    const String& authSessionHandle,
                    const String& authVerifier,
                    const String& httpMethod) {
  auto oa = Native::data<OAuth>(this_);
  if (!accessTokenURL.length()) {
    OAuth::handleError(oa, "Invalid access token url length");
  }

  String verifier = authVerifier;
  if (!verifier.length()) {
    auto g = php_global(s__GET);
    if (g.asArrRef().exists(OAuthParam::Verifier)) {
      verifier = g.asArrRef()[OAuthParam::Verifier].asCStrRef();
    } else {
      auto p = php_global(s__POST);
      if (p.asArrRef().exists(OAuthParam::Verifier)) {
        verifier = p.asArrRef()[OAuthParam::Verifier].asCStrRef();
      }
    }
  }

  Array extraArgs = Array::Create();
  if (authSessionHandle.length()) {
    extraArgs.set(OAuthParam::Ash, authSessionHandle);
  }
  if (verifier.length()) {
    extraArgs.set(OAuthParam::Verifier, verifier);
  }

  auto retcode = oa->fetch(accessTokenURL,
    OAuthHTTPMethod::getMethod(Object(this_), httpMethod), null_variant,
    null_array, extraArgs, OAuthFetchFlags::UseToken);
  if (retcode == -1 || oa->lastresponse.isNull()) {
    return false;
  }

  Array ret = Array::Create();
  oa->setResponseArgs(&ret);
  return ret;
}

Array HHVM_METHOD(OAuth, getCAPath) {
  Array ret = Array::Create();
  auto caInfo = Native::getProp(Object(this_), OAuthAttr::CAInfo);
  auto caPath = Native::getProp(Object(this_), OAuthAttr::CAPath);
  if (!caInfo.isNull()) {
    ret.set(s_ca_info, caInfo);
  }
  if (!caPath.isNull()) {
    ret.set(s_ca_path, caPath);
  }
  return ret;
}

Variant HHVM_METHOD(OAuth, getLastResponse) {
  auto oa = Native::data<OAuth>(this_);
  if (!oa->lastresponse.isNull()) {
    return oa->lastresponse;
  }
  return false;
}

Variant HHVM_METHOD(OAuth, getLastResponseHeaders) {
  auto oa = Native::data<OAuth>(this_);
  if (!oa->headers_in.isNull()) {
    return oa->headers_in;
  }
  return false;
}

Variant HHVM_METHOD(OAuth, getLastResponseInfo) {
  if (Native::issetProp(Object(this_), OAuthAttr::LastResInfo).toBoolean()) {
    return Native::getProp(Object(this_), OAuthAttr::LastResInfo).toArray();
  }
  return false;
}

Variant HHVM_METHOD(OAuth, getRequestHeader,
                    const String& httpMethod,
                    const String& url,
                    const Variant& extraParams) {
  auto oa = Native::data<OAuth>(this_);
  if (!url.length()) {
    return false;
  }

  auto retcode = oa->fetch(url, httpMethod, extraParams, null_array,
    null_array, OAuthFetchFlags::UseToken | OAuthFetchFlags::HeadOnly);
  if (retcode < 0) {
    return false;
  }

  return oa->headers_out;
}

Variant HHVM_METHOD(OAuth, getRequestToken,
                    const String& requestTokenURL,
                    const Variant& callbackURL,
                    const String& httpMethod) {
  auto oa = Native::data<OAuth>(this_);
  if (!requestTokenURL.length()) {
    OAuth::handleError(oa, "Invalid request token url length");
  }

  Array args = Array::Create();
  if (!callbackURL.isNull() && callbackURL.isString()) {
    if (callbackURL.asCStrRef().length()) {
      args.set(OAuthParam::Callback, callbackURL);
    } else {
      args.set(OAuthParam::Callback, s_oob);
    }
  }

  auto retcode = oa->fetch(
    requestTokenURL,
    OAuthHTTPMethod::getMethod(Object(this_), httpMethod),
    null_variant, null_array, args, OAuthFetchFlags::None);
  if (retcode == -1 || oa->lastresponse.isNull()) {
    return false;
  }

  Array ret = Array::Create();
  oa->setResponseArgs(&ret);
  return ret;
}

bool HHVM_METHOD(OAuth, setAuthType, int64_t authType) {
  auto oa = Native::data<OAuth>(this_);
  switch (authType) {
    case OAUTH_AUTH_TYPE_URI:
    case OAUTH_AUTH_TYPE_FORM:
    case OAUTH_AUTH_TYPE_AUTHORIZATION:
    case OAUTH_AUTH_TYPE_NONE:
      Native::setProp(Object(this_), OAuthAttr::AuthMethod, authType);
      return true;
    default:
      OAuth::handleError(oa, "Invalid auth type");
  }
}

bool HHVM_METHOD(OAuth, setCAPath, const String& caPath, const String& caInfo) {
  if (caPath.length()) {
    Native::setProp(Object(this_), OAuthAttr::CAPath, caPath);
  }
  if (caInfo.length()) {
    Native::setProp(Object(this_), OAuthAttr::CAInfo, caInfo);
  }
  return true;
}

bool HHVM_METHOD(OAuth, setNonce, const String& nonce) {
  auto oa = Native::data<OAuth>(this_);
  if (!nonce.length()) {
    OAuth::handleError(oa, "Invalid nonce");
  }

  oa->nonce = nonce;
  return true;
}

void HHVM_METHOD(OAuth, setRequestEngine, int64_t reqEngine) {
  auto oa = Native::data<OAuth>(this_);
  switch (reqEngine) {
    case OAUTH_REQENGINE_STREAMS:
#ifdef ENABLE_EXTENSION_CURL
    case OAUTH_REQENGINE_CURL:
#endif
      oa->reqengine = reqEngine;
      break;
    default:
      OAuth::handleError(oa, "Invalid request engine specified");
  }
}

bool HHVM_METHOD(OAuth, setRSACertificate, const String& cert) {
  auto oa = Native::data<OAuth>(this_);
  auto ret = HHVM_FN(openssl_pkey_get_private)(cert);
  if (!ret.isResource()) {
    OAuth::handleError(oa, "Could not parse RSA certificate");
  }
  oa->sig_ctx->private_key = ret;
  return true;
}

bool HHVM_METHOD(OAuth, setSSLChecks, int64_t sslChecks) {
  Native::data<OAuth>(this_)->sslcheck = sslChecks & OAUTH_SSLCHECK_BOTH;
  return true;
}

bool HHVM_METHOD(OAuth, setTimeout, int64_t ms) {
  auto oa = Native::data<OAuth>(this_);
  if (ms < 0) {
    OAuth::handleError(oa, "Invalid timeout");
  }
  oa->timeout = ms;
  return true;
}

bool HHVM_METHOD(OAuth, setTimestamp, const String& timestamp) {
  auto oa = Native::data<OAuth>(this_);
  if (!timestamp.length()) {
    OAuth::handleError(oa, "Invalid timestamp");
  }

  oa->timestamp = timestamp;
  return true;
}

bool HHVM_METHOD(OAuth, setToken, const String& token,
                 const String& tokenSecret) {
  Native::setProp(Object(this_), OAuthAttr::Token, token);
  if (tokenSecret.length()) {
    auto sec = OAuth::urlEncode(tokenSecret);
    Native::setProp(Object(this_), OAuthAttr::TokenSecret, sec);
  }
  return true;
}

bool HHVM_METHOD(OAuth, setVersion, const String& version) {
  auto oa = Native::data<OAuth>(this_);
  if (!version.length()) {
    OAuth::handleError(oa, "Invalid version");
  }

  Native::setProp(Object(this_), OAuthAttr::OAuthVersion, version);
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// OAuthProvider
///////////////////////////////////////////////////////////////////////////////

Variant OAuthProvider::callCallback(OAuthProviderCallback cbType) {
  Variant callback;
  const char* errStr;
  switch (cbType) {
    case OAuthProviderCallback::Consumer:
      callback = this->consumer_handler;
      errStr = "Consumer key/secret handler not specified, did you set a"
        " valid callback via OAuthProvider::consumerHandler()?";
      break;
    case OAuthProviderCallback::Token:
      callback = this->token_handler;
      errStr = "Token handler not specified, did you set a valid callback"
        " via OAuthProvider::tokenHandler()?";
      break;
    case OAuthProviderCallback::TSNonce:
      callback = this->tsnonce_handler;
      errStr = "Timestamp/nonce handler not specified, did you set a valid"
        " callback via OAuthProvider::timestampNonceHandler()?";
      break;
    default:
      raise_error("Invalid callback type of OAuthProvider");
  }

  if (callback.isNull()) {
    raise_error(errStr);
  }

  if (!is_callable(callback)) {
    raise_error("Invalid callback");
  }

  return vm_call_user_func(callback,
                           make_packed_array(Object(Native::object(this))));
}

bool OAuthProvider::parseAuthHeader(const String& authHeader) {
  // oauth_provider_parse_auth_header
  to_do_implement_me();
  return true;
}

void HHVM_METHOD(OAuthProvider, __construct, const Variant& params) {
  auto oap = Native::data<OAuthProvider>(this_);

  int paramCount = 0;
  if (!params.isNull() && params.isArray()) {
    paramCount = params.asCArrRef().size();
  }

  if (RuntimeOption::ClientExecutionMode() && !paramCount) {
    raise_error("For the CLI sapi parameters must be set first via"
                " OAuthProvider::__construct(array(\"oauth_param\" =>"
                " \"value\", ...))");
  }

  oap->required_params.add(OAuthParam::ConsumerKey, null_variant);
  oap->required_params.add(OAuthParam::Signature, null_variant);
  oap->required_params.add(OAuthParam::SignatureMethod, null_variant);
  oap->required_params.add(OAuthParam::Nonce, null_variant);
  oap->required_params.add(OAuthParam::Timestamp, null_variant);
  oap->required_params.add(OAuthParam::Token, null_variant);

  auto thisObj = Object(this_);
  Native::setProp(thisObj, OAuthProviderAttr::ConsumerKey, null_variant);
  Native::setProp(thisObj, OAuthProviderAttr::ConsumerSecret, null_variant);
  Native::setProp(thisObj, OAuthProviderAttr::Nonce, null_variant);
  Native::setProp(thisObj, OAuthProviderAttr::Token, null_variant);
  Native::setProp(thisObj, OAuthProviderAttr::TokenSecret, null_variant);
  Native::setProp(thisObj, OAuthProviderAttr::Timestamp, null_variant);
  Native::setProp(thisObj, OAuthProviderAttr::Version, null_variant);
  Native::setProp(thisObj, OAuthProviderAttr::SignatureMethod, null_variant);
  Native::setProp(thisObj, OAuthProviderAttr::Callback, null_variant);
  Native::setProp(thisObj, OAuthProviderAttr::RequestTokenEndpoint, false);

  if (!paramCount) {
    String authHeader = null_string;
    if (ApacheExtension::Enable) {
      auto apacheHeaders = HHVM_FN(apache_request_headers)();
      if (apacheHeaders.exists(s_Authorization)) {
        authHeader = apacheHeaders[s_Authorization];
      } else {
        for (ArrayIter iter(apacheHeaders); iter; ++iter) {
          if (!HHVM_FN(strcasecmp)(iter.first().asCStrRef(), s_Authorization)) {
            authHeader = iter.second().asStrRef();
            break;
          }
        }
      }
    } else {
      auto serv = php_global(s__SERVER);
      if (serv.isArray() && serv.asArrRef().exists(s_HTTP_AUTHORIZATION)) {
        authHeader = serv.asArrRef()[s_HTTP_AUTHORIZATION];
      } else {
        auto env = php_global(s__ENV);
        if (env.isArray() && env.asArrRef().exists(s_HTTP_AUTHORIZATION)) {
          authHeader = env.asArrRef()[s_HTTP_AUTHORIZATION];
        }
      }
    }

    if (!authHeader.isNull()) {
      if (!oap->parseAuthHeader(authHeader)) {
        OAuth::handleError(nullptr, "Unknown signature method", nullptr,
                           nullptr, OAUTH_SIGNATURE_METHOD_REJECTED);
      }
    }
  }

  if (paramCount) {
    oap->oauth_params.merge(params.asCArrRef());
  }
}

bool HHVM_METHOD(OAuthProvider, addRequiredParameter, const String& param) {
  Native::data<OAuthProvider>(this_)->required_params.set(param, null_variant);
  return true;
}

void HHVM_METHOD(OAuthProvider, callConsumerHandler) {
  Native::data<OAuthProvider>(this_)->callCallback(
    OAuthProviderCallback::Consumer);
}

void HHVM_METHOD(OAuthProvider, callTimestampNonceHandler) {
  Native::data<OAuthProvider>(this_)->callCallback(
    OAuthProviderCallback::TSNonce);
}

void HHVM_METHOD(OAuthProvider, callTokenHandler) {
  Native::data<OAuthProvider>(this_)->callCallback(
    OAuthProviderCallback::Token);
}

void HHVM_METHOD(OAuthProvider, checkOAuthRequest,
                 const String& url,
                 const String& requestMethod) {
  auto oap = Native::data<OAuthProvider>(this_);

  String httpVerb = requestMethod;
  if (httpVerb.empty()) {
    auto g = php_global(s__SERVER);
    if (!g.isNull()) {
      auto a = g.asArrRef();
      if (a.exists(s_REQUEST_METHOD)) {
        httpVerb = a[s_REQUEST_METHOD];
      } else if (a.exists(s_HTTP_METHOD)) {
        httpVerb = a[s_HTTP_METHOD];
      }

      if (httpVerb.empty()) {
        raise_error("Failed to detect HTTP method, set a HTTP method"
                    " via OAuthProvider::checkOAuthRequest()");
      }
    }
  }
  
  Array sbsVars = Array::Create();
  auto g = php_global(s__GET);
  if (!g.isNull()) {
    sbsVars.merge(g.asCArrRef());
  }
  auto p = php_global(s__POST);
  if (!p.isNull()) {
    sbsVars.merge(p.asCArrRef());
  }
  if (!oap->oauth_params.empty()) {
    sbsVars.merge(oap->oauth_params);
  }
  if (!oap->custom_params.empty()) {
    sbsVars.merge(oap->custom_params);
  }

#define SET_STD_PARAM(name) \
  if (sbsVars.exists(OAuthParam::name)) { \
    Native::setProp(thisObj, OAuthProviderAttr::name, \
                    sbsVars[OAuthParam::name]); \
  }

  auto thisObj = Object(this_);
  SET_STD_PARAM(ConsumerKey);
  SET_STD_PARAM(Token);
  SET_STD_PARAM(Signature);
  SET_STD_PARAM(Nonce);
  SET_STD_PARAM(Timestamp);
  SET_STD_PARAM(Version);
  SET_STD_PARAM(SignatureMethod);
  SET_STD_PARAM(Callback);
  SET_STD_PARAM(Verifier);

#undef SET_STD_PARAM

  if (url.empty()) {
    to_do_implement_me();
  }


  to_do_implement_me();
}

void OAuthProvider::setStdParam(Array& arr,
                                const StaticString& authParam,
                                const StaticString& providerParam) {
  if (arr.exists(authParam)) {
    Native::setProp(Object(Native::object(this)),
                    providerParam, arr[authParam]);
  }
}

void HHVM_METHOD(OAuthProvider, consumerHandler, const Variant& cb) {
  auto oap = Native::data<OAuthProvider>(this_);
  if (is_callable(cb)) {
    oap->consumer_handler = cb;
  }
}

String HHVM_STATIC_METHOD(OAuthProvider, generateToken,
                          int64_t size,
                          bool strong) {
  // We ignore the strong parameter and always generate via a strong random.
  if (size < 1) {
    raise_warning("Cannot generate token with a size of less than 1");
    return empty_string();
  }

  auto buf = req::malloc(size);
  folly::Random::secureRandom(buf, size);
  return String((char*)buf, size, AttachString);
}

void HHVM_METHOD(OAuthProvider, isRequestTokenEndpoint, bool willIssue) {
  Native::setProp(Object(this_),
                  OAuthProviderAttr::RequestTokenEndpoint, willIssue);
}

bool HHVM_METHOD(OAuthProvider, removeRequiredParameter,
                 const String& requiredParam) {
  auto oap = Native::data<OAuthProvider>(this_);
  if (!oap->required_params.exists(requiredParam)) {
    return false;
  }

  oap->required_params.remove(requiredParam);
  return true;
}

String HHVM_STATIC_METHOD(OAuthProvider, reportProblem,
                          const Object& exception,
                          bool sendHeaders) {
  auto code = Native::getProp(exception, s_code).asInt64Val();

  Variant addInfo = null_variant;
  String ret = null_string;
  int httpCode = -1;
  switch (code) {
    case OAUTH_BAD_TIMESTAMP:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = OAuthProblem::BadTimestamp;
      break;
    case OAUTH_BAD_NONCE:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = OAuthProblem::BadNonce;
      break;
    case OAUTH_CONSUMER_KEY_UNKNOWN:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = OAuthProblem::ConsumerKeyUnknown;
      break;
    case OAUTH_CONSUMER_KEY_REFUSED:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = OAuthProblem::ConsumerKeyRefused;
      break;
    case OAUTH_TOKEN_USED:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = OAuthProblem::TokenUsed;
      break;
    case OAUTH_TOKEN_EXPIRED:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = OAuthProblem::TokenExpired;
      break;
    case OAUTH_TOKEN_REVOKED:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = OAuthProblem::TokenRevoked;
      break;
    case OAUTH_TOKEN_REJECTED:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = OAuthProblem::TokenRejected;
      break;
    case OAUTH_VERIFIER_INVALID:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = OAuthProblem::VerifierInvalid;
      break;
    case OAUTH_INVALID_SIGNATURE:
      httpCode = OAUTH_ERR_BAD_AUTH;
      ret = "oauth_problem=signature_invalid";
      addInfo = Native::getProp(exception, s_additionalInfo);
      if (!addInfo.isNull()) {
        auto s = addInfo.toString();
        if (s.length()) {
          ret += "&debug_sbs=" + s;
        }
      }
      break;
    case OAUTH_SIGNATURE_METHOD_REJECTED:
      httpCode = OAUTH_ERR_BAD_REQUEST;
      ret = OAuthProblem::SignatureMethodRejected;
      break;
    case OAUTH_PARAMETER_ABSENT:
      httpCode = OAUTH_ERR_BAD_REQUEST;
      ret = "oauth_problem=parameter_absent";
      addInfo = Native::getProp(exception, s_additionalInfo);
      if (!addInfo.isNull()) {
        auto s = addInfo.toString();
        if (s.length()) {
          ret += "&oauth_parameters_absent=" + s;
        }
      }
      break;
    default:
      httpCode = OAUTH_ERR_INTERNAL_ERROR;
      ret = folly::format("oauth_problem=unknown_problem&code={}", code).str();
      break;
  }

  if (sendHeaders) {
    Transport* transport = g_context->getTransport();
    if (httpCode == OAUTH_ERR_BAD_REQUEST) {
      transport->replaceHeader(OAuthProblem::_400_BadRequest);
    } else {
      transport->replaceHeader(OAuthProblem::_401_Unauthorized);
    }
    transport->setResponse(httpCode);
  }

  return ret;
}

bool HHVM_METHOD(OAuthProvider, setParam,
                 const String& key,
                 const Variant& val) {
  auto oap = Native::data<OAuthProvider>(this_);
  if (val.isNull()) {
    if (oap->custom_params.exists(key)) {
      oap->custom_params.remove(key);
      return true;
    }
    return false;
  } else {
    oap->custom_params.set(key, val);
    return true;
  }
}

bool HHVM_METHOD(OAuthProvider, setRequestTokenPath, const String& path) {
  Native::data<OAuthProvider>(this_)->requestEndpointPath = path;
  return true;
}

void HHVM_METHOD(OAuthProvider, timestampNonceHandler, const Variant& cb) {
  auto oap = Native::data<OAuthProvider>(this_);
  if (is_callable(cb)) {
    oap->tsnonce_handler = cb;
  }
}

void HHVM_METHOD(OAuthProvider, tokenHandler, const Variant& cb) {
  auto oap = Native::data<OAuthProvider>(this_);
  if (is_callable(cb)) {
    oap->token_handler = cb;
  }
}

///////////////////////////////////////////////////////////////////////////////
// OAuthExtension
///////////////////////////////////////////////////////////////////////////////

static OAuthExtension s_oauth_extension;
Class* OAuthExtension::OAuthExceptionClass;

void OAuthExtension::moduleInit() {
  HHVM_FE(oauth_urlencode);
  HHVM_FE(oauth_get_sbs);

  Native::registerNativeDataInfo<OAuth>(s_OAuth.get(),
                                        Native::NDIFlags::NO_COPY);
  Native::registerNativePropHandler<OAuthPropHandler>(s_OAuth);
  HHVM_ME(OAuth, __construct);
  HHVM_ME(OAuth, __destruct);
  HHVM_ME(OAuth, disableDebug);
  HHVM_ME(OAuth, disableRedirects);
  HHVM_ME(OAuth, disableSSLChecks);
  HHVM_ME(OAuth, enableDebug);
  HHVM_ME(OAuth, enableRedirects);
  HHVM_ME(OAuth, enableSSLChecks);
  HHVM_ME(OAuth, fetch);
  HHVM_ME(OAuth, generateSignature);
  HHVM_ME(OAuth, getAccessToken);
  HHVM_ME(OAuth, getCAPath);
  HHVM_ME(OAuth, getLastResponse);
  HHVM_ME(OAuth, getLastResponseHeaders);
  HHVM_ME(OAuth, getLastResponseInfo);
  HHVM_ME(OAuth, getRequestHeader);
  HHVM_ME(OAuth, getRequestToken);
  HHVM_ME(OAuth, setAuthType);
  HHVM_ME(OAuth, setCAPath);
  HHVM_ME(OAuth, setNonce);
  HHVM_ME(OAuth, setRequestEngine);
  HHVM_ME(OAuth, setRSACertificate);
  HHVM_ME(OAuth, setSSLChecks);
  HHVM_ME(OAuth, setTimeout);
  HHVM_ME(OAuth, setTimestamp);
  HHVM_ME(OAuth, setToken);
  HHVM_ME(OAuth, setVersion);

  Native::registerNativeDataInfo<OAuthProvider>(s_OAuthProvider.get(),
    Native::NDIFlags::NO_COPY | Native::NDIFlags::NO_SWEEP);
  HHVM_ME(OAuthProvider, __construct);
  HHVM_ME(OAuthProvider, addRequiredParameter);
  HHVM_ME(OAuthProvider, callConsumerHandler);
  HHVM_ME(OAuthProvider, callTimestampNonceHandler);
  HHVM_ME(OAuthProvider, callTokenHandler);
  HHVM_ME(OAuthProvider, consumerHandler);
  HHVM_STATIC_ME(OAuthProvider, generateToken);
  HHVM_MALIAS(OAuthProvider, is2LeggedEndpoint,
              OAuthProvider, isRequestTokenEndpoint);
  HHVM_ME(OAuthProvider, isRequestTokenEndpoint);
  HHVM_ME(OAuthProvider, removeRequiredParameter);
  HHVM_STATIC_ME(OAuthProvider, reportProblem);
  HHVM_ME(OAuthProvider, setParam);
  HHVM_ME(OAuthProvider, setRequestTokenPath);
  HHVM_ME(OAuthProvider, timestampNonceHandler);
  HHVM_ME(OAuthProvider, tokenHandler);


  HHVM_RC_STR_SAME(OAUTH_SIG_METHOD_HMACSHA1);
  HHVM_RC_STR_SAME(OAUTH_SIG_METHOD_HMACSHA256);
  HHVM_RC_STR_SAME(OAUTH_SIG_METHOD_RSASHA1);
  HHVM_RC_STR_SAME(OAUTH_SIG_METHOD_PLAINTEXT);

  HHVM_RC_INT_SAME(OAUTH_AUTH_TYPE_AUTHORIZATION);
  HHVM_RC_INT_SAME(OAUTH_AUTH_TYPE_URI);
  HHVM_RC_INT_SAME(OAUTH_AUTH_TYPE_FORM);
  HHVM_RC_INT_SAME(OAUTH_AUTH_TYPE_NONE);

  HHVM_RC_STR_SAME(OAUTH_HTTP_METHOD_GET);
  HHVM_RC_STR_SAME(OAUTH_HTTP_METHOD_POST);
  HHVM_RC_STR_SAME(OAUTH_HTTP_METHOD_PUT);
  HHVM_RC_STR_SAME(OAUTH_HTTP_METHOD_HEAD);
  HHVM_RC_STR_SAME(OAUTH_HTTP_METHOD_DELETE);

  HHVM_RC_INT_SAME(OAUTH_REQENGINE_STREAMS);
#ifdef ENABLE_EXTENSION_CURL
  HHVM_RC_INT_SAME(OAUTH_REQENGINE_CURL);
#endif

  HHVM_RC_INT_SAME(OAUTH_SSLCHECK_NONE);
  HHVM_RC_INT_SAME(OAUTH_SSLCHECK_HOST);
  HHVM_RC_INT_SAME(OAUTH_SSLCHECK_PEER);
  HHVM_RC_INT_SAME(OAUTH_SSLCHECK_BOTH);
  
  HHVM_RC_INT_SAME(OAUTH_OK);
  HHVM_RC_INT_SAME(OAUTH_BAD_NONCE);
  HHVM_RC_INT_SAME(OAUTH_BAD_TIMESTAMP);
  HHVM_RC_INT_SAME(OAUTH_CONSUMER_KEY_UNKNOWN);
  HHVM_RC_INT_SAME(OAUTH_CONSUMER_KEY_REFUSED);
  HHVM_RC_INT_SAME(OAUTH_INVALID_SIGNATURE);
  HHVM_RC_INT_SAME(OAUTH_TOKEN_USED);
  HHVM_RC_INT_SAME(OAUTH_TOKEN_EXPIRED);
  HHVM_RC_INT_SAME(OAUTH_TOKEN_REVOKED);
  HHVM_RC_INT_SAME(OAUTH_TOKEN_REJECTED);
  HHVM_RC_INT_SAME(OAUTH_VERIFIER_INVALID);
  HHVM_RC_INT_SAME(OAUTH_PARAMETER_ABSENT);
  HHVM_RC_INT_SAME(OAUTH_SIGNATURE_METHOD_REJECTED);

  loadSystemlib();
  OAuthExtension::OAuthExceptionClass =
    NamedEntity::get(makeStaticString("OAuthException"))->clsList();
}

}
