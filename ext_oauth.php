<?hh

/* Generates a Signature Base String according to pecl/oauth.
 */
<<__Native>>
function oauth_get_sbs(mixed $http_method,
                       mixed $uri,
                       mixed $request_parameters = []): mixed;

/* Encodes a URI to RFC 3986.
 */
<<__Native>>
function oauth_urlencode(mixed $uri): mixed;

/* This exception is thrown when exceptional errors occur while using the
 * OAuth extension and contains useful debugging information.
 */
class OAuthException extends Exception {
  public string? $additionalInfo;
  public string? $lastResponse;
  public array? $debugInfo;

  public function __construct(string $msg,
                              int $code,
                              string? $lastResponse,
                              array? $debugInfo,
                              string? $additionalInfo) {
    parent::__construct($msg, $code);
    $this->lastResponse = $lastResponse;
    $this->debugInfo = $debugInfo;
    $this->additionalInfo = $additionalInfo;
  }
}

/* The OAuth extension provides a simple interface to interact with data
 * providers using the OAuth HTTP specification to protect private resources.
 */
<<__NativeData("OAuth")>>
class OAuth {
  public int $debug = 0;
  public int $sslChecks = 1;
  public string $debugInfo = '';

  /* Creates a new OAuth object
   */
  <<__Native>>
  public function __construct(mixed $consumer_key,
                              mixed $consumer_secret,
                              mixed $signature_method = OAUTH_SIG_METHOD_HMACSHA1,
                              mixed $auth_type = 0): void;

  /* The destructor.
   */
  <<__Native>>
  public function __destruct(): void;

  /* Turns off verbose request information (off by default). Alternatively, the
   * debug property can be set to a FALSE value to turn debug off.
   */
  <<__Native>>
  public function disableDebug(): bool;

  /* Disable redirects from being followed automatically, thus allowing the
   * request to be manually redirected.
   */
  <<__Native>>
  public function disableRedirects(): bool;

  /* Turns off the usual SSL peer certificate and host checks, this is not for
   * production environments. Alternatively, the sslChecks member can be set to
   * FALSE to turn SSL checks off.
   */
  <<__Native>>
  public function disableSSLChecks(): bool;

  /* Turns on verbose request information useful for debugging, the debug
   * information is stored in the debugInfo member. Alternatively, the debug
   * member can be set to a non-FALSE value to turn debug on.
   */
  <<__Native>>
  public function enableDebug(): bool;

  /* Follow and sign redirects automatically, which is enabled by default.
   */
  <<__Native>>
  public function enableRedirects(): bool;

  /* Turns on the usual SSL peer certificate and host checks (enabled by
   * default). Alternatively, the sslChecks member can be set to a non-FALSE
   * value to turn SSL checks off.
   */
  <<__Native>>
  public function enableSSLChecks(): bool;

  /* Fetch a resource.
   */
  <<__Native>>
  public function fetch(mixed $protected_resource_url,
                        mixed $extra_parameters = [],
                        mixed $http_method = "",
                        mixed $http_headers = []): bool;

  /* Generate a signature based on the final HTTP method, URL and a string/array
   * of parameters.
   */
  <<__Native>>
  public function generateSignature(mixed $http_method,
                                    mixed $url,
                                    mixed $extra_parameters = []): mixed;

  /* Fetch an access token, secret and any additional response parameters from
   * the service provider.
   */
  <<__Native>>
  public function getAccessToken(mixed $access_token_url,
                                 mixed $auth_session_handle = "",
                                 mixed $verifier_token = "",
                                 mixed $http_method = ""): mixed;

  /* Gets the Certificate Authority information, which includes the ca_path and
   * ca_info set by OAuth::setCaPath().
   */
  <<__Native>>
  public function getCAPath(): array;

  /* Get the raw response of the most recent request.
   */
  <<__Native>>
  public function getLastResponse(): mixed;

  /* Get headers for last response.
   */
  <<__Native>>
  public function getLastResponseHeaders(): mixed;

  /* Get HTTP information about the last response.
   */
  <<__Native>>
  public function getLastResponseInfo(): mixed;

  /* Generate OAuth header string signature based on the final HTTP method, URL
   * and a string/array of parameters
   */
  <<__Native>>
  public function getRequestHeader(mixed $http_method,
                                   mixed $url,
                                   mixed $extra_parameters = []): mixed;

  /* Fetch a request token, secret and any additional response parameters from
   * the service provider.
   */
  <<__Native>>
  public function getRequestToken(mixed $request_token_url,
                                  mixed $callback_url = null,
                                  mixed $http_method = ""): mixed;

  /* Set where the OAuth parameters should be passed.
   */
  <<__Native>>
  public function setAuthType(mixed $auth_type): bool;

  /* Sets the Certificate Authority (CA), both for path and info.
   */
  <<__Native>>
  public function setCAPath(mixed $ca_path = "",
                            mixed $ca_info = ""): bool;

  /* Sets the nonce for all subsequent requests.
   */
  <<__Native>>
  public function setNonce(mixed $nonce): bool;

  /* Sets the Request Engine, that will be sending the HTTP requests.
   */
  <<__Native>>
  public function setRequestEngine(mixed $reqengine): void;

  /* Sets the RSA certificate.
   */
  <<__Native>>
  public function setRSACertificate(mixed $cert): bool;

  /* Tweak specific SSL checks for requests.
   */
  <<__Native>>
  public function setSSLChecks(mixed $sslcheck): bool;

  /* Set the timeout, in milliseconds, for requests.
   */
  <<__Native>>
  public function setTimeout(mixed $milliseconds): bool;
  
  /* Sets the OAuth timestamp for subsequent requests.
   */
  <<__Native>>
  public function setTimestamp(mixed $timestamp): bool;

  /* Set the token and secret for subsequent requests.
   */
  <<__Native>>
  public function setToken(mixed $token,
                           mixed $token_secret): bool;

  /* Sets the OAuth version for subsequent requests
   */
  <<__Native>>
  public function setVersion(mixed $version): bool;
}

/* Manages an OAuth provider class.  See also an external in-depth tutorial
 * titled Writing an OAuth Provider Service, which takes a hands-on approach
 * to providing this service. There are also OAuth provider examples within
 * the OAuth extensions sources.
 */
<<__NativeData("OAuthProvider")>>
class OAuthProvider {
  
  /* Initiates a new OAuthProvider object.
   */
  <<__Native>>
  public function __construct(mixed $params_array = null): void;

  /* Add required oauth provider parameters.
   */
  <<__Native>>
  public function addRequiredParameter(mixed $req_params): bool;

  /* Calls the registered consumer handler callback function, which is set with
   * OAuthProvider::consumerHandler().
   */
  <<__Native>>
  public function callConsumerHandler(): void;

  /* Calls the registered timestamp handler callback function, which is set with
   * OAuthProvider::timestampNonceHandler().
   */
  <<__Native>>
  public function callTimestampNonceHandler(): void;

  /* Calls the registered token handler callback function, which is set with
   * OAuthProvider::tokenHandler().
   */
  <<__Native>>
  public function callTokenHandler(): void;

  /* Checks an OAuth request.
   */
  <<__Native>>
  public function checkOAuthRequest(mixed $uri = null,
                                    mixed $method = null): void;

  /* Sets the consumer handler callback, which will later be called with
   * OAuthProvider::callConsumerHandler().
   */
  <<__Native>>
  public function consumerHandler(mixed $callback_function): void;

  /* Generates a string of pseudo-random bytes.
   */
  <<__Native>>
  public static function generateToken(mixed $size,
                                       mixed $strong = false): string;

  /* The 2-legged flow, or request signing. It does not require a token.
   */
  <<__Native>>
  public function is2LeggedEndpoint(mixed $will_issue_request_token): void;

  <<__Native>>
  public function isRequestTokenEndpoint(mixed $will_issue_request_token): void;

  /* Removes a required parameter.
   */
  <<__Native>>
  public function removeRequiredParameter(mixed $req_param): bool;

  /* Pass in a problem as an OAuthException, with possible problems listed in
   * the OAuth constants section.
   */
  <<__Native>>
  public static function reportProblem(mixed $oauthexception,
                                       mixed $send_headers = true): string;

  /* Sets a parameter.
   */
  <<__Native>>
  public function setParam(mixed $param_key,
                           mixed $param_val): bool;

  /* Sets the request tokens path.
   */
  <<__Native>>
  public function setRequestTokenPath(mixed $path): bool;

  /* Sets the timestamp nonce handler callback, which will later be called with
   * OAuthProvider::callTimestampNonceHandler(). Errors related to
   * timestamp/nonce are thrown to this callback.
   */
  <<__Native>>
  public function timestampNonceHandler(mixed $callback_function): void;

  /* Sets the token handler callback, which will later be called with
   * OAuthProvider::callTokenHandler().
   */
  <<__Native)>>
  public function tokenHandler(mixed $callback_function): void;
}
