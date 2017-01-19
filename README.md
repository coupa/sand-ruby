# sand-ruby
A Ruby client library for service authentication via OAuth2.

A client who wants to communicate with a service, it will request a token from the OAuth2 server and use this token to make an API call to the service.

When a service receives a request with an OAuth bearer token, it verifies the token with the OAuth2 server to see if the token is allowed to access this service. The service acts like an OAuth2 Resource Server that verifies the token.

## Features

* The authentication is done using the "client credentials" grant type in OAuth2.
* The tokens are cached on both the client and the service sides. The cache store is configurable to use a cache store like Rails.cache.

## Instruction

Sand::Client can request a token and cache this token until it expires. To initialize a Sand::Client instance is to provide the following configuration to the constructor:

```
opts = {
  client_id: "abcd",            # Required. The client ID of the OAuth2 client credentials
  client_secret: "defg",        # Required. The client secret of the OAuth2 client credentials
  token_site: "https://oauth.example.com", # Required. The host site of the OAuth2 server
  token_path: "/oauth2/token",  # Required. The OAuth token endpoint on the OAuth2 server.

  # Below also shows their default values
  skip_tls_verify:  false,  # Skip verifying the TLS certificate
  max_retry:        5,      # Maximum number of retries on connection error
  race_ttl_in_secs: 10,     # Extended TTL for racing condition for cache
  cache:            nil,    # For example, Rails.cache
  cache_root:       "sand", # A string as the root namespace in the cache
  logger:           nil     # For example, Rails.logger
}
client = Sand::Client.new(opts)

client.request('cache_key', 'scope1 scope2') do |token|
  # Make http request with net/http, Faraday, Httparty, etc...
  # with "Bearer token" in the Authorization header
  # return the response
end
```

Sand::Service can verify the token with the OAuth2 server. The result can also be cached to avoid checking on the same token on every request. To initialize a Sand::Service instance is to provide the above options PLUS additional options below:

```
opts = {
  ... # Same as Sand::Client's options above
  resource:          "some-service",          # Required. This service's unique resource name registered with the OAuth2 server
  token_verify_path: "/warden/token/allowed", # Required. The token verification endpoint

  # Below also shows their default values
  default_exp_time: 3600     # The default expiry time for cache for invalid tokens and also valid tokens without expiry times.
  scopes:           ''       # The scopes required to access the token verification endpoint

}
service = Sand::Service.new(opts)

# Usage Example with Rails request
begin
  allowed = service.check_request(request, 'target_scope1 target_scope2', 'action')
  render status: service.access_denied_code if !allowed
rescue => e
  render status: service.error_code
end
```

### Client

Sand::Client has the `check_request` method which can perform retry when encountering 401 responses from the service. This should be the primary method to use for a client.

Both the Sand::Client and Sand::Service classes have the `token` method that gets an OAuth token from authentication service. If a cache store is available and the token is found in cache, it will return this token and not retrieving the token from the authentication service.

### Service

The Sand::Service class defines the `check_request` method for verifying a request with the authentication service on whether the client token from the request is allowed to communicate with this service. A client's token and the verification result will also be cached if the cache is available.
