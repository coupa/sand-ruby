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
  ssl_min_version:     :TLS1_2,  # Minimum TLS version supported. For Faraday >= v1.0, the default value will be :TLS1_2. For Faraday < v1.0, the value will be :TLSv1_2.
  default_retry_count: 5,      # Default number of retries on connection error
  cache:               nil,    # Always use a cache!! For example, Rails.cache
  cache_root:          "sand", # A string as the root namespace in the cache
  logger:              nil     # For example, Rails.logger
}
client = Sand::Client.new(opts)

client.request(cache_key: 'cache_key', scopes: ['scope1', 'scope2'], num_retry: 3) do |token|
  response = ... # Make http request with net/http, Faraday, Httparty, etc...
                 # with "Bearer token" in the Authorization header
  response       # **** MUST **** return the response object in the block
end
```

Please note that the block for Sand::Client's request method MUST return the response object at the end of the block.

Sand::Service can verify the token with the OAuth2 server. The result can also be cached to avoid checking on the same token on every request. To initialize a Sand::Service instance is to provide the above options PLUS additional options below:

```
opts = {
  ... # Same as Sand::Client's options above
  token_verify_path: "/warden/token/allowed", # Required. The token verification endpoint
  resource:          "default:resource",      # This service's default resource name registered with the OAuth2 server

  # Below also shows their default values
  default_exp_time: 3600     # The default expiry time for cache for invalid tokens and also valid tokens without expiry times.
  scopes:           nil      # A string array. These are the scopes required to access the OAuth2 server's token verification endpoint
}
service = Sand::Service.new(opts)

# Usage Example with Rails request
begin
  result = service.check_request(request, resource: 'some:resource', scopes: ['target_scope1', 'target_scope2'], action: 'action', num_retry: 5)
  render status: service.access_denied_code if !result["allowed"]
rescue => e
  render status: service.error_code
end
```

### Client

Sand::Client has the `request` method which can perform retry when encountering 401 responses from the service. This should be the primary method to use for a client.

Both the Sand::Client and Sand::Service classes have the `token` method that gets an OAuth token from authentication service. If a cache store is available and the token is found in cache, it will return this token and not retrieving the token from the authentication service.

### Service

The Sand::Service class defines the `check_request` method for verifying a request with the authentication service on whether the client token from the request is allowed to communicate with this service. A client's token and the verification result will also be cached if the cache is available.

`check_request` returns a hash, say "result". If result["allowed"] is true, then result["sub"] is the subject who is making the request. If result["allowed"] is false, no other data will present.
