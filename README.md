# sand-ruby
A Ruby client library for service authentication via OAuth2.

## Features

* The authentication is done using the "client credentials" grant type in OAuth2.
* The tokens are cached on both the client and the service sides. The cache store is configurable to use a cache store like Rails.cache.

## Instruction

To initialize a Sand::Client instance is to provide the following configuration to the constructor:

```
opts = {
  client_id: "abcd",                 # Required
  client_secret: "defg",             # Required
  token_site: "https://example.com", # Required
  token_path: "/oauth2/token",       # Required
  scopes: "",             # A string of whitespace separated scopes
  skip_tls_verify: false, # Skip verifying the TLS certificate
  max_retry: 5,           # Maximum number of retries on connection error
  race_ttl_in_secs: 10,   # Extended TTL for racing condition for cache
  cache: nil,             # For example, Rails.cache
  cache_root: "sand",     # A string as the root namespace in the cache
}
client = Sand::Client.new(opts)
token = client.get_token("some-service")
```

To initialize a Sand::Service instance is to provide the above options PLUS additional options below:

```
opts = {
  ... # Same as Sand::Client's options above
  resource: "some-service",  # Required. This service's unique resource name registered with the authentication service
  token_verify_path: "/warden/token/allowed", # The token verification endpoint
  target_scopes: "",         # A string of whitespace separated scopes. Scopes that this service require its clients to be in.
  default_exp_time: 3600     # The default expiry time for cache for invalid tokens and also valid tokens without expiry times.

}
service = Sand::Service.new(opts)
allowed = service.token_allowed?(some_token)
```

### Client

Both the Sand::Client and Sand::Service classes have the `get_token` method that gets an OAuth token from authentication service. If a cache store is available and the token is found in cache, it will return this token and not retrieving the token from the authentication service.

### Service

The Sand::Service class defines the `token_allowed?` method for verifying with the authentication service on whether the client token from the request is allowed to communicate with this service. A client's token and the verification result will also be cached if the cache is available.
