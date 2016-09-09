module Sand
  class Base
    attr_accessor :client_id, :client_secret, :token_site, :token_path, :scopes,
        :race_ttl_in_secs, :skip_tls_verify, :max_retry, :cache, :cache_root

    # opts = {
    #   client_id: Required
    #   client_secret: Required
    #   token_site: Required
    #   token_path: Required
    #   scopes: A string of whitespace separated scopes
    #   skip_tls_verify: Skip verifying the TLS certificate
    #   max_retry: Maximum number of retries on connection error
    #   race_ttl_in_secs: Extended TTL for racing condition for cache
    #   cache: For example, Rails.cache
    #   cache_root: A string as the root namespace in the cache
    # }
    def initialize(opts = {})
      opts = opts.dup
      @client_id = opts.delete(:client_id) { |o| raise ArgumentError.new("#{o} is required") }
      @client_secret = opts.delete(:client_secret) { |o| raise ArgumentError.new("#{o} is required") }
      @token_site = opts.delete(:token_site) { |o| raise ArgumentError.new("#{o} is required") }
      @token_path = opts.delete(:token_path) { |o| raise ArgumentError.new("#{o} is required") }
      @scopes = opts.delete(:scopes) || ''
      @skip_tls_verify = opts.delete(:skip_tls_verify) || false
      @max_retry = opts.delete(:max_retry) || 5
      # Default race ttl to 10 seconds
      @race_ttl_in_secs = opts.delete(:race_ttl_in_secs) || 10
      # If @cache is nil, there will be no caching of tokens.
      @cache = opts.delete(:cache)
      @cache_root = opts.delete(:cache_root) || 'sand'
    end

    def self.cache_name
      raise NotImplementedError
    end

    def cache_key(key)
      [@cache_root, self.class.cache_name] + Array(key)
    end
  end
end
