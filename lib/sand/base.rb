module Sand
  class Base
    attr_accessor :client_id, :client_secret, :token_site, :token_path,
        :race_ttl_in_secs, :skip_tls_verify, :default_retry_count, :cache, :cache_root, :logger

    # opts = {
    #   client_id: Required
    #   client_secret: Required
    #   token_site: Required
    #   token_path: Required
    #   skip_tls_verify: Skip verifying the TLS certificate
    #   default_retry_count: Default number of retries on connection error
    #   max_retry: Deprecated. Same as :default_retry_count.
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
      @skip_tls_verify = opts.delete(:skip_tls_verify) || false
      # Support :max_retry for backward compatibility
      @default_retry_count = opts.delete(:default_retry_count) || opts.delete(:max_retry) || 5
      # Default race ttl to 10 seconds
      @race_ttl_in_secs = opts.delete(:race_ttl_in_secs) || 10
      # If @cache is nil, there will be no caching of tokens.
      @cache = opts.delete(:cache)
      @cache_root = opts.delete(:cache_root) || 'sand'
      @logger = opts.delete(:logger)
    end

    def self.cache_type
      raise NotImplementedError
    end

    def cache_key(key, scopes, opts = {})
      ret = @cache_root.dup
      ret << '/' << self.class.cache_type

      key = key.to_s.strip
      ret << '/' << key unless key.empty?

      scopes = Array(scopes)
      unless scopes.empty?
        scopes.sort!
        ret << '/' << scopes.join('_')
      end

      if opts.is_a? Hash
        ret << '/' << opts[:resource] if opts.key?(:resource) && !opts[:resource].to_s.empty?
        ret << '/' << opts[:action] if opts.key?(:action) && !opts[:action].to_s.empty?
      end

      ret
    end

    # When services successfully check tokens with authentication service but the
    # token is denied access, they must use this method to set the response code.
    def access_denied_code
      401
    end

    # When services raise error when checking a request's token, they must use
    # this method to set the response code.
    def error_code
      502
    end
  end
end
