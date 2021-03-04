module Sand
  class Base
    attr_accessor :client_id, :client_secret, :token_site, :token_path,
        :ssl_min_version, :default_retry_count, :cache, :cache_root, :logger

    # opts = {
    #   client_id: Required
    #   client_secret: Required
    #   token_site: Required
    #   token_path: Required
    #   ssl_min_version: Minimum TLS version supported. For Faraday >= v1.0, the value should be like :TLS1_2. For Faraday < v1.0, the value should be :TLSv1_2
    #   default_retry_count: Default number of retries on connection error
    #   max_retry: Deprecated. Same as :default_retry_count.
    #   cache: For example, Rails.cache
    #   cache_root: A string as the root namespace in the cache
    # }
    def initialize(opts = {})
      opts = opts.dup
      @client_id = opts.delete(:client_id) { |o| raise ArgumentError.new("#{o} is required") }
      @client_secret = opts.delete(:client_secret) { |o| raise ArgumentError.new("#{o} is required") }
      @token_site = opts.delete(:token_site) { |o| raise ArgumentError.new("#{o} is required") }
      @token_path = opts.delete(:token_path) { |o| raise ArgumentError.new("#{o} is required") }
      # Support :max_retry for backward compatibility
      @default_retry_count = (opts.delete(:default_retry_count) || opts.delete(:max_retry) || 5).to_i
      # If @cache is nil, there will be no caching of tokens.
      @cache = opts.delete(:cache)
      @cache_root = opts.delete(:cache_root) || 'sand'
      @logger = opts.delete(:logger)
      @ssl_min_version = opts.delete(:ssl_min_version)

      # Faraday < 1.0 has :version in SSLOptions class, with value like :TLSv1_2
      # >= 1.0 has :min_version with value like :TLS1_2
      o = Faraday::SSLOptions.new
      if o.respond_to?(:min_version)
        @faraday_ssl_version_key = :min_version
        @ssl_min_version ||= :TLS1_2
      else
        @faraday_ssl_version_key = :version
        @ssl_min_version ||= :TLSv1_2
      end
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
        scopes = scopes.sort
        ret << '/' << scopes.join('_')
      end

      if opts.is_a? Hash
        ret << '/' << opts[:resource] if opts.key?(:resource) && !opts[:resource].to_s.empty?
        ret << '/' << opts[:action] if opts.key?(:action) && !opts[:action].to_s.empty?
      end

      ret
    end

    # Wrap the cache read/write methods to add the expiration timestamp, in case
    # some cache stores do not support expires_in
    def cache_read(key)
      return nil if cache.nil?

      hash = cache.read(key)
      return nil if hash.nil?

      expiry = hash[:expiry_epoch_sec]
      # Use <= because it may take time for the service to verify a token.
      # If expiry is 0, per cache store implementation it means caching forever
      if expiry > 0 && expiry <= Time.now.to_i
        cache.delete(key)
        return nil
      end
      return hash[:data]
    end

    # Wrap the cache read/write methods to add the expiration timestamp, in case
    # some cache stores do not support expires_in
    def cache_write(key, payload, expires_in_sec)
      return if cache.nil?

      expires_in_sec = expires_in_sec.to_i
      expires_in_sec = 0 if expires_in_sec < 0

      data = {
        data: payload,
        expiry_epoch_sec: expires_in_sec == 0 ? 0 : Time.now.to_i + expires_in_sec
      }
      cache.write(key, data, expires_in: expires_in_sec)
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
