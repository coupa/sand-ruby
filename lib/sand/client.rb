require 'oauth2'
require 'faraday'

module Sand
  class Client < Base

    def self.cache_type
      'resources'
    end

    # resource_key will be used as the cache key for caching the token
    def token(resource_key, retry_on_error = true)
      raise ArgumentError.new('resource_key cannot be empty') if resource_key.to_s.strip.empty?
      if @cache
        token = @cache.read(cache_key(resource_key))
        return token unless token.nil?
      end
      hash = oauth_token(retry_on_error)
      raise TokenIsEmptyError.new('Received a blank access token') if hash[:access_token].empty?

      if @cache && hash[:expires_in] >= 0
        #expires_in = 0 means no expiry limit
        @cache.write(cache_key(resource_key), hash[:access_token],
            expires_in: hash[:expires_in],
            race_condition_ttl: @race_ttl_in_secs)
      end
      hash[:access_token]
    end

    # If retry_on_error is true, it will retry up to @max_retry times with exponential
    # backoff time of 1, 2, 4, 8, 16,... seconds
    def oauth_token(retry_on_error = true)
      client = OAuth2::Client.new(@client_id, @client_secret,
          :site => @token_site, token_url: @token_path, :ssl => {:verify => @skip_tls_verify != true})
      num_retry = 0
      begin
        token = client.client_credentials.get_token(scope: @scopes)
        {access_token: token.token.to_s, expires_in: token.expires_in.to_i}
      rescue Faraday::ConnectionFailed, Faraday::ResourceNotFound, Faraday::TimeoutError => e
        raise e unless retry_on_error
        if num_retry < @max_retry
          sleep 2 ** num_retry
          num_retry += 1
          retry
        end
        raise e
      end
    end
  end
end
