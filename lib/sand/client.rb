require 'oauth2'
require 'faraday'

module Sand
  class Client < Base

    def self.cache_type
      'resources'
    end

    # Wraps around an HTTP request with authentication to the OAuth2 server, and
    # then performs the HTTP request. It then inspects the status code of the HTTP
    # response. If it is 401, it performs retry by getting a new token from the
    # OAuth2 server.
    #
    # block should perform normal HTTP request and returns a response. The response
    # needs to respond to :status (Faraday) or :code (net/http and Httparty)
    #
    # client.request('some-service') do |token|
    #   # Make http request with net/http, Faraday, Httparty, etc...
    #   # with bearer token in the Authorization header
    #   # return the response
    # end
    def request(resource_key, &block)
      restClientError = nil
      t = self.token(resource_key)
      resp = begin
        block.call(t)
      rescue => e
        # RestClient raises an error on all http error codes. RestClient errors
        # support the :response method
        # See "Exceptions" on https://github.com/rest-client/rest-client
        raise e unless e.respond_to?(:response)
        restClientError = e
        e.response
      end

      if status_code(resp).nil?
        raise UnsupportedResponseError.new("Response unsupported: #{resp}")
      end
      num_retry = 0
      # Retry only when the status code is 401
      # Get a fresh token from authentication and retry
      while status_code(resp) == access_denied_code && num_retry < @max_retry do
        restClientError = nil
        secs = 2 ** num_retry
        @logger.warn("Sand request: retrying after #{secs} sec on #{access_denied_code}") if @logger
        sleep secs
        num_retry += 1

        # Prevent reading the token from cache
        @cache.delete(cache_key(resource_key)) if @cache
        t = self.token(resource_key)
        resp = begin
          block.call(t)
        rescue => e
          raise e unless e.respond_to?(:response)
          restClientError = e
          e.response
        end
      end if @max_retry > 0

      # This retains the behavior of RestClient, which raises error on all http error codes.
      raise restClientError if restClientError
      resp
    end

    # resource_key will be used as the cache key for caching the token
    def token(resource_key)
      resource_key = resource_key.to_s
      if @cache && !resource_key.empty?
        token = @cache.read(cache_key(resource_key))
        return token unless token.nil?
      end
      hash = oauth_token
      raise AuthenticationError.new('Invalid access token') if hash[:access_token].nil? || hash[:access_token].empty?

      if @cache && !resource_key.empty? && hash[:expires_in] >= 0
        #expires_in = 0 means no expiry limit
        @cache.write(cache_key(resource_key), hash[:access_token],
            expires_in: hash[:expires_in],
            race_condition_ttl: @race_ttl_in_secs)
      end
      hash[:access_token]
    end

    # If @max_retry > 0, it will retry up to @max_retry times with exponential
    # backoff time of 1, 2, 4, 8, 16,... seconds
    def oauth_token
      client = OAuth2::Client.new(@client_id, @client_secret,
          :site => @token_site, token_url: @token_path, :ssl => {:verify => @skip_tls_verify != true})
      num_retry = 0
      begin
        token = client.client_credentials.get_token(scope: @scopes)
        {access_token: token.token.to_s, expires_in: token.expires_in.to_i}
      rescue => e
        if num_retry < @max_retry
          secs = 2 ** num_retry
          @logger.warn("Sand token: retrying after #{secs} sec due to error: #{e}") if @logger
          sleep secs
          num_retry += 1
          retry
        end
        raise AuthenticationError.new(e)
      end
    end

  protected

    def status_code(resp)
      if resp.respond_to? :status
        resp.status
      elsif resp.respond_to? :code
        resp.code
      else
        nil
      end
    end
  end
end
