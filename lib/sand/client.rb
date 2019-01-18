require 'oauth2'
require 'faraday'
require 'cgi'

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
    # options[:cache_key]: If options[:cache_key] is empty, the token WILL NOT BE CACHED
    #
    # options[:num_retry]: Specifying options[:num_retry] (>= 1) number of retries for this request call.
    # It cannot be 0 because in case of expired tokens, at least 1 retry is required.
    # options[:num_retry] < 1 will default to @default_retry_count, equivalent to not giving this option.
    # Retry delay increases expentially: 1, 2, 4, 8, 16,... seconds
    #
    # options[:scopes]: is an array of scope strings.
    #
    # # Example: this request will retry a maximum 2 times, 1 + 2 = 3 seconds
    # client.request(cache_key: 'cache-key', scopes: ['scope1', 'scope2'], num_retry: 2) do |token|
    #   # Make http request with net/http, Faraday, Httparty, etc...
    #   # with bearer token in the Authorization header
    #   # return the response
    # end
    def request(options = {}, &block)
      caching_key = options[:cache_key] || ''

      # request_retry_limit cannot be 0 or less, because if a client's token is
      # expired, it must retry at least once to get a fresh token and try the request
      # to service again
      request_retry_limit = options[:num_retry].to_i
      request_retry_limit = @default_retry_count if request_retry_limit < 1
      request_retry_limit = 1 if request_retry_limit < 1

      restClientError = nil
      t = self.token(options)
      resp = begin
        block.call(t)
      rescue => e
        # RestClient raises an error on all http error codes. RestClient errors
        # support the :response method
        # See "Exceptions" on https://github.com/rest-client/rest-client
        raise e if !e.respond_to?(:response) || status_code(e.response).nil?
        restClientError = e
        e.response
      end

      # Return response if we can't get the status code of the response
      if status_code(resp).nil?
        logger.warn("Sand request: unable to get the response code and return without retrying") if logger
        return resp
      end

      retry_count = 0
      # Set number of retry to 0 for the function that is getting the token, since
      # the retry is done here already. Otherwise if both functions are retrying,
      # it may lock up for a long time.
      options[:num_retry] = 0

      # Retry only when the status code is 401
      # Get a fresh token from authentication and retry
      while status_code(resp) == access_denied_code && retry_count < request_retry_limit do
        restClientError = nil
        secs = 2 ** retry_count
        logger.warn("Sand request: retrying after #{secs} sec on #{access_denied_code}") if logger
        sleep secs
        retry_count += 1

        # Prevent reading the token from cache
        @cache.delete(cache_key(caching_key, options[:scopes])) if @cache

        t = self.token(options)
        resp = begin
          block.call(t)
        rescue => e
          raise e if !e.respond_to?(:response) || status_code(e.response).nil?
          restClientError = e
          e.response
        end
        if status_code(resp).nil?
          logger.warn("Sand request: unable to get the response code and return without retrying") if logger
          return resp
        end
      end if request_retry_limit > 0

      # This retains the behavior of RestClient, which raises error on all http error codes.
      raise restClientError if restClientError
      resp
    end

    # caching_key will be used as the cache key for caching the token
    def token(options = {})
      ckey = nil
      caching_key = options.delete(:cache_key).to_s
      if @cache
        ckey = cache_key(caching_key, options[:scopes])
        token = @cache.read(ckey)
        return token unless token.nil?
      end
      hash = oauth_token(options)
      raise AuthenticationError.new('Invalid access token') if hash[:access_token].nil? || hash[:access_token].empty?

      if @cache && hash[:expires_in] >= 0
        #expires_in = 0 means no expiry limit
        @cache.write(ckey, hash[:access_token],
            expires_in: hash[:expires_in],
            race_condition_ttl: @race_ttl_in_secs)
      end
      hash[:access_token]
    end

    # If options[:num_retry] >= 0, it will retry up to that many times with exponential
    # backoff time of 1, 2, 4, 8, 16,... seconds
    # If options[:num_retry] is not present or < 0, it will use @default_retry_count as the retry number
    def oauth_token(options = {})
      retry_limit = options[:num_retry] && options[:num_retry].to_i >= 0 ? options[:num_retry].to_i : @default_retry_count

      # The 'auth_scheme' option is for oauth2 1.3.0 gem, but it will work for 1.2 since it's just an option
      client = OAuth2::Client.new(CGI.escape(@client_id), CGI.escape(@client_secret),
          site: @token_site, token_url: @token_path,
          ssl: {:verify => @skip_tls_verify != true},
          auth_scheme: :basic_auth)
      retry_count = 0
      begin
        token = client.client_credentials.get_token(scope: Array(options[:scopes]).join(' '))
        {access_token: token.token.to_s, expires_in: token.expires_in.to_i}
      rescue => e
        if retry_count < retry_limit
          secs = 2 ** retry_count
          logger.warn("Sand token: retrying after #{secs} sec due to error: #{e}") if logger
          sleep secs
          retry_count += 1
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
