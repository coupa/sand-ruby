require 'faraday'
require 'json'
require 'time'

module Sand
  class Service < Client
    attr_accessor :resource, :token_verify_path, :target_scopes, :default_exp_time

    def self.cache_type
      'tokens'
    end

    # opts = {
    #   resource: Required. This service's unique resource name registered with SAND
    #   token_verify_path: SAND's token allowed endpoint
    #   target_scopes: A string of whitespace separated scopes. Scopes that this service require its clients to be in.
    #   default_exp_time: The default expiry time for cache for invalid tokens and also valid tokens without expiry times.
    # }
    def initialize(opts = {})
      super
      @resource = opts.delete(:resource) { |o| raise ArgumentError.new("#{o} is required") }
      @token_verify_path = opts.delete(:token_verify_path) { |o| raise ArgumentError.new("#{o} is required") }
      @target_scopes = opts.delete(:target_scopes) || ''
      @default_exp_time = opts.delete(:default_exp_time) || 3600
    end

    # This can be used for Rails' http request that has the bearer token in the
    # "Authorization" header. It will extract the token and check with SAND to
    # verify whether the token client is allowed to access this service.
    def check_request(request, action = 'any')
      token = if request.respond_to?(:authorization)
        extract_token(request.authorization)
      elsif request.respond_to?(:headers) && request.headers.key?('HTTP_AUTHORIZATION')
        extract_token(request.headers['HTTP_AUTHORIZATION'])
      else
        nil
      end
      token ? token_allowed?(token, action) : false
    end

    # Checks with SAND about whether the token is allowed to access this service.
    # The token and the result will be cached up to @default_exp_time
    def token_allowed?(token, action = 'any')
      return false if token.to_s.strip.empty?
      if @cache
        cached = @cache.read(cache_key(token))
        # The token is allowed iff the value is true
        return cached == true unless cached.nil?
      end
      resp = verify_token(token, action)
      if @cache
        if resp['allowed'] == true
          @cache.write(cache_key(token), true,
              expires_in: expiry_time(resp['exp']), race_condition_ttl: @race_ttl_in_secs)
        else
          @cache.write(cache_key(token), false,
              expires_in: @default_exp_time, race_condition_ttl: @race_ttl_in_secs)
        end
      end
      resp['allowed'] == true
    end

    # Returns the token verification response body as a hash
    # Sample allowed response:
    #   {"sub":"client",
    #     "scopes":["myscope"],
    #     "iss":"hydra.localhost",
    #     "aud":"the-service",
    #     "iat":"2016-09-06T07:32:59.71-07:00",
    #     "exp":"2016-09-06T08:32:59.71-07:00",
    #     "ext":null,
    #     "allowed":true}
    #
    # Not allowed response:
    #   {"allowed":false}
    def verify_token(token, action = 'any')
      return {'allowed' => false} if token.to_s.strip.empty?
      # retry_on_error is false because service does not retry token verification
      access_token = token('service_access_token', false)
      data = {
        scopes: @target_scopes.to_s.split,
        token: token,
        resource: @resource,
        action: action,
        context: {},
      }
      conn = Faraday.new(url: @token_site) do |faraday|
        faraday.ssl.verify = false if @skip_tls_verify == true
        faraday.adapter(Faraday.default_adapter)
      end
      conn.authorization(:Bearer, access_token)
      resp = conn.post do |req|
        req.url @token_verify_path
        req.headers['Content-Type'] = 'application/json'
        req.body = data.to_json
      end
      JSON.parse(resp.body)
    end

    # Extract token from the value of authorization header with bearer.
    # E.g., "Bearer khh8h3o1298yu9183aiuwhasdf"
    def extract_token(authorization_header)
      values = authorization_header.to_s.split
      return nil if values.length < 2
      values[0].downcase == 'bearer' ? values[1] : nil
    end

    # SAND's sample response time: {"exp":"2016-09-06T08:32:59.71-07:00"}
    def expiry_time(str_time)
      exp = Time.parse(str_time)
      expires_in = exp.to_i - Time.now.to_i
      return expires_in if expires_in > 0
      @default_exp_time
    rescue
      @default_exp_time
    end
  end
end
