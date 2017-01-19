require 'faraday'
require 'json'
require 'time'

module Sand
  class Service < Client
    attr_accessor :resource, :token_verify_path, :default_exp_time, :scopes

    def self.cache_type
      'tokens'
    end

    # opts = {
    #   resource: Required. This service's unique resource name registered with SAND
    #   token_verify_path: SAND's token allowed endpoint
    #   default_exp_time: The default expiry time for cache for invalid tokens and also valid tokens without expiry times.
    #   scopes: The scopes required to access the token verification endpoint
    # }
    def initialize(opts = {})
      super
      @resource = opts.delete(:resource) { |o| raise ArgumentError.new("#{o} is required") }
      @token_verify_path = opts.delete(:token_verify_path) { |o| raise ArgumentError.new("#{o} is required") }
      @default_exp_time = opts.delete(:default_exp_time) || 3600
      @scopes = opts.delete(:scopes) || ''
    end

    # This can be used for Rails' http request that has the bearer token in the
    # "Authorization" header. It will extract the token and check with SAND to
    # verify whether the token client is allowed to access this service.
    # Example code with Rails:
    #   begin
    #     allowed = sand_service.check_request(request, 'action')
    #     render status: sand_service.access_denied_code if !allowed
    #   rescue => e
    #     render status: sand_service.error_code    # This will set 502
    #   end
    def check_request(request, target_scopes = '', action = '')
      token = if request.respond_to?(:authorization)
        extract_token(request.authorization)
      elsif request.respond_to?(:headers) && request.headers.respond_to?(:key?) && request.headers.key?('HTTP_AUTHORIZATION')
        extract_token(request.headers['HTTP_AUTHORIZATION'])
      else
        raise AuthenticationError.new('Failed to extract token from the request')
      end
      begin
        return token_allowed?(token, target_scopes, action)
      rescue => e
        if logger
          logger.error(e.message)
          logger.error(e.backtrace[0..15].join("\n"))
        end
        raise AuthenticationError.new('Service failed to verify the token')
      end
    end

    # Checks with SAND about whether the token is allowed to access this service.
    # The token and the result will be cached up to @default_exp_time
    def token_allowed?(token, target_scopes = '', action = '')
      token = token.to_s.strip
      return false if token.empty?
      if @cache
        cached = @cache.read(cache_key(token))
        # The token is allowed iff the value is true
        return cached == true unless cached.nil?
      end
      resp = verify_token(token, target_scopes, action)
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
    def verify_token(token, target_scopes = '', action = '')
      token = token.to_s
      return {'allowed' => false} if token.empty?

      access_token = self.token('service-access-token', @scopes)
      data = {
        scopes: target_scopes.to_s.split,
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
      raise AuthenticationError.new("Error response from the authentication service: #{resp.status}") if resp.status != 200
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
