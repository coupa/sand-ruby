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
    #   token_verify_path: Required. SAND's token allowed endpoint
    #   resource: This service's unique resource name registered with SAND
    #   default_exp_time: The default expiry time for cache for invalid tokens and also valid tokens without expiry times.
    #   scopes: The scopes required to access the token verification endpoint
    # }
    def initialize(opts = {})
      super
      @resource = opts.delete(:resource)
      @token_verify_path = opts.delete(:token_verify_path) { |o| raise ArgumentError.new("#{o} is required") }
      @default_exp_time = opts.delete(:default_exp_time) || 3600
      @scopes = opts.delete(:scopes)
      @context = opts.fetch(:context, default_context)
    end

    # This can be used for Rails' http request that has the bearer token in the
    # "Authorization" header. It will extract the token and check with SAND to
    # verify whether the token client is allowed to access this service.
    #
    # options[:num_retry]: Number of retries is defaulted to @default_retry_count unless options[:num_retry] is given
    # on a per request basis. For a service, num_retry is applied when it has problem
    # connecting to Sand for an access token. The token verificatioin
    # does not perform any retry.
    #
    # options[:scopes]: An array of scopes to check whether the client has permission to access
    #
    # options[:action]: A string to check if the client is allowed to perform
    #
    # Example code with Rails:
    #   begin
    #     result = sand_service.check_request(request, scopes: ['scope'], action: 'action', num_retry: 1)
    #     render status: sand_service.access_denied_code if !result["allowed"]
    #   rescue => e
    #     render status: sand_service.error_code    # This will set 502
    #   end
    def check_request(request, options = {})
      token = if request.respond_to?(:authorization)
        extract_token(request.authorization)
      elsif request.respond_to?(:headers) && request.headers.respond_to?(:key?) && request.headers.key?('HTTP_AUTHORIZATION')
        extract_token(request.headers['HTTP_AUTHORIZATION'])
      else
        raise AuthenticationError.new('Failed to extract token from the request')
      end

      begin
        return check_token(token, options)
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
    def check_token(token, options = {})
      token = token.to_s.strip
      return {'allowed' => false} if token.empty?

      # Check if cached
      ckey = cache_key(token, options[:scopes], resource: options[:resource], action: options[:action]) if @cache
      if ckey
        cached = @cache.read(ckey)
        return cached unless cached.nil?
      end

      resp = verify_token(token, options)
      # To ensure that allowed is true if and only if it is really true
      # If allowed is not true, make sure nothing else is included
      resp = {'allowed' => false} unless resp['allowed'] == true

      # Keep result in cache
      if ckey
        exp = resp['allowed'] ? expiry_time(resp['exp']) : @default_exp_time
        @cache.write(ckey, resp,
            expires_in: exp, race_condition_ttl: @race_ttl_in_secs)
      end

      resp
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
    def verify_token(token, options = {})
      token = token.to_s
      return {'allowed' => false} if token.empty?

      resource = options.fetch(:resource, @resource).to_s.strip
      raise ArgumentError.new("resource is required") if resource.empty?

      access_token = self.token(cache_key: 'service-access-token', scopes: @scopes, num_retry: options[:num_retry])
      data = {
        scopes: Array(options[:scopes]),
        token: token,
        resource: resource,
        action: options[:action].to_s,
        context: options.fetch(:context, @context),
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

    def default_context
      # TODO: Consider adding remoteIP?
      # See https://www.ory.sh/docs/guides/latest/1-hydra/2-overview/3-access-control
      {}
    end
  end
end
