require 'spec_helper'
require 'time'

describe Sand::Service do
  RSpec.shared_examples 'a valid sand service' do
    let(:body) { '' }
    before{ allow_any_instance_of(Faraday::Connection).to receive(:post).and_return(Response.new(body)) }

    context 'token allowed' do
      let(:body) { {'allowed' => 'yes', 'sub' => 'test'}.to_json }

      it 'returns the parsed response body as a hash' do
        expect(subject['allowed']).to eq('yes')
        expect(subject['sub']).to eq('test')
      end
    end

    context 'malformed response' do
      let(:body) { 'not json format' }

      it 'raises JSON parse error' do
        expect{subject}.to raise_error(JSON::ParserError)
      end
    end

    context 'error response' do
      before{ allow_any_instance_of(Faraday::Connection).to receive(:post).and_return(Response.new(body, 502)) }

      it 'raises authentication error' do
        expect{subject}.to raise_error(Sand::AuthenticationError)
      end
    end

    class Response
      attr_accessor :body, :status
      def initialize(body, status = 200)
        @body = body
        @status = status
      end
    end
  end

  let(:service_client_id) { 'a' }
  let(:service_client_secret) { 'b' }
  let(:service_token_site) { 'http://localhost' }
  let(:service_token_path) { '/abc' }
  let(:service_resource) { 'cers' }
  let(:service_token_verify_path) { '/verify/token' }
  let(:service_cache) { Sand::Memory.cache }
  let(:service) do
    Sand::Service.new(
      client_id: service_client_id,
      client_secret: service_client_secret,
      token_site: service_token_site,
      token_path: service_token_path,
      resource: service_resource,
      token_verify_path: service_token_verify_path,
      cache: service_cache,
    )
  end

  before { allow(service).to receive(:token).and_return("fake_token") }
  after { service.cache.clear if service.cache }

  describe '#check_request' do
    let(:request) { {} }
    subject{ service.check_request(request) }
    before{ allow(service).to receive(:verify_token).and_return({'allowed' => true}) }

    context 'with request responds to authorization method' do
      context 'with valid bearer token' do
        before{ allow(request).to receive(:authorization).and_return('Bearer ABCD') }

        it 'should return true' do
          expect(subject['allowed']).to be(true)
        end
      end

      describe 'case-insensitive bearer keyword' do
        before{ allow(request).to receive(:authorization).and_return('bearer ABCD') }

        it 'should return true' do
          expect(subject['allowed']).to be(true)
        end
      end

      context 'with invalid bearer token' do
        before{ allow(request).to receive(:authorization).and_return('ABCD') }

        it 'should return false because token extracted is empty' do
          expect(subject['allowed']).to be(false)
        end
      end

      context 'with a blank token' do
        before{ allow(request).to receive(:authorization).and_return('') }

        it 'should return false because token extracted is empty' do
          expect(subject['allowed']).to be(false)
        end
      end
    end

    context 'with request responds to headers method' do
      context 'with authorization header and valid bearer token' do
        before{ allow(request).to receive(:headers).and_return({'HTTP_AUTHORIZATION' => 'Bearer ABCD'}) }

        it 'should return true' do
          expect(subject['allowed']).to be(true)
        end
      end

      context 'without authorization header' do
        before{ allow(request).to receive(:headers).and_return({}) }

        it 'should raise an exception' do
          expect{subject}.to raise_error(Sand::AuthenticationError, 'Failed to extract token from the request')
        end
      end
    end

    context 'without any authorization header method' do
      it 'should raise an exception' do
        expect{subject}.to raise_error(Sand::AuthenticationError, 'Failed to extract token from the request')
      end
    end
  end

  describe '#extract_token' do
    let(:auth_header) { 'Bearer ABCD' }
    subject{ service.extract_token(auth_header) }

    context 'with valid bearer token' do
      it 'returns the token' do
        expect(subject).to eq('ABCD')
      end
    end

    context 'without bearer token' do
      let(:auth_header) { 'Bear ABCD' }

      it 'returns nil' do
        expect(subject).to be_nil
      end
    end

    context 'without the token' do
      let(:auth_header) { 'Bearer ' }

      it 'returns nil' do
        expect(subject).to be_nil
      end
    end

    context 'case-insensitive bearer keyword' do
      let(:auth_header) { 'bearer ABCD' }

      it 'returns the token' do
        expect(subject).to eq('ABCD')
      end
    end
  end

  describe '#check_token' do
    let(:token) { 'testToken' }
    subject{ service.check_token(token, scopes: ['scope']) }
    before { allow(service).to receive(:verify_token) }

    context 'token is empty' do
      let(:token) { nil }

      it 'returns false ' do
        expect(subject['allowed']).to eq(false)
      end
    end

    context 'Sand responds with 500' do
      before { allow(service).to receive(:verify_token).and_return(nil) }

      it 'returns allowed => false without caching' do
        expect(service.cache).to receive(:read)
        expect(service.cache).not_to receive(:write)
        expect(subject).to eq('allowed' => false)
      end
    end

    context 'Sand responds with 401' do
      before { allow(service).to receive(:verify_token).and_raise(Sand::ServiceUnauthorizedError) }

      it 'retries once more' do
        expect(service).to receive(:verify_token).twice
        expect(service.cache).to receive(:read)
        expect(service.cache).not_to receive(:write)
        expect(service.cache).to receive(:delete)
        expect{subject}.to raise_error(Sand::ServiceUnauthorizedError)
      end
    end

    describe 'cache operations' do
      context 'token and result already cached' do
        it 'gets the result from cache' do
          service.cache_write(service.cache_key(token, ['scope'], nil), {'allowed' => true, 'sub' => 'test'}, 0)
          expect(service).not_to receive(:verify_token)
          expect(subject['allowed']).to be(true)
          expect(subject['sub']).to eq('test')
        end
      end

      context 'uncached token' do
        before{ allow(service).to receive(:verify_token).and_return('allowed' => false) }

        it 'caches token verification result' do
          expect(service.cache_read(service.cache_key(token, ['scope'], nil))).to be_nil
          expect(subject['allowed']).to be(false)
          expect(service.cache_read(service.cache_key(token, ['scope'], nil))).to eq({'allowed' => false})
        end
      end

      describe 'expiry time' do
        let(:response) { {} }
        before{ allow(service).to receive(:verify_token).and_return(response) }

        context 'token is allowed with exp time' do
          let(:response) { {'allowed' => true, 'exp' => (Time.now + (service.default_exp_time + 3600)).iso8601} }

          it 'will compute the expiry time' do
            expect(service).to receive(:expiry_time)
            expect(subject['allowed']).to be(true)
          end
        end

        context 'token is allowed without exp time' do
          let(:response) { {'allowed' => true} }

          it 'will use the default expiry time' do
            expect(service).to receive(:expiry_time)
            expect(subject['allowed']).to be(true)
          end
        end

        context 'token is not allowed' do
          let(:response) { {'allowed' => false} }

          it 'will use the default expiry time' do
            expect(service).not_to receive(:expiry_time)
            expect(subject['allowed']).to be(false)
          end
        end

        context 'without allowed response' do
          let(:response) { {} }

          it 'will use the default expiry time' do
            expect(service).not_to receive(:expiry_time)
            expect(subject['allowed']).to be(false)
          end
        end

        context 'with invalid allowed response' do
          let(:response) { {'allowed' => 'hello'} }

          it 'will use the default expiry time' do
            expect(service).not_to receive(:expiry_time)
            expect(subject['allowed']).to be(false)
          end
        end
      end
    end

    context 'without cache' do
      before do
        service.cache = nil
        allow(service).to receive(:verify_token).and_return('allowed' => true, 'sub' => 'test')
        expect(service).to receive(:verify_token)
      end

      it 'gets the token from SAND' do
        expect(subject['allowed']).to be(true)
        expect(subject['sub']).to eq('test')
      end

      context 'and allowed is false' do
        before{ allow(service).to receive(:verify_token).and_return('allowed' => false, 'sub' => 'test') }

        it 'should not include subject' do
          expect(subject['allowed']).to be(false)
          expect(subject['sub']).to be_nil
        end
      end
    end
  end

  describe '#verify_token' do
    let(:token) { 'testToken' }
    subject{ service.verify_token(token) }

    context 'token is empty' do
      let(:token) { nil }

      it 'returns allowed is false ' do
        expect(subject['allowed']).to eq(false)
      end
    end

    it_behaves_like 'a valid sand service'

    context 'service does not have a default resource' do
      let(:service_resource) { nil }

      context 'and resource was not given' do
        it 'should raise an ArgumentError' do
          expect { subject }.to raise_error(ArgumentError)
        end
      end

      context 'and resource is passed' do
        subject { service.verify_token(token, resource: 'b') }

        it_behaves_like 'a valid sand service'
      end
    end

    context 'Sand responds with 500' do
      let(:body) { '' }
      before{ allow_any_instance_of(Faraday::Connection).to receive(:post).and_return(Response.new(body, 500)) }

      it 'returns nil' do
        expect(subject).to be_nil
      end
    end

    context 'Sand responds with 401' do
      let(:body) { '' }
      before { allow_any_instance_of(Faraday::Connection).to receive(:post).and_return(Response.new(body, 401)) }

      it 'raises an error' do
        expect{subject}.to raise_error(Sand::ServiceUnauthorizedError)
      end
    end
  end

  describe '#expiry_time' do
    let(:str_time) { Time.now.iso8601 }
    subject{ service.expiry_time(str_time) }

    context 'with future expiry time' do
      let(:str_time) { (Time.now + 1000).iso8601 }

      it 'returns expiry time that is not the default' do
        expect(subject).not_to eq(service.default_exp_time)
      end
    end

    context 'with expiry time that is passed' do
      let(:str_time) { (Time.now - 10).iso8601 }

      it 'returns the default expiry time' do
        expect(subject).to eq(service.default_exp_time)
      end
    end

    context 'with unparsable time' do
      let(:str_time) { 'abc' }

      it 'returns the default expiry time' do
        expect(subject).to eq(service.default_exp_time)
      end
    end
  end
end
