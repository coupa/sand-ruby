require 'spec_helper'
require 'time'

describe Sand::Service do
  let(:service) { Sand::Service.new(client_id: 'a', client_secret: 'b', token_site: 'http://localhost', token_path: '/abc', resource: 'cers', token_verify_path: '/verify/token', cache: Sand::Memory.cache) }

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
          expect(subject).to be(true)
        end
      end

      describe 'case-insensitive bearer keyword' do
        before{ allow(request).to receive(:authorization).and_return('bearer ABCD') }

        it 'should return true' do
          expect(subject).to be(true)
        end
      end

      context 'with invalid bearer token' do
        before{ allow(request).to receive(:authorization).and_return('ABCD') }

        it 'should return false because token extracted is empty' do
          expect(subject).to be(false)
        end
      end

      context 'with a blank token' do
        before{ allow(request).to receive(:authorization).and_return('') }

        it 'should return false because token extracted is empty' do
          expect(subject).to be(false)
        end
      end
    end

    context 'with request responds to headers method' do
      context 'with authorization header and valid bearer token' do
        before{ allow(request).to receive(:headers).and_return({'HTTP_AUTHORIZATION' => 'Bearer ABCD'}) }

        it 'should return true' do
          expect(subject).to be(true)
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

  describe '#token_allowed?' do
    let(:token) { 'testToken' }
    subject{ service.token_allowed?(token, ['scope']) }
    before { allow(service).to receive(:verify_token) }

    context 'token is empty' do
      let(:token) { nil }

      it 'returns false ' do
        expect(subject).to eq(false)
      end
    end

    describe 'cache operations' do
      context 'token and result already cached' do
        it 'gets the result from cache' do
          service.cache.write(service.cache_key(token, ['scope']), true)
          expect(service).not_to receive(:verify_token)
          expect(subject).to be(true)
        end
      end

      context 'uncached token' do
        before{ allow(service).to receive(:verify_token).and_return('allowed' => false) }

        it 'caches token verification result' do
          expect(service.cache.read(service.cache_key(token, ['scope']))).to be_nil
          expect(subject).to be(false)
          expect(service.cache.read(service.cache_key(token, ['scope']))).to be(false)
        end
      end

      describe 'expiry time' do
        let(:response) { {} }
        before{ allow(service).to receive(:verify_token).and_return(response) }

        context 'token is allowed with exp time' do
          let(:response) { {'allowed' => true, 'exp' => (Time.now + (service.default_exp_time + 3600)).iso8601} }

          it 'will compute the expiry time' do
            expect(service).to receive(:expiry_time)
            expect(subject).to be(true)
          end
        end

        context 'token is allowed without exp time' do
          let(:response) { {'allowed' => true} }

          it 'will use the default expiry time' do
            expect(service).to receive(:expiry_time)
            expect(subject).to be(true)
          end
        end

        context 'token is not allowed' do
          let(:response) { {'allowed' => false} }

          it 'will use the default expiry time' do
            expect(service).not_to receive(:expiry_time)
            expect(subject).to be(false)
          end
        end

        context 'without allowed response' do
          let(:response) { {} }

          it 'will use the default expiry time' do
            expect(service).not_to receive(:expiry_time)
            expect(subject).to be(false)
          end
        end

        context 'with invalid allowed response' do
          let(:response) { {'allowed' => 'hello'} }

          it 'will use the default expiry time' do
            expect(service).not_to receive(:expiry_time)
            expect(subject).to be(false)
          end
        end
      end
    end

    context 'without cache' do
      before do
        service.cache = nil
        allow(service).to receive(:verify_token).and_return('allowed' => true)
      end

      it 'gets the token from SAND' do
        expect(service).to receive(:verify_token)
        expect(subject).to be(true)
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

    describe 'difference cases of response' do
      let(:body) { '' }
      before{ allow_any_instance_of(Faraday::Connection).to receive(:post).and_return(Response.new(body)) }

      context 'token allowed' do
        let(:body) { {allowed: 'yes'}.to_json }

        it 'returns the parsed response body as a hash' do
          expect(subject['allowed']).to eq('yes')
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
