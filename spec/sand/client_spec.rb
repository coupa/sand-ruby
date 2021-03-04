require 'spec_helper'

describe Sand::Client do
  let(:client) { Sand::Client.new(client_id: 'a', client_secret: 'b', token_site: 'http://localhost', token_path: '/abc', default_retry_count: 2, cache: Sand::Memory.cache) }
  after{ client.cache.clear if client.cache }

  describe '#request' do
    let(:response) { 'good' }
    subject do
      client.request(cache_key: 'test') { |token| response }
    end
    before{ allow(client).to receive(:token).and_return('abc') }

    context 'with authorized response' do
      it 'returns the response' do
        allow(response).to receive(:status).and_return(200)
        expect(subject).to eq(response)

        allow(response).to receive(:code).and_return(200)
        expect(subject).to eq(response)
      end
    end

    context 'with unknown response code' do
      it 'returns the response' do
        expect(subject).to eq(response)
      end
    end

    context 'with unauthorized response' do
      before{ allow(response).to receive(:code).and_return(401) }

      context 'with retry' do
        it 'performs retry and returns 401 response' do
          expect(client).to receive(:sleep).exactly(2).times
          expect(subject.code).to eq(401)
        end
      end

      context 'with default retry set to 0' do
        subject do
          client.default_retry_count = 0
          client.request(cache_key: 'test') { |token| response }
        end
        it 'still performs retry once and returns 401 response' do
          expect(client).to receive(:sleep).exactly(1).times
          expect(subject.code).to eq(401)
        end
      end

      context 'with per-request retry' do
        subject do
          client.default_retry_count = 0
          client.request(cache_key: 'test', num_retry: 2) { |token| response }
        end
        it 'performs retry and returns 401 response' do
          expect(client).to receive(:sleep).exactly(2).times
          expect(subject.code).to eq(401)
        end
      end
    end
  end

  describe '#token' do
    let(:resource) { 'test' }
    subject{ client.token(cache_key: resource, scopes: ['scope']) }
    before{ allow(client).to receive(:oauth_token).and_return({access_token: 'retrieve_token', expires_in: 60}) }

    describe 'reading from cache' do
      before{ client.cache_write(client.cache_key('test', ['scope']), 'testToken', 0) }

      it 'uses the token from cache' do
        expect(client).not_to receive(:oauth_token)
        expect(subject).to eq('testToken')
      end

      context 'with resource not found in cache' do
        let(:resource) { 'not_test' }

        it 'retrieves the token from SAND' do
          expect(client).to receive(:oauth_token)
          expect(subject).not_to eq('testToken')
        end
      end
    end

    describe 'writing to cache' do
      it 'writes the token to cache' do
        expect(subject).to eq('retrieve_token')
        expect(client.cache_read(client.cache_key(resource, ['scope'], nil))).to eq('retrieve_token')
      end
    end

    context 'without cache' do
      before{ client.cache = nil }

      it 'gets the token from SAND' do
        expect(client).to receive(:oauth_token)
        expect(subject).to eq('retrieve_token')
      end

      context 'with an empty token' do
        before{ allow(client).to receive(:oauth_token).and_return({access_token: '', expires_in: 60}) }

        it 'gets the token from SAND' do
          expect(client).to receive(:oauth_token)
          expect{subject}.to raise_error(Sand::AuthenticationError)
        end
      end
    end
  end

  describe '#oauth_token' do
    context 'gets token successfully' do
      before { allow_any_instance_of(OAuth2::Strategy::ClientCredentials).to receive(:get_token).and_return(Token.new('token', 60)) }

      it 'returns token and expiry time' do
        expect_any_instance_of(OAuth2::Strategy::ClientCredentials).to receive(:get_token).with({scope: 'test scope'})
        t = client.oauth_token(scopes: ['test', 'scope'])
        expect(t[:access_token]).to eq('token')
        expect(t[:expires_in]).to eq(60)
      end
    end

    context 'on network error' do
      before { allow_any_instance_of(OAuth2::Strategy::ClientCredentials).to receive(:get_token).and_raise(StandardError) }

      context 'without retry' do
        it 'should raise error and not call sleep' do
          client.default_retry_count = 0
          expect(client).not_to receive(:sleep)
          expect{client.oauth_token}.to raise_error(Sand::AuthenticationError)
        end
      end

      context 'with retry' do
        it 'should call sleep and then raise error' do
          client.default_retry_count = 2
          expect(client).to receive(:sleep).exactly(2).times
          expect{client.oauth_token}.to raise_error(Sand::AuthenticationError)
        end
      end

      context 'with per-request retry' do
        it 'should call sleep and then raise error' do
          client.default_retry_count = 0
          expect(client).to receive(:sleep).exactly(3).times
          expect{client.oauth_token(num_retry: 3)}.to raise_error(Sand::AuthenticationError)
        end

        context 'with per-request retry set to 0' do
          it 'should not retry' do
            client.default_retry_count = 3
            expect(client).to receive(:sleep).exactly(0).times
            expect{client.oauth_token(num_retry: 0)}.to raise_error(Sand::AuthenticationError)
          end
        end

        context 'with per-request retry set to nil or a negative number' do
          it 'should default to default_retry_count for number of retries' do
            client.default_retry_count = 3
            expect(client).to receive(:sleep).exactly(3).times
            expect{client.oauth_token(num_retry: -1)}.to raise_error(Sand::AuthenticationError)
          end

          it 'should default to default_retry_count for number of retries' do
            client.default_retry_count = 3
            expect(client).to receive(:sleep).exactly(3).times
            expect{client.oauth_token(num_retry: nil)}.to raise_error(Sand::AuthenticationError)
          end
        end
      end
    end

    class Token
      attr_accessor :token, :expires_in
      def initialize(token, exp)
        @token = token
        @expires_in = exp
      end
    end
  end

  describe '#status_code' do
    it 'returns nil when given nil' do
      expect(client.send(:status_code, nil)).to be_nil
    end
  end
end
