require 'spec_helper'

describe Sand::Client do
  let(:client) { Sand::Client.new(client_id: 'a', client_secret: 'b', token_site: 'http://localhost', token_path: '/abc', max_retry: 2, cache: Sand::Memory.cache) }
  after{ client.cache.clear if client.cache }

  describe '#token' do
    let(:resource) { 'test' }
    subject{ client.token(resource) }
    before{ allow(client).to receive(:oauth_token).and_return({access_token: 'retrieve_token', expires_in: 60}) }

    context 'resource is empty' do
      let(:resource) { nil }

      it 'raises error ' do
        expect{subject}.to raise_error(ArgumentError)
      end
    end

    describe 'reading from cache' do
      before{ client.cache.write(client.cache_key('test'), 'testToken') }

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
        expect(client.cache.read(client.cache_key(resource))).to eq('retrieve_token')
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
          expect{subject}.to raise_error(Sand::TokenIsEmptyError)
        end
      end
    end
  end

  describe '#oauth_token' do
    context 'gets token successfully' do
      before { allow_any_instance_of(OAuth2::Strategy::ClientCredentials).to receive(:get_token).and_return(Token.new('token', 60)) }

      it 'returns token and expiry time' do
        t = client.oauth_token(false)
        expect(t[:access_token]).to eq('token')
        expect(t[:expires_in]).to eq(60)
      end
    end

    context 'on non-network error' do
      before { allow_any_instance_of(OAuth2::Strategy::ClientCredentials).to receive(:get_token).and_raise(StandardError) }

      it 'should raise error and not call sleep with retry_on_error off' do
        expect(client).not_to receive(:sleep)
        expect{client.oauth_token(false)}.to raise_error(StandardError)
      end

      it 'should raise error and not call sleep with retry_on_error on' do
        expect(client).not_to receive(:sleep)
        expect{client.oauth_token(true)}.to raise_error(StandardError)
      end
    end

    context 'on network error' do
      before { allow_any_instance_of(OAuth2::Strategy::ClientCredentials).to receive(:token).and_raise(Faraday::ConnectionFailed.new('ex')) }

      context 'without retry_on_error' do
        it 'should raise error and not call sleep' do
          expect(client).not_to receive(:sleep)
          expect{client.oauth_token(false)}.to raise_error(Faraday::ConnectionFailed)
        end
      end

      context 'with retry_on_error on' do
        it 'should raise error and call sleep' do
          expect(client).to receive(:sleep).exactly(2).times
          expect{client.oauth_token(true)}.to raise_error(Faraday::ConnectionFailed)
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

end
