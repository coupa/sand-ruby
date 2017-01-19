require 'spec_helper'

describe Sand::Client do
  let(:client) { Sand::Client.new(client_id: 'a', client_secret: 'b', token_site: 'http://localhost', token_path: '/abc', max_retry: 2, cache: Sand::Memory.cache) }
  after{ client.cache.clear if client.cache }

  describe '#request' do
    let(:response) { 'good' }
    subject do
      client.request('test') { |token| response }
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
      it 'raises unsupported error' do
        expect{subject}.to raise_error(Sand::UnsupportedResponseError)
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

      context 'without retry' do
        subject do
          client.max_retry = 0
          client.request('test') { |token| response }
        end
        it 'returns 401 without retry' do
          expect(client).not_to receive(:sleep)
          expect(subject.code).to eq(401)
        end
      end
    end
  end

  describe '#token' do
    let(:resource) { 'test' }
    subject{ client.token(resource) }
    before{ allow(client).to receive(:oauth_token).and_return({access_token: 'retrieve_token', expires_in: 60}) }

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
        t = client.oauth_token('test scope')
        expect(t[:access_token]).to eq('token')
        expect(t[:expires_in]).to eq(60)
      end
    end

    context 'on network error' do
      before { allow_any_instance_of(OAuth2::Strategy::ClientCredentials).to receive(:get_token).and_raise(StandardError) }

      context 'without retry' do
        it 'should raise error and not call sleep' do
          client.max_retry = 0
          expect(client).not_to receive(:sleep)
          expect{client.oauth_token}.to raise_error(Sand::AuthenticationError)
        end
      end

      context 'with retry' do
        it 'should call sleep and then raise error' do
          client.max_retry = 2
          expect(client).to receive(:sleep).exactly(2).times
          expect{client.oauth_token}.to raise_error(Sand::AuthenticationError)
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
