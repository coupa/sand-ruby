require 'spec_helper'

describe Sand::Base do
  let(:base) { Sand::Base.new(client_id: 'a', client_secret: 'b', token_site: 'http://localhost', token_path: '/abc', default_retry_count: 2, cache: Sand::Memory.cache) }
  after{ base.cache.clear if base.cache }

  describe '#cache_key' do
    before do
      base.cache_root = 'root'
      allow(Sand::Base).to receive(:cache_type).and_return('type')
    end

    it 'returns the cache key' do
      expect(base.cache_key('key', 'scope', nil)).to eq('root/type/key/scope')
      expect(base.cache_key('key', ['scope'])).to eq('root/type/key/scope')
      expect(base.cache_key('key', ['scope'], nil)).to eq('root/type/key/scope')
      expect(base.cache_key('key', ['scope1', 'scope2'], nil)).to eq('root/type/key/scope1_scope2')
      expect(base.cache_key('key', ['scope1', 'scope2', 'scope3'], nil)).to eq('root/type/key/scope1_scope2_scope3')
      expect(base.cache_key('key', ['scope1', 'scope2'], resource: 'r1')).to eq('root/type/key/scope1_scope2/r1')
      expect(base.cache_key('key', ['scope1', 'scope2'], action: 'a1', resource: 'r1')).to eq('root/type/key/scope1_scope2/r1/a1')
      expect(base.cache_key('key', ['scope1', 'scope2'], action: '', resource: 'r1')).to eq('root/type/key/scope1_scope2/r1')
      expect(base.cache_key('key', ['scope1', 'scope2'], action: 'a1')).to eq('root/type/key/scope1_scope2/a1')
    end

    context 'with either key or scopes being empty' do
      it 'accepts scopes as empty array or nil' do
        expect(base.cache_key('key', nil)).to eq('root/type/key')
        expect(base.cache_key('key', [])).to eq('root/type/key')

        expect(base.cache_key(nil, nil)).to eq('root/type')
        expect(base.cache_key(nil, [])).to eq('root/type')
      end

      it 'accepts keys as empty string or nil' do
        expect(base.cache_key('', 'scope')).to eq('root/type/scope')
        expect(base.cache_key('', ['scope'])).to eq('root/type/scope')

        expect(base.cache_key(nil, 'scope')).to eq('root/type/scope')
        expect(base.cache_key(nil, ['scope1', 'scope2'])).to eq('root/type/scope1_scope2')
      end
    end
  end

  describe '#cache_read' do
    context 'when there is no cache' do
      it 'returns nil' do
        base.cache = nil
        data = ''
        expect{data = base.cache_read('')}.not_to raise_error
        expect(data).to be_nil
      end
    end

    context 'when key does not exist or data is nil' do
      it 'returns nil' do
        base.cache.write('test', nil)
        expect(base.cache_read('not_exist')).to be_nil
        expect(base.cache_read('test')).to be_nil
      end
    end

    context 'when data is expired' do
      it 'deletes the key from cache and return nil' do
        base.cache.write('test', { data: 'hi', expiry_epoch_sec: 1 })
        expect(base.cache).to receive(:delete).with('test')
        expect(base.cache_read('test')).to be_nil
      end
    end

    context 'when expiry time is 0' do
      it 'returns the data' do
        base.cache.write('test', { data: 'hi', expiry_epoch_sec: 0 })
        expect(base.cache).not_to receive(:delete)
        expect(base.cache_read('test')).to eq('hi')
      end
    end

    context 'when data has not expired' do
      it 'returns the data' do
        base.cache.write('test', { data: 'hi', expiry_epoch_sec: Time.now.to_i + 1000000 })
        expect(base.cache).not_to receive(:delete)
        expect(base.cache_read('test')).to eq('hi')
      end
    end
  end

  describe '#cache_write' do
    context 'when there is no cache' do
      it 'does nothing' do
        base.cache = nil
        expect(base.cache).not_to receive(:write)
        expect{base.cache_write('', '', 0)}.not_to raise_error
      end
    end

    context 'when expires_in_sec > 0' do
      it 'writes to the cache' do
        allow(Time).to receive(:now).and_return(100)
        expect(base.cache).to receive(:write).with('key', { data: 'data', expiry_epoch_sec: 110 }, expires_in: 10)
        base.cache_write('key', 'data', 10)
      end
    end

    context 'when expires_in_sec <= 0' do
      it 'writes to the cache with 0 expiry time' do
        expect(base.cache).to receive(:write).with('key', { data: 'data', expiry_epoch_sec: 0 }, expires_in: 0)
        base.cache_write('key', 'data', -1)

        expect(base.cache).to receive(:write).with('key', { data: 'data', expiry_epoch_sec: 0 }, expires_in: 0)
        base.cache_write('key', 'data', 0)
      end
    end
  end
end
