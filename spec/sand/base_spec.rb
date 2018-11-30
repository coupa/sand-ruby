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
end
