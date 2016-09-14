module Sand
  module Memory
    extend self

    def cache
      Cache
    end

    # This is modeled to the API of Rails.cache
    # This cache only does read and write and does not perform any other cache
    # operations, like expires_in...
    module Cache
      extend self

      @store = {}

      def read(name, opts = nil)
        @store[cache_key(name)]
      end

      def write(name, value, opts = nil)
        @store[cache_key(name)] = value
      end

      def clear(opts = nil)
        @store.clear
      end

      def delete(name, opts = nil)
        @store.delete(name)
      end

    protected

      def cache_key(name)
        Array(name).join('/')
      end
    end
  end
end
