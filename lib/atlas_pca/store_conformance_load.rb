# frozen_string_literal: true

# Load a store adapter from a Ruby file (./my_adapter.rb[:Const]), a requirable feature name, or a built-in reference
# (builtin:<name>) (port of the TypeScript reference, @atlasauth/pca-store-conformance, load.ts). The file defines the adapter (or a
# factory callable taking the options Hash) as the constant PcaStoreAdapter, or as the constant named after the colon.
require_relative 'store_conformance_runner'

module AtlasPca
  module StoreConformanceLoad
    DEFAULT_CONST = 'PcaStoreAdapter'

    module_function

    def adapter_like?(x) = !x.nil? && (x.respond_to?(:open_store) || x.respond_to?(:call))

    # Pick the exported constant; nil when it is missing or not adapter-like.
    def pick_export(const_name = nil)
      name = const_name.nil? || const_name.empty? ? DEFAULT_CONST : const_name
      v = Object.const_defined?(name) ? Object.const_get(name) : nil
      adapter_like?(v) ? v : nil
    end

    # Load the file or feature of spec (without any ":Const" suffix).
    def import(target)
      if target.end_with?('.rb') || target.include?(File::SEPARATOR) || File.exist?(target)
        load File.expand_path(target)
      else
        require target
      end
    end

    def load_adapter(spec, options = nil)
      options ||= {}
      if spec.start_with?('builtin:')
        name = spec['builtin:'.length..]
        unless StoreConformanceRunner::REFERENCE_ADAPTERS.key?(name)
          raise ArgumentError, "unknown built-in adapter '#{name}' (known: #{StoreConformanceRunner::REFERENCE_ADAPTERS.keys.join(', ')})"
        end

        exported = StoreConformanceRunner::REFERENCE_ADAPTERS[name]
      else
        target, _, const = spec.rpartition(':').then { |a, sep, b| sep.empty? || a.empty? || a.length == 1 ? [spec, '', ''] : [a, sep, b] }
        import(target)
        exported = pick_export(const)
        raise ArgumentError, "#{spec}: exports no #{const.to_s.empty? ? DEFAULT_CONST : const}" if exported.nil?
      end
      a = exported.respond_to?(:open_store) ? exported : (exported.respond_to?(:call) ? exported.call(options) : nil)
      unless a.respond_to?(:open_store) && a.respond_to?(:name) && a.name.is_a?(String)
        raise TypeError, "#{spec}: does not export a store adapter (an object with a String #name and an #open_store callable, or a factory returning one)"
      end

      a
    end
  end
end
