# frozen_string_literal: true

# The approval-store conformance run over every reference store (a guard that has never failed proves nothing: a deliberately
# broken store must fail it).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/ciba_conformance'
require 'minitest/autorun'
require 'tmpdir'

class TestRefCibaConformance < Minitest::Test
  C = AtlasPca::Ciba
  CF = AtlasPca::CibaConformance

  def stores(name, dir)
    case name
    when 'memory' then [-> { C.create_memory_approval_store }, nil]
    when 'file'
      make = lambda do
        path = File.join(Dir.mktmpdir(nil, dir), 'a.json')
        C.create_file_approval_store(path).tap { |s| s.define_singleton_method(:path) { path } }
      end
      [make, ->(prev) { C.create_file_approval_store(prev.path) }]
    when 'kv-memory' then [-> { C.create_kv_approval_store(C.create_memory_kv) }, nil]
    else
      make = lambda do
        where = Dir.mktmpdir(nil, dir)
        C.create_kv_approval_store(C.create_directory_kv(where)).tap { |s| s.define_singleton_method(:where) { where } }
      end
      [make, ->(prev) { C.create_kv_approval_store(C.create_directory_kv(prev.where)) }]
    end
  end

  %w[memory file kv-memory kv-directory].each do |name|
    define_method("test_store_conformance_#{name.tr('-', '_')}") do
      Dir.mktmpdir do |d|
        make, reopen = stores(name, d)
        report = CF.run_approval_store_conformance(make, reopen)
        assert report.ok?, report.render
      end
    end
  end

  # no compare-and-set: every cas succeeds
  class Lax
    def initialize = (@m = {})
    def get(key) = @m[key] && Marshal.load(Marshal.dump(@m[key]))

    def cas(key, expected, value)
      @m[key] = { 'version' => expected + 1, 'value' => Marshal.load(Marshal.dump(value)) }
      true
    end
  end

  def test_a_store_without_compare_and_set_fails
    report = CF.run_approval_store_conformance(-> { Lax.new })
    refute report.ok?, report.render
  end
end
