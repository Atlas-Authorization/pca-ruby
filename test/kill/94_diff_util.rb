# frozen_string_literal: true
require 'json'
require 'zlib'
# Shared helpers of the differential kill tests (96_* ...): loading a TS-generated oracle file and comparing values.
# The shared oracles are written by tools/pca-audit/java-mutate/k042-*-oracle.m(j|t)s (the Java suite runs the same files).
module MutationKill
  module DiffUtil
    module_function
    DATA = File.expand_path('../../test-data', __dir__)

    # JSON text of an oracle file (.gz or plain), UTF-8
    def read(name)
      path = File.join(DATA, name)
      raw = name.end_with?('.gz') ? Zlib::GzipReader.open(path, &:read) : File.binread(path)
      raw.force_encoding('UTF-8')
    end

    # the platform-JSON reading of the oracle text (-0 kept, a lone surrogate becomes an invalid-encoding string). Parsed
    # ONCE at registry load, i.e. by the unmutated library in the parent process.
    def parse(text) = AtlasPca::JsonParser.new(text, true, true, json_text: true).parse_document

    def load(name) = parse(read(name))

    # nil when this mutation run is for a file the oracle does not bear on (MUT_FILE is exported by mutate.rb; unset = run all)
    def skip?(*files) = (f = ENV['MUT_FILE']) && !f.empty? && !files.include?(f)

    # comparable form: integral floats -> Integer (JSON has one number type), hashes/arrays recursively
    def norm(x)
      case x
      when Hash then x.each_with_object({}) { |(k, v), h| h[k] = norm(v) }
      when Array then x.map { |v| norm(v) }
      when Float then x.finite? && x == x.floor && x.abs < 1e300 ? (x.zero? && (1.0 / x).negative? ? -0.0 : x.to_i) : x
      else x
      end
    end

    # the host lacks a PQ suite the case names: by design (an unsupported_suite refusal), not a difference
    def pq_case?(c) = !AtlasPca.supported_suites.include?('ml-dsa-65') && c.to_s.match?(/ml-dsa|hybrid|slh-dsa|fn-dsa|less/)
  end
end
