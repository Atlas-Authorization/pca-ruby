# frozen_string_literal: true

# run_adapter_acceptance through a tiny in-process adapter built on authorize(): the matrix must equal the expected table.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/testing'
require 'minitest/autorun'

class TestTestingAcceptance < Minitest::Test
  T = AtlasPca::Testing

  def harness(options)
    lambda do |req|
      op = T.acceptance_operation({ 'method' => req['method'], 'url' => req['path'], 'body' => req['body'] })
      next { 'status' => 403, 'handlerRan' => false } if op.nil?

      h = req['headers']
      text = AtlasPca.decode_pca_header(h[AtlasPca::PCA_HEADER])
      next { 'status' => 401, 'handlerRan' => false } if text.nil?

      bundle = h.key?(AtlasPca::PROV_HEADER) ? AtlasPca.parse_json(AtlasPca.decode_pca_header(h[AtlasPca::PROV_HEADER]), any_top: true) : nil
      r = AtlasPca.authorize(AtlasPca.parse_json(text), operation: op, provenance_bundle: bundle, **options)
      next { 'status' => [401, 403].include?(r.status) ? r.status : 403, 'handlerRan' => false } unless r.allow

      { 'status' => 200, 'handlerRan' => true, 'operation' => r.operation }
    end
  end

  def test_acceptance_matrix_equals_expected
    assert_equal T::ADAPTER_ACCEPTANCE_EXPECTED, T.run_adapter_acceptance(method(:harness))
  end

  def test_acceptance_detects_a_fail_open_adapter
    # an adapter that runs the handler without authorizing must NOT equal the table
    got = T.run_adapter_acceptance(->(_o) { ->(_req) { { 'status' => 200, 'handlerRan' => true } } })
    refute_equal T::ADAPTER_ACCEPTANCE_EXPECTED, got
  end
end
