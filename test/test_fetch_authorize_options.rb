# frozen_string_literal: true

# Fetch.authorize_options keeps the caller's AuthorizeOptions instance (never swaps it for a blank set) and refuses other types.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestFetchAuthorizeOptions < Minitest::Test
  F = AtlasPca::Fetch

  def test_instance_is_returned_unchanged
    opts = AtlasPca::AuthorizeOptions.new
    assert_same opts, F.authorize_options(opts)
  end

  def test_nil_and_hash
    assert_nil F.authorize_options(nil)
    assert_instance_of AtlasPca::AuthorizeOptions, F.authorize_options({ 'operation' => nil }.transform_keys(&:to_sym))
  end

  def test_other_types_are_refused
    [1, 'x', [], Object.new].each { |v| assert_raises(TypeError) { F.authorize_options(v) } }
  end
end
