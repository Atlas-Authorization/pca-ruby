# frozen_string_literal: true

# The Rails concern drives the Rack guard: a request without a PCActn is refused with 401 and the action never runs.
require_relative '../lib/atlas_pca/rails'
require 'minitest/autorun'

class TestRails < Minitest::Test
  # A stand-in for the controller surface Rails supplies (before_action / request / response / render).
  class Base
    @filters = []
    class << self
      attr_reader :filters

      def before_action(**_o, &blk) = (@filters ||= []) << blk
    end
    attr_reader :request, :response, :rendered

    def initialize(env)
      @request = Struct.new(:env).new(env)
      @response = Struct.new(:h) { def set_header(k, v) = h[k] = v }.new({})
    end

    def render(**o) = @rendered = o
  end

  def test_refuses_without_proof_and_requires_binding
    k = Class.new(Base) { include AtlasPca::Rails::Controller }
    assert_raises(ArgumentError) { k.pca_protect(audience: 'rs', resolve_grant: ->(_r) { nil }) }
    k.pca_protect(audience: 'rs', resolve_grant: ->(_r) { nil }, signature_only: true)
    c = k.new({ 'REQUEST_METHOD' => 'POST', 'rack.input' => StringIO.new('') })
    c.instance_exec(&k.filters.first)
    assert_equal 401, c.rendered[:status]
    assert_nil c.pca_context
    assert_match(/PCA realm=/, c.response.h['WWW-Authenticate'])
  end
end
