# frozen_string_literal: true

# Break-glass grants against the shared vectors (packages/pca/conformance/break-glass-vectors.json). A missing file fails.
#   ruby -Ilib test/test_break_glass.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestBreakGlass < Minitest::Test
  FILE = File.expand_path('../conformance/break-glass-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_scenarios
    assert_operator DOC['scenarios'].length, :>=, 10
    DOC['scenarios'].each do |s|
      reg = AtlasPca::BreakGlassRegistry.new({ 'authorities' => [DOC['authority']], 'reviewers' => [DOC['reviewer']] + (s['extra_reviewers'] || []) })
      s['steps'].each do |st|
        label = "#{s['name']}: #{st['op']}"
        e = st['expect']
        case st['op']
        when 'accept' then assert_equal e, reg.accept(DOC['grants'][st['grant']], st['now']), label
        when 'use' then assert_equal e, reg.use(st['id'], st['holder'], st['action_digest'], st['now'], st['notified']), label
        when 'review' then assert_equal e, reg.review(DOC['reviews'][st['review']], st['holder'], st['now']), label
        when 'frozen' then assert_equal e, reg.frozen(st['holder'], st['now']), label
        else flunk "unknown op #{st['op']}"
        end
      end
    end
  end

  def test_total_on_hostile_input
    reg = AtlasPca::BreakGlassRegistry.new({ 'authorities' => [], 'reviewers' => [] })
    [nil, 1, 'x', [], {}].each do |x|
      refute AtlasPca.verify_break_glass(x)
      refute AtlasPca.verify_break_glass_review(x)
      assert_equal 'bad_record', reg.accept(x, 1)['code']
      assert_equal 'bad_record', reg.review(x, 'h', 1)['code']
      assert_equal 'bad_input', reg.use(x, 'h', 'a', 1, true)['code'] unless x == 'x'
      assert reg.frozen(x, 1) unless x == 'x'
    end
  end
end
