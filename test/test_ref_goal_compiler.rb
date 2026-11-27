# frozen_string_literal: true

# The typed front door of the goal compiler (typecheck / compile / decide / render over the hand-ported kernel) on the goal
# conformance vectors themselves, when the monorepo layout puts them at ../../packages/pca-conformance: reasons, policy digest,
# decision + witness of every probe, and the card round trip.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_compiler'
require 'minitest/autorun'
require 'json'

class TestRefGoalCompiler < Minitest::Test
  CP = AtlasPca::GoalCompiler
  C = AtlasPca::GoalCodec
  DIR = File.expand_path('../../../packages/pca-conformance/vectors/goal', __dir__)

  def vectors
    return [] unless File.directory?(DIR)

    Dir.children(DIR).sort.select { |f| f.end_with?('.json') && f != 'index.json' }
       .map { |f| JSON.parse(File.read(File.join(DIR, f))) }.reject { |v| v['kind'] == 'fn' }
  end

  def test_typed_front_door_on_conformance_vectors
    vs = vectors
    skip 'goal conformance vectors not in this layout' if vs.empty?
    bad = []
    vs.each do |v|
      bad << "#{v['id']}: reasons" unless CP.typecheck(v['goal'], v['ontology']) == v['compile']['reasons']
      r = CP.compile_goal(v['goal'], v['ontology'])
      bad << "#{v['id']}: policy_digest" unless (r['ok'] ? CP.policy_digest(r['policy']) : nil) == v['policy_digest']
      bad << "#{v['id']}: render" unless C.decode_goal(CP.render_tape(v['goal'])) == C.decode_goal(C.encode_goal(v['goal']))
      next unless v['compile']['ok']

      v['probes'].each_with_index do |p, i|
        d = CP.decide_policy(v['goal'], v['ontology'], p['action'], p['history'])
        got = d['ok'] ? { 'decision' => d['decision'], 'witness' => d['witness'] } : { 'decision' => 'deny', 'witness' => nil }
        bad << "#{v['id']}##{i}: #{got.inspect} != #{p['expect'].inspect}" if got != p['expect'] || (d['ok'] && d['decision'] == 'allow' && !d['witnessChecked'])
        bad << "#{v['id']}##{i}: decide_goal != decide_policy" if d['ok'] && CP.decide_goal(v['goal'], v['ontology'], p['action'], p['history']) != d['decision']
      end
    end
    assert bad.empty?, "#{bad.length} divergence(s):\n#{bad.first(25).join("\n")}"
  end

  def test_proved_kernel_review_wiring
    pk = CP.proved_kernel
    assert_equal CP.method(:compile_goal), pk.compile
    assert_equal CP.method(:decide_goal), pk.decide
    assert_equal CP.method(:policy_digest), pk.policy_digest
  end
end
