# frozen_string_literal: true

# Differential replay of AtlasPca::Ap2.verify_pca_binding against vectors generated from the TypeScript reference
# (@atlasauth/pca-ap2). The policy engine is injected: `ref_decide` below runs the reference decision steps (envelope predicates,
# caveats, risk, budget) over the native predicate, caveat and risk modules.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/ap2'
require 'minitest/autorun'

class TestRefAp2Binding < Minitest::Test
  A = AtlasPca::Ap2
  CASES = Ref.load('ap2-java-extra')
  CANON = ->(v) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(v))) }
  FAST = %w[reversible rate_limited costly].freeze

  def self.denied(reason, budget)
    { 'releaseGuardianShare' => false, 'requiredThreshold' => { 't' => 3, 'proof' => 'strong', 'optimisticAllowed' => false }, 'r' => 1,
      'admit' => false, 'needStepUp' => true, 'reasons' => [reason], 'budget' => budget }
  end

  # steps 3-5 of the reference policy VM over the native risk primitives
  def self.decide_risk(pol, risk, budget, now, release, reversibility_class)
    r_ = AtlasPca::Risk
    leaked = r_.leak(budget, now, pol['lambda'])
    inputs = r_::WORST.merge((risk || {}).select { |k, v| r_::WORST.key?(k) && r_.fin?(v) })
    missing = r_::WORST.keys.reject { |k| k == 'age' || r_.fin?((risk || {})[k]) }
    inputs['age'] = r_.age_since_touch(leaked, now, 3_600_000) if (risk || {})['age'].nil?
    reasons = []
    reasons << "risk input(s) missing, assumed worst case: #{missing.join(', ')}" unless missing.empty?
    r = [r_.risk_score(inputs, pol['weights']), 0].max
    rt = r_.required_threshold(r, pol, !(reversibility_class.is_a?(String) && FAST.include?(reversibility_class)))
    adm = r_.admit(r, leaked, pol)
    if adm['needStepUp']
      reasons << (rt['t'] < 3 && adm['t'] == 3 ? 'trust budget depleted: human recharge required' : "risk #{r_.to_fixed3(r)} exceeds auto threshold: step-up to t=#{adm['t']}")
    end
    { 'r' => r, 'release' => release, 'threshold' => r_.escalate_threshold(rt, adm['t']), 'admit' => release && adm['admit'],
      'needStepUp' => release ? adm['needStepUp'] : true, 'reasons' => reasons,
      'budget' => release && adm['metered'] ? r_.debit(leaked, r_.cost(r, pol['kappa'])) : leaked }
  end

  REF_DECIDE = lambda do |inp|
    grant = inp['grant']
    action = inp['action']
    risk = inp['risk']
    budget = inp['budget']
    now = inp['now']
    env = AtlasPca.read_envelope(grant)
    next denied('grant carries no valid envelope', budget) if env.nil?
    next denied('invalid decision time', budget) unless AtlasPca::Js.num?(now) && (now.is_a?(Integer) || now.finite?)

    why, ok = AtlasPca.verify_chain([grant], grant['issuer'], true)
    next denied("capability chain unverified: #{why}", budget) unless ok

    cc = inp['caveatContext'] || {}
    cctx = { 'now' => now, 'blast_radius' => risk['blastRadius'], 'reversibility_class' => cc['reversibilityClass'] }
    cctx['recent_action_times'] = cc['recentActionTimes'] unless cc['recentActionTimes'].nil?
    reasons = []
    pr = AtlasPca.evaluate_predicates(env['predicates'], action)
    reasons << (pr['reason'] || 'action not permitted by envelope predicates') unless pr['allowed']
    ok1, failed1 = AtlasPca.evaluate_agent_caveats(env['caveats'], cctx, action)
    reasons << "caveat(s) not satisfied: #{failed1.join(', ')}" unless ok1
    root = grant['caveats'].reject { |c| c.is_a?(Hash) && c['type'] == 'envelope' }
    ok2, failed2 = AtlasPca.evaluate_agent_caveats(root, cctx, action)
    reasons << "root caveat(s) not satisfied: #{failed2.join(', ')}" unless ok2
    d = decide_risk(env['risk_policy'], risk, budget, now, pr['allowed'] == true && ok1 && ok2, cctx['reversibility_class'])
    { 'releaseGuardianShare' => d['release'], 'requiredThreshold' => d['threshold'], 'r' => d['r'], 'admit' => d['admit'],
      'needStepUp' => d['needStepUp'], 'reasons' => reasons + d['reasons'], 'budget' => d['budget'] }
  end

  def self.verify_pca_binding(i)
    o = Ref.snake(i)
    o['hooks'] = o['hooks'].transform_values { |v| ->(_ctx) { v } } if o['hooks']
    A.verify_pca_binding(o, REF_DECIDE)
  end

  # The reference's own core-verifier wording (cap_chain / freshness names, its validity / audience / signature reasons) is not the
  # native core's; those refusals are compared as "refused at the PCActn stage" only.
  CORE_STAGE = /\APCActn: (validity|audience|leaf_signature|plan_inclusion|wire|freshness|cap_chain|chain|version|grant_ref)/.freeze

  def test_ap2_pca_binding_matches_reference
    assert_equal ['verifyPcaBinding'], CASES.keys
    bad = []
    CASES['verifyPcaBinding'].each do |c|
      out = c['out']
      got = begin
        verify_pca_binding(Ref.dec(c['args'][0]))
      rescue StandardError => e
        e
      end
      if Ref.throws?(out)
        bad << [c['name'], "returned #{CANON.call(got)[0, 200]}"] unless got.is_a?(StandardError) && (!out.key?('code') || got.respond_to?(:code) && got.code == out['code'])
      elsif got.is_a?(StandardError)
        bad << [c['name'], "raised #{got.class}: #{got.message}"]
      elsif out['reason'].is_a?(String) && out['reason'].match?(CORE_STAGE)
        bad << [c['name'], "ok=#{got['ok']} reason=#{got['reason']}"] unless got['ok'] == false && got['reason'].to_s.start_with?('PCActn: ')
      elsif c['args'][0]['enforce']
        bad << [c['name'], 'enforce gates must be refused'] unless got['ok'] == false
      elsif CANON.call(got) != CANON.call(out)
        bad << [c['name'], "got #{CANON.call(got)[0, 300]} ref #{CANON.call(out)[0, 300]}"]
      end
    end
    assert bad.empty?, "#{bad.length} differ from the TS reference:\n#{bad.first(25).map { |n, g| "  #{n}: #{g}" }.join("\n")}"
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 126, CASES.values.sum(&:length), 'ap2-java-extra'
  end

end
