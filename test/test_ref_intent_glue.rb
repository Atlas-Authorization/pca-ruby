# frozen_string_literal: true

# Replays the TS-reference oracles of the learner feedback glue (test-data/ref-intent-glue-py.json.gz, ref-intent-jit.json.gz,
# ref-intent-routing.json.gz): outcome verification (a violated postcondition vetoes the cell), frame reports, org layers learned from
# maps, delta grants (the cells a new answer adds, their predicates, the minted principal-signed delta grant) and just-in-time consent
# decisions. Doubles compare to 1e-12 relative; ppm integers, signatures, strings and structure exactly.
require_relative 'support/ref_intent'
require_relative '../lib/atlas_pca/intent_effects'
require_relative '../lib/atlas_pca/intent_frames'
require_relative '../lib/atlas_pca/intent_jit'
require_relative '../lib/atlas_pca/intent_layers_wallet'
require_relative '../lib/atlas_pca/intent_mapkit'
require_relative '../lib/atlas_pca/intent_runtime'
require 'minitest/autorun'

class TestRefIntentGlue < Minitest::Test
  EF = AtlasPca::IntentEffects
  FR = AtlasPca::IntentFrames
  J = AtlasPca::IntentJit
  LW = AtlasPca::IntentLayersWallet
  M = AtlasPca::IntentMapkit
  RT = AtlasPca::IntentRuntime
  GLUE = Ref.load('intent-glue-py')
  JIT = Ref.load('intent-jit')
  ROUTING = Ref.load('intent-routing')

  def self.mk(omega, mo, obs)
    l = M.create_learner(omega, mo)
    obs.each { |x| l.observe({ 'verb' => x['verb'], 'values' => x['values'] }, x['y'], x['source'], x['region']) }
    l
  end

  def self.tail(l) = { 'vetoed' => l.vetoed_cells, 'metrics' => l.metrics, 'observations' => l.observations }

  def self.verify_case(*args)
    if args.length == 5 # the variant that answers "yes" after the violation: the veto must hold
      omega, mo, obs, oc, effect = args
      l = mk(omega, mo, obs)
      r = EF.verify_outcome(l, oc, effect)
      l.observe(oc, 1, 'elicitation')
      return { 'r' => r }.merge(tail(l)).merge('again' => l.admits_outcome(oc))
    end
    omega, mo, obs, oc, effect, pcs = args
    l = mk(omega, mo, obs)
    { 'result' => EF.verify_outcome(l, oc, effect, pcs) }.merge(tail(l))
  end

  def self.frame_scenario(omega, mo, obs, oc, report)
    l = mk(omega, mo, obs)
    { 'result' => FR.apply_frame_report(l, oc, report) }.merge(tail(l))
  end

  def self.org_scenario(omega, principals, rule, mo)
    maps = principals.map { |p| M.emit_intent_map(mk(omega, mo, p['observations']), p['ref']) }
    LW.org_layer_from_maps(maps, rule)
  end

  def self.delta_scenario(omega, mo, a, b)
    prev = mk(omega, mo, a)
    nxt = mk(omega, mo, a + b)
    d = J.delta_cells(prev, nxt)
    { 'cells' => d, 'predicates' => J.delta_predicates(nxt.omega, d) }
  end

  def self.mint_scenario(omega, mo, a, b, args, princ_seed)
    prev = mk(omega, mo, a)
    nxt = mk(omega, mo, a + b)
    kw = {}
    kw[:map_form] = args['mapForm'] unless args['mapForm'].nil?
    kw[:caveats] = args['caveats'] if args.key?('caveats')
    r = J.mint_delta(prev, nxt, args['prevGrant'], AtlasPca::KeyPair.from_seed_b64u(princ_seed), args['holder'], args['session'], args['seq'], args['root'],
                     args['mapDigest'], args['prev'], salt: args['salt'], **kw)
    r.nil? ? nil : { 'grant' => r['grant'], 'goalSalt' => r['goal_salt'], 'cells' => r['cells'] }
  end

  # the ceilings of the visit scenarios, by the corpus's names
  CEILINGS = {
    'all' => ->(_vs, _oc) { true }, 'none' => ->(_vs, _oc) { false },
    'amountLe60' => lambda { |_vs, oc|
      a = oc['values']['action.params.amount']
      !a.is_a?(Numeric) || a <= 60
    },
    'notGmail' => ->(_vs, oc) { oc['verb'] != 'gmail.send' }
  }.freeze

  def self.visit_scenario(omega, mo, obs, lifted, conform, ceilings, in_effective)
    J.decide_visit('learner' => mk(omega, mo, obs), 'lifted' => lifted, 'conform' => conform, 'ceilings' => ceilings.map { |n| CEILINGS.fetch(n) },
                   'inEffective' => in_effective)
  end

  def self.vs_of(omega, verb) = omega['verbs'].find { |v| v['verb'] == verb }

  def self.required_scenario(omega, vs_verb, cell, input, kid_seed)
    inp = input.merge('vs' => vs_of(omega, vs_verb), 'cell' => cell)
    { 'body' => J.intent_required_body(inp), 'signed' => AtlasPca.signed_intent_required(inp, 'site-1', AtlasPca::KeyPair.from_seed_b64u(kid_seed)) }
  end

  def self.dig(x) = AtlasPca.b64e(Digest::SHA256.digest(x))

  def self.wallet_scenario(omega, inp, mutation, now, lifted, session, map_digest, site_seed)
    site = AtlasPca::KeyPair.from_seed_b64u(site_seed)
    body = AtlasPca.signed_intent_required(inp.merge('vs' => vs_of(omega, 'stripe.refund'), 'cell' => [1, 0]), 'site-1', site)
    case mutation
    when 'coords' then body['cell']['coords']['action.params.amount'] = [2, 2]
    when 'verb' then body['cell']['verb'] = 'gmail.send'
    when 'sig' then body['sig']['value'] = "#{body['sig']['value'][0...-2]}AA"
    when 'kid' then body['sig']['kid'] = 'other'
    when 'session' then body['session'] = dig('other')
    when 'action' then body['action_digest'] = dig('other')
    when 'null' then body = nil
    end
    J.wallet_check_intent_required(body, { 'keys' => [{ 'kid' => 'site-1', 'alg' => 'ed25519', 'pk' => site.public }], 'now' => now, 'session' => session,
                                           'mapDigest' => map_digest, 'omegaTilde' => omega, 'lifted' => lifted, 'pcactn' => inp['pcactn'] },
                                   AtlasPca::IntentRequired.method(:verify_intent_required))
  end

  def self.jit_scenario(omega, mo, obs, oc, decision, ctx)
    l = mk(omega, mo, obs)
    req = RT.jit_consent_request(l, oc, { 'intentRef' => ctx['intentRef'], 'mapDigest' => ctx['mapDigest'] })
    { 'req' => req, 'digest' => RT.jit_consent_digest(req), 'result' => RT.record_jit_decision(l, req, decision), 'metrics' => l.metrics,
      'route' => RT.route_action(l, oc, {}) }
  end

  def test_corpora_are_fully_covered
    assert_equal %w[verifyScenario frameScenario orgScenario].sort, GLUE.keys.sort
    assert_equal %w[cellCoords cellFromCoords deltaScenario mintScenario requiredScenario visitScenario walletScenario], JIT.keys.sort
    assert_equal ['jitScenario'], ROUTING.keys
  end

  def test_glue_matches_the_reference
    Ref.run(self, GLUE['verifyScenario'], self.class.method(:verify_case), compare: RefIntent.cmp)
    Ref.run(self, GLUE['frameScenario'], self.class.method(:frame_scenario), compare: RefIntent.cmp)
    Ref.run(self, GLUE['orgScenario'], self.class.method(:org_scenario), compare: RefIntent.cmp)
  end

  def test_delta_grants_match_the_reference
    Ref.run(self, JIT['deltaScenario'], self.class.method(:delta_scenario), compare: RefIntent.cmp)
    Ref.run(self, JIT['mintScenario'], self.class.method(:mint_scenario), compare: RefIntent.cmp)
  end

  # lazy elicitation: the visit decision, the cell coordinates, the signed intent_required notice and the wallet's check of it
  def test_lazy_elicitation_matches_the_reference
    Ref.run(self, JIT['visitScenario'], self.class.method(:visit_scenario), compare: RefIntent.cmp)
    Ref.run(self, JIT['cellCoords'], J.method(:cell_coords), compare: RefIntent.cmp)
    Ref.run(self, JIT['cellFromCoords'], J.method(:cell_from_coords), compare: RefIntent.cmp)
    Ref.run(self, JIT['requiredScenario'], self.class.method(:required_scenario), compare: RefIntent.cmp)
    Ref.run(self, JIT['walletScenario'], self.class.method(:wallet_scenario), compare: RefIntent.cmp)
  end

  def test_jit_decisions_match_the_reference
    Ref.run(self, ROUTING['jitScenario'], self.class.method(:jit_scenario), compare: RefIntent.cmp)
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 146, GLUE.values.sum(&:length), 'intent-glue-py'
    assert_equal 219, JIT.values.sum(&:length), 'intent-jit'
    assert_equal({ 'visitScenario' => 96, 'cellCoords' => 19, 'cellFromCoords' => 34, 'deltaScenario' => 7, 'requiredScenario' => 29, 'walletScenario' => 16, 'mintScenario' => 18 }, JIT.transform_values(&:length))
    assert_equal 13, ROUTING.values.sum(&:length), 'intent-routing'
  end

end
