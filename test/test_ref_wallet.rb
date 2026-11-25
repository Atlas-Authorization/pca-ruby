# frozen_string_literal: true

# Differential replay of the wallet side of the Intent Layer v2 (Wallet, WalletCard, WalletPricing, WalletPopulation, WalletDelivery,
# WalletChannel, WalletHandlers: signed answers, friction tiers, cell coordinates, noise numerics, canaries, approval fatigue,
# risk-priced escalation, the trusted card, clarification, population priors, question delivery and the question channel) against
# vectors generated from the TypeScript reference (@atlasauth/pca-wallet). A reference throw requires the port to raise. Doubles from
# the diagnostic statistics (lnGamma, betacf, betaInc, betaQuantile, binEnt, the population noise) are compared to 1e-12 relative; the Clopper-Pearson bound,
# the noise estimate (which now takes its upper bounds from it), etaUnderLoad, noiseState and admissionPolicy are exact.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/wallet'
require_relative '../lib/atlas_pca/wallet_card'
require_relative '../lib/atlas_pca/wallet_pricing'
require_relative '../lib/atlas_pca/wallet_population'
require_relative '../lib/atlas_pca/wallet_delivery'
require_relative '../lib/atlas_pca/wallet_channel'
require_relative '../lib/atlas_pca/wallet_handlers'
require 'minitest/autorun'

class TestRefWallet < Minitest::Test
  W = AtlasPca::Wallet
  C = AtlasPca::WalletCard
  P = AtlasPca::WalletPricing
  PO = AtlasPca::WalletPopulation
  DL = AtlasPca::WalletDelivery
  CH = AtlasPca::WalletChannel
  H = AtlasPca::WalletHandlers
  O = AtlasPca::IntentOmega
  BY_FN = Ref.load('wallet')
  OM = BY_FN['omegas'][0]['out']

  def self.seed(label) = Digest::SHA256.digest("atlas-pca-conformance/#{label}")
  def self.key(label) = AtlasPca::KeyPair.new(seed(label))
  # a {"$seed": label} argument arrives as the base64url of that seed
  def self.key_b64(s) = AtlasPca::KeyPair.from_seed_b64u(s)

  def self.sub(x)
    case x
    when Array then x.map { |v| sub(v) }
    when Hash then x.keys == ['$omega'] ? OM[x['$omega']] : x.transform_values { |v| sub(v) }
    else x
    end
  end

  def self.vs_of(i, verb) = OM[i]['verbs'].find { |v| v['verb'] == verb }

  def self.close?(a, b)
    return a.keys == b.keys && a.all? { |k, v| close?(v, b[k]) } if a.is_a?(Hash) && b.is_a?(Hash)
    return a.length == b.length && a.zip(b).all? { |x, y| close?(x, y) } if a.is_a?(Array) && b.is_a?(Array)
    if a.is_a?(Numeric) && b.is_a?(Numeric)
      return a == b if a.is_a?(Integer) && b.is_a?(Integer)

      return (a - b).abs <= [1e-12 * [a.abs, b.abs].max, 1e-15].max
    end
    Ref.canon(a) == Ref.canon(b)
  end

  CLOSE = ->(got, out, _c) { close?(Ref.norm(got), out) }

  def self.verify_wrapped(a, principals = nil)
    r = W.verify_intent_answer(a, principals)
    !r['ok'] && r['reason'].start_with?('malformed answer:') ? { 'ok' => false, 'reason' => 'malformed answer' } : r
  end

  def self.seq(xs)
    i = 0
    lambda do
      raise 'rand exhausted' if i >= xs.length

      i += 1
      xs[i - 1]
    end
  end

  def self.pick(ctx0)
    ctx = sub(ctx0)
    c = { 'omega' => ctx['omega'], 'confirmed' => ctx['confirmed'], 'knownNo' => ->(v, idx) { ctx['knownNo'][W.cell_key(v, idx)] },
          'knownYes' => ctx['knownYes'], 'exclude' => Set.new(ctx['exclude']), 'rand' => seq(ctx['rands']), 'lowHarmSession' => ctx['lowHarmSession'],
          'canariesSoFar' => ctx['canariesSoFar'] }
    c['rho'] = ctx['rho'] if ctx.key?('rho')
    W.pick_canary(c)
  end

  def self.sliding(window, ops)
    c = window.nil? ? W::SlidingWindowCounter.new : W::SlidingWindowCounter.new(window)
    ops.map do |op|
      { 'v' => op[0] == 'count' ? c.count(op[1]) : c.try_add(op[1], op[2]) }
    rescue StandardError
      { 'err' => true }
    end
  end

  def self.resolve(om, verb, coords)
    r = W.resolve_coords(sub(om), verb, coords)
    r['ok'] ? { 'ok' => true, 'verb' => r['vs']['verb'], 'box' => r['box'] } : r
  end

  def self.of_action(i, a)
    r = W.cell_of_action(OM[i], a)
    r ? { 'verb' => r['vs']['verb'], 'idx' => r['idx'] } : nil
  end

  def self.render(x0)
    x = x0.dup
    om = OM[x.delete('omegaId')]
    C.render_card({ 'omega' => om }.merge(x))
  end

  def self.plan(x0)
    x = sub(x0)
    v = x['view']
    view = { 'p' => ->(verb, i) { v['p'].fetch(W.cell_key(verb, i), 0) }, 'vetoed' => ->(verb, i) { v['vetoed'].include?(W.cell_key(verb, i)) },
             'outsideCeiling' => ->(verb, i) { v['ceiling'].include?(W.cell_key(verb, i)) } }
    C.plan_clarification({ 'omega' => x['omega'], 'view' => view, 'candidates' => x['candidates'], 'asked' => Set.new(x['asked']),
                           'etaPos' => x['etaPos'], 'etaNeg' => x['etaNeg'] })
  end

  def self.sign_with(fn) = ->(body, k) { fn.call(body, key_b64(k['$seed'] || k)) }

  def self.wallet_constants
    {
      'FRICTION_ORDER' => W::FRICTION_ORDER, 'INTENT_ANSWER_SIG_DOMAIN' => W::INTENT_ANSWER_SIG_DOMAIN, 'INTENT_ANSWER_REF_DOMAIN' => W::INTENT_ANSWER_REF_DOMAIN,
      'INTENT_TYPED_DOMAIN' => W::INTENT_TYPED_DOMAIN, 'INTENT_DEVICE_CHALLENGE_DOMAIN' => W::INTENT_DEVICE_CHALLENGE_DOMAIN, 'MIN_HOLD_MS' => W::MIN_HOLD_MS,
      'PROVENANCE_ORDER' => W::PROVENANCE_ORDER, 'DEFAULT_FRICTION_THRESHOLDS' => W::DEFAULT_FRICTION_THRESHOLDS, 'CARD_DOMAIN' => C::CARD_DOMAIN,
      'CLARIFY_REASONS' => C::CLARIFY_REASONS, 'REASON_LABELS' => C::REASON_LABELS, 'MAX_CANDIDATES' => C::MAX_CANDIDATES, 'EMPTY_NOISE' => W::EMPTY_NOISE,
      'NOISE_PRIOR' => W::NOISE_PRIOR, 'DEFAULT_FATIGUE' => W::DEFAULT_FATIGUE, 'PPM' => P::PPM, 'MAX_MULTIPLIER_PPM' => P::MAX_MULTIPLIER_PPM
    }
  end

  def self.aggregate(schema, period, opts, votes, rel, rands)
    o = { 'rand' => seq(rands) }
    o['maxCellsPerPrincipal'] = opts['maxCellsPerPrincipal'] if opts.key?('maxCellsPerPrincipal')
    a = PO::PopulationAggregator.new(schema, period, o)
    vr = votes.map { |v| a.contribute(v) }
    release = begin
      a.release(rel)
    rescue StandardError
      { 'err' => true }
    end
    { 'votes' => vr, 'release' => release }
  end

  def self.prior(rel, beta, i, verb, contained)
    pm = PO.population_prior(rel, beta)
    { 'beta' => pm['beta'], 'weight' => pm['weight'].call(vs_of(i, verb), ->(c) { contained.include?(c) }) }
  end

  def self.notice(ir, keys, site, now, *inbox)
    DL.site_question_notice(ir, { 'keys' => keys, 'site' => site, 'now' => now }.merge(inbox.empty? ? {} : { 'inboxUrl' => inbox[0] }))
  end

  def self.hook(cfg, script, notices)
    calls = []
    idx = 0
    fetch = lambda do |url, init|
      calls << { 'url' => url, 'method' => init['method'], 'headers' => init['headers'], 'body' => init['body'] }
      step = idx < script.length ? script[idx] : { 'ok' => true, 'status' => 200 }
      idx += 1
      raise step['throw'] if step['throw']

      { 'ok' => step['ok'], 'status' => step['status'] }
    end
    c = { 'fetch' => fetch }
    c['url'] = cfg['url'] if cfg.key?('url')
    c['headers'] = cfg['headers'] if W.truthy?(cfg['headers']) && !cfg['headers'].empty?
    ch = DL.question_webhook_channel(c)
    { 'kind' => ch.kind, 'enabled' => ch.enabled, 'deliveries' => notices.map { |n| ch.notify(n) }, 'calls' => calls }
  end

  def self.tchan(kind, name, script, notices)
    sent = []
    idx = 0
    cfg = { 'siteName' => name }
    unless script.nil?
      cfg['send'] = lambda do |b|
        sent << b
        st = idx < script.length ? script[idx] : nil
        idx += 1
        raise st['throw'] if st && st['throw']
      end
    end
    ch = DL.question_text_channel(kind, cfg)
    { 'kind' => ch.kind, 'enabled' => ch.enabled, 'deliveries' => notices.map { |n| ch.notify(n) }, 'sent' => sent }
  end

  def self.dispatch(cfgs, note)
    chans = cfgs.map do |c|
      if c['type'] == 'webhook'
        DL.question_webhook_channel({ 'fetch' => ->(_u, _i) { { 'ok' => true, 'status' => 200 } } }.merge(c.key?('url') ? { 'url' => c['url'] } : {}))
      else
        DL.question_text_channel(c['type'], { 'siteName' => 'S' }.merge(c['enabled'] ? { 'send' => ->(_b) {} } : {}))
      end
    end
    d = DL.create_question_dispatcher(chans)
    { 'n' => d.channels.length, 'deliveries' => d.notify_all(note) }
  end

  # a Python-style truthiness of a JSON value (the generator's option filter)
  def self.pytruthy(v) = !(v.nil? || v == false || v == 0 || v == '' || v == [] || v == {})

  def self.channel(spec0)
    spec = sub(spec0)
    state = { 't' => spec['t0'], 'counts' => spec['noise'] }
    hourly = spec.key?('windowMs') ? W::SlidingWindowCounter.new(spec['windowMs']) : W::SlidingWindowCounter.new
    spec['hourlyPre'].each { |ts| hourly.try_add(ts, 9_007_199_254_740_991) }
    vw = spec['view']
    view = { 'p' => ->(v, i) { vw['p'].fetch(W.cell_key(v, i), 0) }, 'vetoed' => ->(v, i) { vw['vetoed'].include?(W.cell_key(v, i)) },
             'outsideCeiling' => ->(v, i) { vw['ceiling'].include?(W.cell_key(v, i)) }, 'confirmed' => -> { vw['confirmed'] } }
    opts = { 'omega' => spec['omega'], 'session' => spec['session'], 'mapDigest' => -> { spec['mapDigest'] }, 'principalSecret' => key(spec['principal']),
             'site' => spec['site'], 'view' => view, 'hourly' => hourly, 'noise' => -> { state['counts'] }, 'onNoise' => ->(n) { state['counts'] = n },
             'rand' => seq(spec['rands']), 'now' => -> { state['t'] } }
    %w[statementText units sensitivity identityPaths caps rho fatigue maxPerScreen maxBoxCells].each do |k|
      opts[k] = spec[k] if spec.key?(k) && (pytruthy(spec[k]) || %w[rho maxPerScreen maxBoxCells statementText].include?(k))
    end
    opts['device'] = Marshal.load(Marshal.dump(spec['device'])) if spec['device']
    opts['liftCandidate'] = ->(a) { { 'verb' => a['verb'], 'values' => a['values'].merge(spec['liftCand']) } } if spec['liftCand']
    if spec['lift']
      opts['lift'] = lambda do |a|
        v = W.action_values_of(a)
        { 'verb' => v['verb'], 'values' => v['values'].merge(spec['lift']['add']) }
      end
    end
    ch = CH::TrustedChannel.new(opts)
    seen = []
    resolver = ->(sid) { sid == spec['session'] ? ch : nil }
    steps = spec['steps'].map do |st|
      r = begin
        q = st['q']
        qid = q.nil? ? st['qid'] : (q < seen.length ? seen[q] : nil)
        case st['op']
        when 'time'
          state['t'] = st['t']
          { 't' => state['t'] }
        when 'receive' then ch.receive(st['ir'], { 'action' => st['action'] })
        when 'next'
          x = ch.next_screen
          ((x || {})['questions'] || []).each { |y| seen << y['questionId'] }
          x
        when 'answer' then ch.answer(qid, st['response'])
        when 'clarify' then ch.clarify(st['body'])
        when 'hQuestion' then H.question_handler(resolver).call(st.fetch('sid', spec['session']), st['body'])
        when 'hClarify' then H.clarify_handler(resolver).call(st.fetch('sid', spec['session']), st['body'])
        when 'summary' then ch.summary
        when 'state' then { 'digest' => ch.state_digest, 'asked' => ch.questions_asked }
        when 'noise' then { 'noise' => ch.noise, 'admission' => ch.admission }
        when 'challenge' then ch.device_challenge_for(qid)
        else raise ArgumentError, "bad op #{st['op']}"
        end
      rescue StandardError
        { '$err' => true }
      end
      { 'op' => st['op'], 'r' => r }
    end
    dev = opts['device']
    { 'steps' => steps, 'noise' => state['counts'], 'signCounts' => dev ? dev['signCounts'] : nil }
  end

  MAP = {
    'isFrictionTier' => [W.method(:friction_tier?)], 'frictionRank' => [W.method(:friction_rank)], 'maxFriction' => [W.method(:max_friction)],
    'satisfiesTier' => [W.method(:satisfies_tier)], 'isProvenanceLevel' => [W.method(:provenance_level?)], 'worstProvenance' => [W.method(:worst_provenance)],
    'frictionFor' => [W.method(:friction_for)], 'pcaActionDigest' => [W.method(:pca_action_digest)], 'actionValuesOf' => [W.method(:action_values_of)],
    'isB64u32' => [W.method(:b64u32?)], 'isObj' => [W.method(:obj?)], 'coordsError' => [W.method(:coords_error)],
    'answerShapeError' => [W.method(:answer_shape_error)],
    'signIntentAnswer' => [->(a, k) { W.sign_intent_answer(a, key_b64(k['$seed'] || k)) }],
    'verifyIntentAnswer' => [method(:verify_wrapped)], 'answerRef' => [W.method(:answer_ref)], 'typedDigest' => [W.method(:typed_digest)],
    'deviceChallenge' => [->(a) { W.device_challenge(a['questionId'], a['renderedDigest'], a['y'], a['actionDigest']) }],
    'lnGamma' => [W.method(:ln_gamma), CLOSE], 'betacf' => [W.method(:betacf), CLOSE], 'betaInc' => [W.method(:beta_inc), CLOSE],
    'betaQuantile' => [W.method(:beta_quantile), CLOSE], 'clopperPearsonUpper' => [W.method(:clopper_pearson_upper)], 'binEnt' => [W.method(:bin_ent), CLOSE],
    'recordCanary' => [W.method(:record_canary)], 'estimateNoise' => [W.method(:estimate_noise)], 'cellKey' => [W.method(:cell_key)],
    'boundaryNeighbours' => [->(om, c) { W.boundary_neighbours(sub(om), c) }], 'pickCanary' => [method(:pick)],
    'etaUnderLoad' => [W.method(:eta_under_load)], 'noiseState' => [W.method(:noise_state)], 'admissionPolicy' => [W.method(:admission_policy)],
    'doubleConfirmed' => [W.method(:double_confirmed)], 'slidingWindow' => [method(:sliding)],
    'signPricingConfig' => [sign_with(P.method(:sign_pricing_config))], 'pricingConfigError' => [P.method(:pricing_config_error)],
    'freshCalibration' => [P.method(:fresh_calibration)], 'decideEscalation' => [P.method(:decide_escalation)],
    'signAnswer' => [sign_with(P.method(:sign_answer))], 'updateCalibration' => [P.method(:update_calibration)],
    'signAutonomyRaise' => [sign_with(P.method(:sign_autonomy_raise))],
    'applyAutonomyRaise' => [->(cfg, r, k) { P.apply_autonomy_raise(cfg, r, key_b64(k['$seed'] || k)) }],
    'omega.verbCellCount' => [->(i, v) { O.verb_cell_count(vs_of(i, v)) }], 'omega.cellCount' => [->(i, v, k) { O.cell_count(vs_of(i, v)['dims'][k]) }],
    'omega.numCells' => [->(i, v, k) { O.num_cells(vs_of(i, v)['dims'][k]) }], 'omega.labelOf' => [AtlasPca::IntentRender.method(:label_of)],
    'omega.decodeCell' => [->(i, v, f) { O.decode_cell(vs_of(i, v), f) }],
    'omega.cellStats' => [->(i, v, ix) { O.cell_stats(vs_of(i, v), ix) }, CLOSE],
    'omega.cellRep' => [->(i, v, ix) { O.cell_rep(vs_of(i, v), ix) }],
    'omega.cellOf' => [->(i, v, oc) { O.cell_of(vs_of(i, v), oc) }],
    'coordKeyOf' => [W.method(:coord_key_of)], 'resolveCoords' => [method(:resolve)],
    'coordsOfBox' => [->(i, v, b) { W.coords_of_box(vs_of(i, v), b) }], 'coordsOfCell' => [->(i, v, ix) { W.coords_of_cell(vs_of(i, v), ix) }],
    'cellInBox' => [W.method(:cell_in_box)], 'boxCells' => [W.method(:box_cells)], 'boxSize' => [W.method(:box_size)],
    'cellOfAction' => [method(:of_action)], 'flatIndex' => [->(i, v, ix) { W.flat_index(vs_of(i, v), ix) }],
    'cleanText' => [C.method(:clean_text)], 'last4' => [C.method(:last4)], 'formatNumber' => [C.method(:format_number)],
    'renderCard' => [method(:render)], 'cardDigest' => [C.method(:card_digest)], 'cardDigestMatches' => [C.method(:card_digest_matches)],
    'cardText' => [C.method(:card_text)], 'partialError' => [C.method(:partial_error)], 'normalizeTyped' => [C.method(:normalize_typed)],
    'expectedTyped' => [C.method(:expected_typed)], 'parseClarifyRequest' => [C.method(:parse_clarify_request)],
    'informationGain' => [C.method(:information_gain), CLOSE], 'planClarification' => [method(:plan), CLOSE],
    'gaussianSigma' => [PO.method(:gaussian_sigma), CLOSE], 'gaussian' => [->(xs) { PO.gaussian(seq(xs)) }, CLOSE],
    'rrKeepProbability' => [PO.method(:rr_keep_probability), CLOSE],
    'randomizedResponse' => [->(y, e, r) { PO.randomized_response(y, e, -> { r }) }], 'debiasRandomizedResponse' => [PO.method(:debias_randomized_response), CLOSE],
    'populationCellKey' => [->(sch, i, v, ix) { PO.population_cell_key(sch, vs_of(i, v), ix) }], 'aggregate' => [method(:aggregate), CLOSE],
    'populationPrior' => [method(:prior), CLOSE], 'siteQuestionNotice' => [method(:notice)], 'clarificationNotice' => [DL.method(:clarification_notice)],
    'questionText' => [DL.method(:question_text)], 'webhookChannel' => [method(:hook)], 'textChannel' => [method(:tchan)], 'dispatcher' => [method(:dispatch)],
    'channel' => [method(:channel), CLOSE]
  }.freeze
  NOT_CALLABLE = %w[omegas constants].freeze

  def test_corpus_is_fully_accounted_for
    assert_equal (MAP.keys + NOT_CALLABLE).sort, BY_FN.keys.sort
  end

  MAP.each do |fn, (call, cmp)|
    define_method("test_#{fn.gsub(/\W/, '_')}") { Ref.run(self, BY_FN[fn], call, compare: cmp) }
  end

  def test_constants
    expected = BY_FN['constants'][0]['out']
    got = Ref.norm(self.class.wallet_constants)
    got.each { |k, v| assert_equal Ref.canon(expected[k]), Ref.canon(v), k }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 7360, BY_FN.values.sum(&:length), 'wallet'
  end

end
