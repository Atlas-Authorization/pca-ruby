# frozen_string_literal: true

# The high-level agent facade: compile a principal's human-level inputs (permissions, limits) into a signed grant, and act.
#
#   a = AtlasPca.create_agent(principal: principal_key, goal: 'reconcile refunds for October',
#                             permissions: { 'stripe' => ['refund'], 'gmail' => ['send'] }, limits: { 'refund' => '$500/day' },
#                             aud: 'https://api.example.com')
#   r = a.act('stripe.refund', 'charge:ch_123', { 'amount' => 42, 'currency' => 'usd' })
#   http.post(url, body, r['headers'])                      # PCA-Action + PCA-Provenance
#
# create_agent compiles the permissions into predicates, caveats and a risk policy (compile_policy), creates the provenance
# recorder whose key the grant's signed envelope names, and mints the root grant. `act` builds a signed PCActn per tool call
# with its provenance bundle; `dry_run` is a local, NON-authoritative pre-check. Nothing here authorizes anything: the
# resource server's verifier decides. Same compile and wire as the TypeScript reference's `agent()`; the compiled policy uses
# the reference's member names (riskPolicy, budgetModel, periodMs, inputLimits) and refusal texts.
#
# Keep the provenance recorder in the harness, out of the model's reach (never expose `agent.provenance` as a tool).
module AtlasPca
  LIMIT_PERIODS = {
    's' => 1000, 'sec' => 1000, 'second' => 1000, 'seconds' => 1000,
    'm' => 60_000, 'min' => 60_000, 'minute' => 60_000, 'minutes' => 60_000,
    'h' => 3_600_000, 'hr' => 3_600_000, 'hour' => 3_600_000, 'hours' => 3_600_000,
    'd' => 86_400_000, 'day' => 86_400_000, 'days' => 86_400_000,
    'w' => 604_800_000, 'week' => 604_800_000, 'weeks' => 604_800_000,
    'mo' => 2_592_000_000, 'month' => 2_592_000_000, 'months' => 2_592_000_000
  }.freeze
  # Longest limit string accepted (UTF-16 units, as the reference counts): bounds the work and the error text.
  MAX_LIMIT_LENGTH = 64
  # ECMAScript WhiteSpace + LineTerminator: what String.prototype.trim and \s cover.
  JS_WS = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
  JS_WS_CLASS = "[#{Regexp.escape(JS_WS)}]*".freeze
  LIMIT_RE = /\A(\$)?#{JS_WS_CLASS}([0-9]+(?:\.[0-9]+)?)#{JS_WS_CLASS}(?:\/#{JS_WS_CLASS}([a-zA-Z]+))?\z/
  JS_TRIM_RE = /\A[#{Regexp.escape(JS_WS)}]+|[#{Regexp.escape(JS_WS)}]+\z/

  module_function

  def js_trim(s) = s.gsub(JS_TRIM_RE, '')
  def utf16_length(s) = s.each_char.sum { |c| c.ord > 0xFFFF ? 2 : 1 }

  # A JS number from decimal text: an Integer when integral and safe (so it canonicalizes and prints as the reference's).
  def js_decimal(text)
    f = Float(text)
    f.finite? && f == f.floor && f.abs <= MAX_SAFE ? f.to_i : f
  end

  # Parse "$500/day", "$500", "10/hour", "10" into {'amount', 'unit' => 'usd' | 'count', 'periodMs'?}. Raises ArgumentError
  # on anything malformed or longer than 64 characters.
  def parse_limit(s)
    raise ArgumentError, 'parseLimit: empty limit' if !s.is_a?(String) || !s.valid_encoding? || js_trim(s).empty?
    raise ArgumentError, "parseLimit: limit is longer than #{MAX_LIMIT_LENGTH} characters" if utf16_length(s) > MAX_LIMIT_LENGTH

    m = LIMIT_RE.match(js_trim(s))
    raise ArgumentError, "parseLimit: cannot parse limit '#{s}'" unless m

    amount = js_decimal(m[2])
    raise ArgumentError, "parseLimit: bad amount in '#{s}'" if (amount.is_a?(Float) && !amount.finite?) || amount.negative?

    out = { 'amount' => amount, 'unit' => m[1] == '$' ? 'usd' : 'count' }
    unless m[3].nil?
      p = LIMIT_PERIODS[m[3].downcase]
      raise ArgumentError, "parseLimit: unknown period '#{m[3]}' in '#{s}'" if p.nil?

      out['periodMs'] = p
    end
    out
  end

  # ---- catalog ------------------------------------------------------------------------------------------------------------

  # A catalog (an Array of action specs, String keys like BUILTIN_ACTIONS) indexed by verb; a later spec overrides an
  # earlier one.
  class FacadeCatalog
    def initialize(actions)
      @by_verb = {}
      actions.each { |a| @by_verb[a['verb']] = a }
    end

    def get(verb) = @by_verb[verb]

    # An alias of exactly one action of the connector (`stripe.issue_refund` is `stripe.refund`); never a guess.
    def resolve(connector, action)
      exact = @by_verb["#{connector}.#{action}"]
      return exact if exact

      hits = @by_verb.values.select { |a| a['connector'] == connector && (a['aliases'] || []).include?(action) }
      hits.length == 1 ? hits[0] : nil
    end

    # The spec of a verb; an uncatalogued verb counts as irreversible with a high blast radius.
    def spec_for(verb)
      s = get(verb)
      return s if s

      dot = verb.index('.')
      via = dot && dot.positive? ? resolve(verb[0...dot], verb[(dot + 1)..]) : nil
      return via if via

      parts = verb.split('.', -1)
      rest = parts[1..].join('.')
      { 'connector' => parts[0] || verb, 'action' => rest.empty? ? verb : rest, 'verb' => verb, 'reversibility' => 'irreversible',
        'blastRadius' => 0.8, 'description' => "(uncatalogued) #{verb}" }
    end
  end

  def facade_catalog(catalog) = FacadeCatalog.new(catalog.nil? ? BUILTIN_ACTIONS : catalog)

  def reversibility_rank(cls) = REVERSIBILITY_ORDER.index(cls) || -1

  def now_ms = (Time.now.to_f * 1000).to_i

  # ---- compile ------------------------------------------------------------------------------------------------------------

  # Compile permissions ({connector => [actions]}) and limits ({action or connector.action => "$N[/period]" | "N[/period]"})
  # into {'predicates', 'caveats', 'riskPolicy', 'actions', 'budgetModel', 'limits', 'inputLimits', 'approximations'}. Pure:
  # no keys.
  #
  # A money limit becomes a per-call ceiling on the action's amount field; a period becomes the grant lifetime (`expires`); each
  # count limit with a period becomes one `rate` caveat; `reversibility_max` is the strictest granted class. A money limit on a
  # verb without an amount field is refused (it could not be enforced). budget_model: 'dollars', 'risk' or nil ('auto').
  def compile_policy(permissions, limits = nil, catalog: nil, budget_model: nil, risk_policy: nil, now: nil)
    cat = facade_catalog(catalog)
    at = now.nil? ? now_ms : now
    raw = limits.nil? ? {} : limits
    raise ArgumentError, 'compilePolicy: permissions must be an object' unless permissions.is_a?(Hash)

    actions = []
    permissions.each do |connector, acts|
      raise ArgumentError, "compilePolicy: permissions.#{connector} must be an array" unless acts.is_a?(Array)

      acts.each { |action| actions << cat.spec_for("#{connector}.#{Predicates.js_string(action)}") }
    end
    raise ArgumentError, 'compilePolicy: no permissions granted' if actions.empty?

    # own keys only; a JSON null is no limit
    own = ->(key) { raw.is_a?(Hash) && key.is_a?(String) ? raw[key] : nil }
    parsed = {}
    limit_for = lambda do |s|
      r = own.call(s['verb'])
      r = own.call(s['action']) if r.nil?
      (s['aliases'] || []).each { |a| r = own.call(a) if r.nil? }
      next nil if r.nil?

      parsed[s['verb']] = parse_limit(r)
    end

    predicates = actions.map do |s|
      lim = limit_for.call(s)
      usd = lim && lim['unit'] == 'usd'
      if usd && !s['amountField']
        raise ArgumentError, "compilePolicy: '$' limit on '#{s['verb']}' but the catalog gives that verb no amount field, so the limit could not be enforced"
      end

      p = { 'verb' => s['verb'], 'resource' => s['resource'] || '*' }
      if usd
        field = "action.params.#{s['amountField']}"
        p['where'] = [{ 'field' => field, 'op' => 'lte', 'value' => lim['amount'] }, { 'field' => field, 'op' => 'gte', 'value' => 0 }]
      end
      p
    end

    strictest = actions.reduce('reversible') { |acc, s| reversibility_rank(s['reversibility']) > reversibility_rank(acc) ? s['reversibility'] : acc }
    caveats = [{ 'type' => 'reversibility_max', 'class' => strictest }]
    periods = parsed.values.filter_map { |l| l['periodMs'] }
    caveats << { 'type' => 'expires', 'at' => at + periods.min } unless periods.empty?
    # one rate caveat per count limit: a second limit can only narrow
    parsed.each_value do |l|
      caveats << { 'type' => 'rate', 'max' => l['amount'], 'per_secs' => [1, (l['periodMs'] / 1000.0 + 0.5).floor].max } if l['unit'] == 'count' && l['periodMs']
    end

    dollars = parsed.values.select { |l| l['unit'] == 'usd' }
    model = if budget_model == 'dollars' then 'dollars'
            elsif budget_model == 'risk' then 'risk'
            else dollars.empty? ? 'risk' : 'dollars'
            end
    irreversible = actions.any? { |s| s['reversibility'] == 'irreversible' }
    rp = if model == 'dollars' && !dollars.empty?
           kappa = dollars.map { |l| l['amount'] }.max
           b_max = dollars.sum(0) { |l| l['amount'] }
           # within-cap actions auto-approve only when nothing granted is irreversible
           { 'weights' => { 'alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0 },
             'theta1' => irreversible ? DEFAULT_RISK_POLICY['theta1'] : 1, 'theta2' => irreversible ? DEFAULT_RISK_POLICY['theta2'] : 1,
             'kappa' => kappa.positive? ? kappa : 1, 'lambda' => 0, 'rho' => DEFAULT_RISK_POLICY['rho'], 'bMax' => b_max.positive? ? b_max : 1 }
         else
           DEFAULT_RISK_POLICY.merge('weights' => DEFAULT_RISK_POLICY['weights'].dup)
         end
    if risk_policy
      w = rp['weights'].merge(risk_policy['weights'] || {})
      rp = rp.merge(risk_policy).merge('weights' => w)
    end
    bad = risk_policy_error(rp)
    raise ArgumentError, "compilePolicy: derived risk policy invalid: #{bad}" if bad

    approximations = parsed.select { |_, l| l['unit'] == 'usd' && l.key?('periodMs') }.map do |v, l|
      "#{v}: $#{Predicates.js_number_string(l['amount'])}/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"
    end
    { 'predicates' => predicates, 'caveats' => caveats, 'riskPolicy' => rp, 'actions' => actions, 'budgetModel' => model,
      'limits' => parsed, 'inputLimits' => raw.is_a?(Hash) ? raw.dup : {}, 'approximations' => approximations }
  end

  # ---- ECMAScript Number(params[field]) for the dollar risk claim -------------------------------------------------------

  JS_NUM_RE = /\A[+-]?(?:Infinity|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)\z/
  JS_RADIX = [[/\A0[xX][0-9a-fA-F]+\z/, 16], [/\A0[oO][0-7]+\z/, 8], [/\A0[bB][01]+\z/, 2]].freeze

  def js_string_to_number(s)
    t = js_trim(s)
    return 0.0 if t.empty?

    JS_RADIX.each { |rx, base| return t[2..].to_i(base).to_f if rx.match?(t) }
    return Float::NAN unless JS_NUM_RE.match?(t)
    return (t.start_with?('-') ? -Float::INFINITY : Float::INFINITY) if t.include?('Infinity')

    Float(t.sub(/\A\+/, '').sub(/\.(?=\z|[eE])/, '').sub(/\A(-?)\./, '\10.'))
  end

  def js_to_number(params, field)
    return Float::NAN unless params.is_a?(Hash) && params.key?(field)

    v = params[field]
    case v
    when nil then 0.0
    when true then 1.0
    when false then 0.0
    when Integer, Float then v.to_f
    when String, Array then js_string_to_number(Predicates.js_string(v))
    else Float::NAN
    end
  end

  # Math.max(0, Math.min(1, x)): NaN stays NaN, as in the reference.
  def js_clamp01(x) = x.is_a?(Float) && x.nan? ? x : [0, [1, x].min].max

  def facade_risk_for(policy, spec, params, override = nil)
    return js_clamp01(override) if override.is_a?(Integer) || override.is_a?(Float)

    if policy['budgetModel'] == 'dollars' && spec['amountField']
      amt = js_to_number(params, spec['amountField'])
      return js_clamp01(amt / policy['riskPolicy']['kappa']) if amt.finite? && policy['riskPolicy']['kappa'].positive?
    end
    js_clamp01(spec['blastRadius'])
  end

  # What create_agent returns: the signed grant and chain, the compiled policy, the holder key, the starting trust budget, and
  # #act / #dry_run / #sub_agent / #encode_grant. `provenance` is the session's recorder: record the principal's message and
  # every tool, retrieval or web result entering the model's context; #act appends the action.
  class AgentHandle
    attr_reader :grant, :chain, :goal_salt, :policy, :holder, :principal_public, :provenance, :counter, :budget, :autonomy_bound

    def initialize(grant:, chain:, goal_salt:, policy:, holder:, principal_public:, catalog:, aud:, start_now:, provenance:)
      @grant = grant
      @chain = chain
      @goal_salt = goal_salt
      @policy = policy
      @holder = holder
      @principal_public = principal_public
      @catalog = catalog
      @aud = aud
      @start_now = start_now
      @provenance = provenance
      @counter = 0
      @lock = Mutex.new
      rp = policy['riskPolicy']
      @budget = { 'B' => rp['bMax'], 'tau' => start_now, 'asOf' => start_now }
      @autonomy_bound = Risk.safety_bound(rp) * rp['kappa']
    end

    # Local, NON-authoritative pre-check of the grant's own predicates and caveats: {'allowed', 'reason'?, 't'?} where 't' is the
    # risk tier the compiled policy would assign (1 automatic, 2, 3 human co-sign).
    def dry_run(verb, resource, params = nil, now: nil)
      spec = @catalog.spec_for(verb)
      at = now.nil? ? AtlasPca.now_ms : now
      ctx = { 'action' => { 'verb' => verb, 'resource' => resource, 'params' => params.nil? ? {} : params,
                            'reversibility_class' => spec['reversibility'] } }
      pred = AtlasPca.evaluate_predicates(@policy['predicates'], ctx)
      return { 'allowed' => false, 'reason' => pred['reason'] || 'no predicate matched' } unless pred['allowed']

      # the local handle has no admitted-action history (the server meters it)
      ok, failed = AtlasPca.evaluate_caveats(@policy['caveats'], { 'now' => at, 'blast_radius' => spec['blastRadius'],
                                                                   'reversibility_class' => spec['reversibility'],
                                                                   'delegation_depth' => @chain.length - 1, 'recent_action_times' => [] })
      return { 'allowed' => false, 'reason' => "caveat(s) failed: #{failed.join(', ')}" } unless ok

      adm = Risk.admit(AtlasPca.facade_risk_for(@policy, spec, params), @budget, @policy['riskPolicy'])
      { 'allowed' => true, 't' => adm['t'] }
    end

    # Build a proof-carrying action (it does NOT authorize). Returns {'pcactn', 'encoded', 'headers', 'dry_run', 'provenance'}:
    # send `headers` (PCA-Action, and PCA-Provenance when the bundle fits a header; else send `provenance` as the body member
    # `pca_provenance`). The counter auto-increments; no nonce unless given.
    def act(verb, resource, params = nil, counter: nil, aud: nil, now: nil, ttl_ms: nil, nonce: nil, caution: nil, risk: nil)
      a = aud.nil? ? @aud : aud
      raise ArgumentError, 'act: aud (resource-server / instance id) is required (pass aud: here or to create_agent)' if a.nil? || a == ''

      spec = @catalog.spec_for(verb)
      # the node commits the SAME params digest the action carries, else plan inclusion fails
      node = { 'id' => 'n0', 'verb' => verb, 'resource' => resource, 'reversibility_class' => spec['reversibility'],
               'params_digest' => AtlasPca.params_digest(params) }
      r = AtlasPca.facade_risk_for(@policy, spec, params, risk)
      use = @lock.synchronize do
        if counter.nil?
          @counter += 1
        else
          @counter = [@counter, counter].max
          counter
        end
      end
      kw = ttl_ms.nil? ? {} : { ttl_ms: ttl_ms }
      pcactn = AtlasPca.build_pcactn(grant: @grant, chain: @chain, plan: [node], node_id: 'n0', counter: use, signer: @holder, aud: a,
                                     params: params, iat: now, extra: { 'nonce' => nonce, 'caution' => caution,
                                                                         'risk_claim' => { 'r' => r, 'inputs' => { 'blastRadius' => r } } }, **kw)
      bundle = @provenance&.for_action({ 'verb' => verb, 'resource' => resource, 'params' => params.nil? ? {} : params })
      { 'pcactn' => pcactn, 'encoded' => AtlasPca.canonicalize(pcactn), 'headers' => AtlasPca.pca_headers(pcactn, provenance: bundle),
        'dry_run' => dry_run(verb, resource, params, now: now), 'provenance' => bundle }
    end

    # A new handle for a sub-agent (a fresh Ed25519 holder unless given) whose chain has one more, narrower hop signed by this
    # holder. It shares the policy, catalog and provenance recorder.
    def sub_agent(holder: nil, added_caveats: [])
      sub = holder || KeyPair.generate
      child = AtlasPca.delegate_cap(@chain.last, @holder, to_holder: sub.public, added: added_caveats)
      AgentHandle.new(grant: @grant, chain: @chain + [child], goal_salt: @goal_salt, policy: @policy, holder: sub,
                      principal_public: @principal_public, catalog: @catalog, aud: @aud, start_now: @start_now, provenance: @provenance)
    end

    # The grant as JSON text (canonical) for transport or inspection.
    def encode_grant = AtlasPca.canonicalize(@grant)

    def inspect = "#<AtlasPca::AgentHandle holder=#{@holder.public}>"
  end

  # Compile the principal's inputs into a signed root grant for `holder` (a KeyPair, generated when omitted) and return the
  # AgentHandle.
  #
  # `limits` keys are a bare action ('refund'), a full verb ('stripe.refund') or an alias. budget_model 'dollars' makes
  # spend = risk exact when limits are monetary (nil, the default, picks it iff a '$' limit is present). `provenance` overrides
  # the recorder's options (mediator 'agent-harness', kid 'k1', key:, session:, now:, alg:, pq:); its key is named in the
  # grant's signed envelope (`provenance.mediators`). goal_salt fixes the goal commitment's salt.
  def create_agent(principal:, goal:, permissions:, limits: nil, holder: nil, agent_binding: nil, risk_policy: nil, budget_model: nil,
                   catalog: nil, aud: nil, now: nil, goal_salt: nil, provenance: nil)
    at = now.nil? ? now_ms : now
    h = holder || KeyPair.generate
    policy = compile_policy(permissions, limits, catalog: catalog, budget_model: budget_model, risk_policy: risk_policy, now: at)
    recorder = ProvenanceRecorder.new(**{ mediator: 'agent-harness', kid: 'k1' }.merge(provenance || {}))
    # the principal designates the harness's mediator key: a verifier trusts its labels with no extra configuration
    minted = mint_grant(principal, h.public, { 'predicates' => policy['predicates'], 'caveats' => policy['caveats'],
                                               'agent_binding' => agent_binding.nil? ? {} : agent_binding,
                                               'risk_policy' => policy['riskPolicy'], 'provenance' => { 'mediators' => [recorder.pin] } },
                        goal, salt: goal_salt)
    g = minted['grant']
    AgentHandle.new(grant: g, chain: [g], goal_salt: minted['goal_salt'], policy: policy, holder: h, principal_public: principal.public,
                    catalog: facade_catalog(catalog), aud: aud, start_now: at, provenance: recorder)
  end
end
