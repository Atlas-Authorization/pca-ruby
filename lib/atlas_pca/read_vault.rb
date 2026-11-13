# frozen_string_literal: true

require 'securerandom'

# K5 tokenisation vault and aggregate read limits (C-315..C-319): ports packages/pca/src/read-vault.ts check for check.
# VAULT: redact_read_with_vault records every `token` mask it mints; detokenize returns the value only for the same signed,
# unexpired, pinned-principal grant, a token minted under THIS grant, and a sink whose rule allows (or escalates) the token's class.
# AGGREGATES: aggregate_read is a pure step over an explicit state {spent_micro, queries, answered}: k-anonymity floor, clamped
# sensitivity, query cap, integer micro-epsilon budget, a repeated identical query answered from the state without a charge. With
# dp the answer gets discrete Laplace noise from an INTEGER-EXACT sampler (Canonne-Kamath-Steinke) over a stream of SHA-256
# blocks. Signing is not ported (verification only). String keys; integers only; total (never raises).
# Replays packages/pca/conformance/vault-aggregate-vectors.json. Requires workflow.rb and readside.rb.
module AtlasPca
  AGGREGATE_DOMAIN = "atlas-pca/aggregate-grant/v1\x00".b.freeze
  K5_AG_REF = 'atlas-pca/aggregate-grant-ref/v1'
  K5_AG_Q = 'atlas-pca/aggregate-query/v1'
  K5_AG_N = 'atlas-pca/aggregate-noise/v1'
  K5_DP_STREAM = 'atlas-pca/dp-stream/v1'
  K5_TWO48 = 2**48
  K5_MAX_STEPS = 100_000
  K5_AG_RULE_KEYS = %w[verb resource_prefix purposes fns min_group clamp epsilon_micro dp].freeze
  K5_AG_BODY_KEYS = %w[v id principal issued_at expires_at rules epsilon_budget_micro max_queries].freeze
  K5_FN_RE = /\A(count|sum)\z/

  # In-process vault: token -> {'cls', 'value', 'grant', 'exp'}.
  class MemoryVault
    def initialize
      @m = {}
      @lock = Mutex.new
    end

    def put(token, entry) = @lock.synchronize { @m[token] = entry }
    def get(token) = @lock.synchronize { @m[token] }
  end

  # The seeded draw source: block i is SHA-256 of the canonical {d, seed, i}; each block yields five 48-bit big-endian values.
  class SeededDraws
    def initialize(seed)
      @seed = seed
      @block = 0
      @buf = []
    end

    def next48
      if @buf.empty?
        bytes = AtlasPca.b64d(AtlasPca.hash_canonical({ 'd' => K5_DP_STREAM, 'seed' => @seed, 'i' => @block }), 32).bytes
        @block += 1
        @buf = (0...5).map { |k| bytes[k * 6, 6].inject(0) { |a, b| (a * 256) + b } }
      end
      @buf.shift
    end

    def uniform(n)
      raise RangeError, 'uniform: bad bound' unless n.is_a?(Integer) && n >= 1 && n <= 2**47

      limit = K5_TWO48 - (K5_TWO48 % n)
      K5_MAX_STEPS.times do
        r = next48
        return r % n if r < limit
      end
      raise RangeError, 'uniform: no draw'
    end
  end

  module_function

  def memory_vault = MemoryVault.new

  # redact_read that also records every token it minted in `store`. Never raises.
  def redact_read_with_vault(inp, store)
    r = redact_read(inp)
    return r unless r['decision'] == 'allow'

    g = inp['grant']['body']
    digest = read_grant_digest(g)
    r['fields'].each do |path, f|
      next unless f['action'] == 'masked' && f['kind'] == 'token'

      store.put(r['view'][path], { 'cls' => f['class'], 'value' => inp['record'][path], 'grant' => digest, 'exp' => g['expires_at'] })
    end
    r
  rescue StandardError
    k5_read_out('deny', 'bad_request')
  end

  # Turn a token back into its value, only for a sink the grant allows that token's class to reach. `inp`: grant, principal,
  # now, sink, token, store.
  def detokenize(inp)
    no = ->(code) { { 'decision' => 'deny', 'code' => code, 'value' => nil } }
    return no.call('bad_request') unless k5_b32?(inp['principal']) && k5_uint?(inp['now']) && inp['token'].is_a?(String) && inp['sink'].is_a?(String)

    sg = inp['grant']
    return no.call('bad_grant') unless sg.is_a?(Hash) && k5_keys?(sg, %w[body sig]) && valid_read_grant_body?(sg['body'])

    b = sg['body']
    return no.call('bad_signature') if b['principal'] != inp['principal'] || !k5_verify_body(READ_GRANT_DOMAIN, b, inp['principal'], sg['sig'])
    return no.call('not_yet') if inp['now'] < b['issued_at']
    return no.call('expired') if inp['now'] >= b['expires_at']

    e = inp['store'].get(inp['token'])
    return no.call('unknown_token') if e.nil? || e['grant'] != read_grant_digest(b)
    return no.call('expired') if inp['now'] >= e['exp']

    rule = b['sinks'][inp['sink']]
    return no.call('unknown_sink') if rule.nil?
    return { 'decision' => 'allow', 'code' => nil, 'value' => e['value'] } if rule['allow'].include?(e['cls'])
    return { 'decision' => 'escalate', 'code' => 'label_escalate', 'value' => nil } if rule['escalate'].include?(e['cls'])

    no.call('label_flow')
  rescue StandardError
    { 'decision' => 'deny', 'code' => 'bad_request', 'value' => nil }
  end

  # ---- aggregates -------------------------------------------------------------------------------------------------------

  def empty_aggregate_state = { 'spent_micro' => 0, 'queries' => 0, 'answered' => {} }

  def k5_valid_agg_rule?(r)
    r.is_a?(Hash) && k5_keys?(r, K5_AG_RULE_KEYS) && k3_str?(r['verb'], 128) && k3_str?(r['resource_prefix'], 512) &&
      k5_sorted_unique?(r['purposes'], K5_ID_RE, 16) && !r['purposes'].empty? && k5_sorted_unique?(r['fns'], K5_FN_RE, 2) && !r['fns'].empty? &&
      k5_uint?(r['min_group']) && r['min_group'] >= 1 && k5_uint?(r['clamp']) && r['clamp'] <= 1_000_000 && k5_uint?(r['epsilon_micro']) &&
      r['epsilon_micro'] <= 1_073_741_824 && [true, false].include?(r['dp']) && (!r['dp'] || r['epsilon_micro'] >= 1)
  end

  def valid_aggregate_grant_body?(b)
    b.is_a?(Hash) && k5_keys?(b, K5_AG_BODY_KEYS) && k5_one?(b['v']) && k5_id?(b['id']) && k5_b32?(b['principal']) && k5_uint?(b['issued_at']) &&
      k5_uint?(b['expires_at']) && b['rules'].is_a?(Array) && b['rules'].length.between?(1, 16) && b['rules'].all? { |r| k5_valid_agg_rule?(r) } &&
      k5_uint?(b['epsilon_budget_micro']) && k5_uint?(b['max_queries'])
  end

  def aggregate_grant_digest(b) = hash_canonical({ 'd' => K5_AG_REF, 'g' => b })

  def seeded_draws(seed) = SeededDraws.new(seed)

  # PRODUCTION noise mode: a seed from the operating system's CSPRNG (answers differ per call; a repeated query is still
  # answered from the state without a new draw).
  def secure_draws = SeededDraws.new(b64e(SecureRandom.random_bytes(32)))

  def k5_bern(d, num, den) = d.uniform(den) < num

  # Bernoulli(exp(-num/den)) for 0 <= num/den <= 1.
  def k5_bern_exp_small(d, num, den)
    (1..K5_MAX_STEPS).each { |k| return k.odd? unless k5_bern(d, num, den * k) }
    raise RangeError, 'bernoulli: no termination'
  end

  # Discrete Laplace with P[x] proportional to exp(-|x| s / t) (CKS Alg. 2). Raises RangeError on a bad bound / no termination.
  def discrete_laplace(d, s, t)
    K5_MAX_STEPS.times do
      u = d.uniform(t)
      next unless k5_bern_exp_small(d, u, t)

      v = 0
      while k5_bern_exp_small(d, 1, 1)
        v += 1
        raise RangeError, 'laplace: no termination' if v > K5_MAX_STEPS
      end
      y = (u + (t * v)) / s
      negative = d.uniform(2) == 1
      next if negative && y.zero?

      return negative ? -y : y
    end
    raise RangeError, 'laplace: no sample'
  end

  def k5_clamped_sum(values, clamp) = values.sum { |v| [-clamp, [clamp, v].min].max }

  # Answer one aggregate under the grant, or refuse. `inp` (String keys): grant, principal, now, verb, resource, purpose, fn,
  # values, salt, noise ('seeded' | 'secure'), state. The input state is never mutated. Never raises.
  def aggregate_read(inp)
    fail_with = ->(code, s = nil) { { 'decision' => 'deny', 'code' => code, 'value' => nil, 'state' => s || empty_aggregate_state, 'charged_micro' => 0 } }
    st = inp['state']
    unless st.is_a?(Hash) && k5_uint?(st['spent_micro']) && k5_uint?(st['queries']) && st['answered'].is_a?(Hash) &&
           st['answered'].values.all? { |v| v.is_a?(Integer) && v.abs <= MAX_SAFE }
      return fail_with.call('bad_request')
    end

    keep = ->(code) { fail_with.call(code, st) }
    return keep.call('bad_request') unless k5_b32?(inp['principal']) && k5_uint?(inp['now'])

    sg = inp['grant']
    return keep.call('bad_grant') unless sg.is_a?(Hash) && k5_keys?(sg, %w[body sig]) && valid_aggregate_grant_body?(sg['body'])

    g = sg['body']
    return keep.call('bad_signature') if g['principal'] != inp['principal'] || !k5_verify_body(AGGREGATE_DOMAIN, g, inp['principal'], sg['sig'])
    return keep.call('not_yet') if inp['now'] < g['issued_at']
    return keep.call('expired') if inp['now'] >= g['expires_at']

    vals = inp['values']
    unless k3_str?(inp['verb'], 128) && k3_str?(inp['resource'], 512) && k5_id?(inp['purpose']) && %w[count sum].include?(inp['fn']) &&
           %w[seeded secure].include?(inp['noise']) && inp['salt'].is_a?(String) && utf16_len(inp['salt']) >= K5_SALT_MIN &&
           vals.is_a?(Array) && vals.length <= 1_000_000 && vals.all? { |v| v.is_a?(Integer) && v.abs <= MAX_SAFE }
      return keep.call('bad_request')
    end

    rule = g['rules'].find { |r| r['verb'] == inp['verb'] && inp['resource'].start_with?(r['resource_prefix']) && r['purposes'].include?(inp['purpose']) }
    return keep.call('no_read_scope') if rule.nil? || !rule['fns'].include?(inp['fn'])
    return keep.call('group_too_small') if vals.length < rule['min_group']

    qd = hash_canonical({ 'd' => K5_AG_Q, 'g' => aggregate_grant_digest(g), 'verb' => inp['verb'], 'resource' => inp['resource'],
                          'purpose' => inp['purpose'], 'fn' => inp['fn'], 'n' => vals.length, 's' => k5_clamped_sum(vals, rule['clamp']) })
    prior = st['answered'][qd]
    return { 'decision' => 'allow', 'code' => nil, 'value' => prior, 'state' => st, 'charged_micro' => 0 } unless prior.nil?
    return keep.call('query_cap') if st['queries'] + 1 > g['max_queries']

    cost = rule['dp'] ? rule['epsilon_micro'] : 0
    return keep.call('epsilon_exhausted') if st['spent_micro'] + cost > g['epsilon_budget_micro']

    exact = inp['fn'] == 'count' ? vals.length : k5_clamped_sum(vals, rule['clamp'])
    if rule['dp']
      sens = inp['fn'] == 'count' ? 1 : rule['clamp']
      draws = inp['noise'] == 'secure' ? secure_draws : seeded_draws(hash_canonical({ 'd' => K5_AG_N, 'salt' => inp['salt'], 'q' => qd }))
      exact += discrete_laplace(draws, rule['epsilon_micro'], sens * 1_000_000)
    end
    nxt = { 'spent_micro' => st['spent_micro'] + cost, 'queries' => st['queries'] + 1, 'answered' => st['answered'].merge(qd => exact) }
    { 'decision' => 'allow', 'code' => nil, 'value' => exact, 'state' => nxt, 'charged_micro' => cost }
  rescue StandardError
    { 'decision' => 'deny', 'code' => 'bad_request', 'value' => nil, 'state' => empty_aggregate_state, 'charged_micro' => 0 }
  end
end
