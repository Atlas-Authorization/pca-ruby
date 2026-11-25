# frozen_string_literal: true

# Replays the TS-reference oracle of the Azure MAA key trust and the release-signed pins (test-data/ref-attest-maa.json.gz, 261 cases): the guarded
# certificate fetch over a scripted transport, the evaluation of key sets (the real public Azure certificate sets, the shipped pin manifest and
# synthetic certificates forged under fixed seeds), the rotation-safe trust store (scenarios with a scripted fetch, an initial state and a
# release-signed re-pin), the durable state adapter, k-of-n corroboration and the built-in pins. Every fn has a handler and the totals are asserted.
# Encodings: {"$blob": id} stands for a string over 400 characters held in the corpus's blob table (hydrated in the arguments AND the results);
# {"$bytes": b64url} bytes; {"$throws": msg} a reference refusal. A reason with the platform's own text ('error:...' from OpenSSL, 'The first argument
# ...' from node) compares by presence only. The certificate with a trailing byte (syn-cert-trailing-byte) is ACCEPTED, as the reference's
# OpenSSL tolerance does. Built-in pins are signed under a hybrid ML-DSA suite, so those cases need a runtime that has it (OpenSSL >= 3.5).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefAttestMaa < Minitest::Test
  A = AtlasPca
  M = AtlasPca::AttestMaa
  PQ = A.supported_suites.include?('ml-dsa-65')
  LIB = /\Aerror:[0-9A-Fa-f]{8}:|\AThe first argument/

  def self.load
    txt = Zlib::GzipReader.open(File.join(Ref::DATA, 'ref-attest-maa.json.gz'), &:read).force_encoding('UTF-8')
    d = AtlasPca::JsonParser.new(txt, true, true, json_text: true).parse_document
    blobs = d['blobs']
    hyd = lambda do |x|
      case x
      when Array then x.map { |e| hyd.call(e) }
      when Hash then x.keys == ['$blob'] ? blobs.fetch(x['$blob']) : x.to_h { |k, v| [k, hyd.call(v)] }
      else x
      end
    end
    cases = d['cases'].map { |c| c.merge('args' => hyd.call(c['args']), 'out' => hyd.call(c['out'])) }
    Ref.unseed({ 'cases' => cases })['cases'].group_by { |c| c['fn'] }
  end

  BY_FN = load

  # an in-memory durable store (the DurableState contract)
  class MemKv
    def initialize = @m = {}
    def get(key) = @m.key?(key) ? JSON.parse(@m[key]) : nil

    def update(key)
      nxt = yield(get(key))
      @m[key] = JSON.generate(nxt) unless nxt.nil?
      get(key)
    end

    def snapshot = @m.transform_values { |v| JSON.parse(v) }
  end

  # the scripted response of a case, in the transport's shape
  def self.respond(r)
    raise r['$throws'] if r['$throws']

    body = r['body']
    bytes = if r['bodyBytes'] then Ref.dec(r['bodyBytes'])
            elsif body.is_a?(Hash) && body.key?('$text') then body['$text'].b
            else JSON.generate(body).b
            end
    status = r.fetch('status', 200)
    res = { 'ok' => status >= 200 && status < 300, 'status' => status, 'headers' => {}, 'body' => bytes }
    res['headers']['content-length'] = r['contentLength'].to_s if r.key?('contentLength')
    res['url'] = r['url'] if r.key?('url')
    res
  end

  def self.script(steps, log)
    i = -1
    lambda do |url, init|
      log << (init['redirect'] == 'error' ? "#{url} [redirect:error]" : url)
      s = steps[[i += 1, steps.length - 1].min]
      respond(s.key?('keys') && !s.key?('body') ? { 'body' => s } : s)
    end
  end

  def self.fetch_certs(c)
    log = []
    opts = c['opts'] || {}
    out = begin
      { 'ok' => true, 'jwks' => M.fetch_maa_certs(c['issuer'], fetch: script([c['response']], log), timeout_ms: opts['timeoutMs'], max_bytes: opts['maxBytes']) }
    rescue StandardError => e
      { 'ok' => false, 'error' => e.message }
    end
    out.merge('requests' => log)
  end

  def self.trust(sc)
    store = M.create_memory_maa_key_state_store
    (sc['initial'] || {}).each { |k, v| store.set(k, v) }
    log = []
    t = M.create_maa_key_trust(policy: sc['policy'], store: store, fetch: script(sc['fetches'], log))
    results = sc['calls'].map { |c| t.get_trust_anchors(c['issuer'], now_ms: c['nowMs'], repin: c['repin']) }
    { 'results' => results, 'store' => store.snapshot, 'fetches' => log }
  end

  def self.kv_store(c)
    kv = MemKv.new
    st = M.durable_maa_key_state_store(kv)
    results = c['steps'].map do |s|
      if s.key?('set')
        st.set(s['set'][0], s['set'][1])
        nil
      else
        st.get(s['get'])
      end
    end
    { 'results' => results, 'kv' => kv.snapshot }
  end

  def self.build_trust(c)
    M.create_maa_key_trust(policy: c['policy'], store: M.create_memory_maa_key_state_store, fetch: c['noFetch'] ? nil : ->(_u, _i) { { 'ok' => true, 'status' => 200, 'body' => '{}' } })
    { 'built' => true }
  end

  HANDLERS = {
    'constants' => lambda {
      { 'BUILTIN_CHAIN_LEAF_CN' => M::BUILTIN_CHAIN_LEAF_CN, 'BUILTIN_MAA_PINS_ISSUER_ID' => M::BUILTIN_MAA_PINS_ISSUER_ID,
        'BUILTIN_MAA_PINS_ISSUER_KEYS' => M::BUILTIN_MAA_PINS_ISSUER_KEYS }
    },
    'evaluateMaaJwks' => ->(jwks, issuer, policy, now) { M.evaluate_maa_jwks(jwks, issuer, policy, now) },
    'loadBuiltinMaaPins' => ->(a) { M.load_builtin_maa_pins(a) },
    'corroborate' => ->(sets, k, opts) { M.corroborate_maa_key_sets(sets, k, opts) },
    'fetchCerts' => ->(c) { fetch_certs(c) },
    'trust' => ->(sc) { trust(sc) },
    'kvStore' => ->(c) { kv_store(c) },
    'buildTrust' => ->(c) { build_trust(c) }
  }.freeze

  TOTALS = { 'constants' => 1, 'evaluateMaaJwks' => 92, 'loadBuiltinMaaPins' => 32, 'corroborate' => 26, 'fetchCerts' => 36, 'trust' => 60,
             'kvStore' => 5, 'buildTrust' => 9 }.freeze

  # the pin manifest is signed under a hybrid ML-DSA suite, so the cases that load pins need it
  def self.pq_case?(c)
    return true if c['fn'] == 'loadBuiltinMaaPins'

    c['fn'] == 'trust' && c['args'][0]['policy']['builtinPins'] != false
  end

  # a result compares by value; a string the reference took from the platform compares by presence
  def self.same?(got, ref)
    case ref
    when Hash then got.is_a?(Hash) && got.keys.sort == ref.keys.sort && ref.all? { |k, v| same?(got[k], v) }
    when Array then got.is_a?(Array) && got.length == ref.length && ref.each_with_index.all? { |v, i| same?(got[i], v) }
    when String then ref.match?(LIB) || ref.include?('error:0') ? got.is_a?(String) && !got.empty? : got == ref
    else Ref.canon(got) == Ref.canon(ref)
    end
  end

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 261, BY_FN.values.sum(&:length)
  end

  def test_the_post_quantum_cases_run_where_required
    assert PQ, 'this runtime must have ML-DSA-65' if ENV['PCA_REQUIRE_PQ'] == '1'
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args) }, skip: ->(c) { !PQ && k.pq_case?(c) },
              compare: ->(got, out, _c) { k.same?(Ref.norm(got), Ref.norm(out)) })
    end
  end
end
