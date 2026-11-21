# frozen_string_literal: true

# Replays the TS-reference oracle of the Shared Signals Framework / CAEP (test-data/ref-signals.json.gz): token build and
# verification, revocation state, replay store, receiver, adapters, stream health, verification, poll queue, push response,
# CAEP builders and the stream management API. Scenario fns replay the reference's scripted operations over the native API.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/signals'
require 'minitest/autorun'
require 'digest'
require 'openssl'

class TestRefSignals < Minitest::Test
  S = AtlasPca::Signals
  BY_FN = Ref.load('signals')
  CLOCK = Ref.clock_ms('signals')
  ET = S::EVENT_TYPES
  K1_SEED = Digest::SHA256.digest('atlas-pca-conformance/ref-signals/tx')
  K1 = OpenSSL::PKey.new_raw_private_key('ED25519', K1_SEED)
  K1_PUB = K1.raw_public_key

  class Coded < StandardError
    attr_reader :code

    def initialize(code, msg)
      super(msg)
      @code = code
    end
  end

  # the reference imports a public JWK through the platform crypto; a malformed one is refused with a platform code
  def self.pub(jwk)
    return jwk unless jwk.is_a?(Hash)
    raise Coded.new('ERR_CRYPTO_INVALID_JWK', 'Invalid JWK') unless jwk['kty'] == 'OKP' && jwk['crv'] == 'Ed25519' && jwk['x'].is_a?(String)

    Ref.b64d(jwk['x'])
  end

  def self.priv(jwk)
    return jwk unless jwk.is_a?(Hash)
    raise Coded.new('ERR_CRYPTO_INVALID_JWK', 'JWK does not contain private key material') unless jwk['kty'] == 'OKP' && jwk['d'].is_a?(String)

    Ref.b64d(jwk['d'])
  end

  def self.err_out(e)
    c = e.respond_to?(:code) ? e.code : nil
    out = { '$err' => true }
    out['code'] = c if c.is_a?(String) && !c.start_with?('ERR_') && !c.start_with?('N')
    out
  end

  def self.state_out(st)
    { 'grants' => st.revoked_grants.to_a, 'agents' => st.killed_agents.to_a,
      'intents' => st.revoked_intent_ids&.to_a }
  end

  UUID = /\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/

  def self.shape(set)
    h, p, s = set.split('.')
    header = JSON.parse(Ref.b64d(h).force_encoding('UTF-8'))
    payload = JSON.parse(Ref.b64d(p).force_encoding('UTF-8'))
    payload['iat'] = '<now>' if payload['iat'].is_a?(Numeric) && (((payload['iat'] * 1000) - (Time.now.to_f * 1000)).abs < 120_000 || ((payload['iat'] * 1000) - CLOCK).abs < 120_000)
    payload['jti'] = '<uuid>' if payload['jti'].is_a?(String) && UUID.match?(payload['jti'])
    pk = OpenSSL::PKey.new_raw_public_key('ED25519', K1_PUB)
    ok = begin
      pk.verify(nil, Ref.b64d(s), "#{h}.#{p}")
    rescue OpenSSL::PKey::PKeyError
      false
    end
    { 'header' => header, 'payload' => payload, 'sigOk' => ok }
  end

  def self.parsed_out(r)
    out = { 'events' => r['events'], 'iss' => r['iss'], 'jti' => r['jti'], 'payload' => r['payload'] }
    out['sub'] = r['sub'] if r.key?('sub')
    out
  end

  MAPPERS = {
    'email' => ->(s) { s['format'] == 'email' && s['email'].is_a?(String) ? s['email'] : nil },
    'throws' => ->(_s) { raise 'x' },
    'empty' => ->(_s) { '' },
    'num' => ->(_s) { 5 },
    'id' => ->(s) { s['id'].is_a?(String) ? s['id'] : nil },
    'prefixed' => ->(s) { s['id'].is_a?(String) ? "agent:#{s['id']}" : nil }
  }.freeze

  def self.std_opts(sp)
    return nil if sp.nil?

    o = {}
    o['subject_to_agent'] = MAPPERS[sp['mapper']] if sp['mapper'] && sp['mapper'] != 'default'
    o['fail_on_unmapped'] = sp['fail'] if sp.key?('fail')
    o
  end

  AGENTS = {
    'throws' => ->(_ctx) { raise 'x' },
    'empty' => ->(_ctx) { '' },
    'num' => ->(_ctx) { 5 },
    'grantId' => ->(ctx) { ctx['grant'].is_a?(Hash) ? ctx['grant']['id'] : nil }
  }.freeze

  def self.agent_of(name)
    return nil if name.nil? || name == 'leaf'
    return ->(_ctx) { name[6..] } if name.is_a?(String) && name.start_with?('const:')

    AGENTS[name]
  end

  CONSTANTS = lambda do
    { 'SET_TYP' => S::SET_TYP, 'SET_ALG' => S::SET_ALG, 'EVENT_TYPES' => S::EVENT_TYPES, 'RISC_EVENT_TYPES' => S::RISC_EVENT_TYPES,
      'SET_INMEMORY_MAX_ENTRIES' => S::SET_INMEMORY_MAX_ENTRIES, 'DELIVERY_PUSH' => S::DELIVERY_PUSH,
      'DELIVERY_POLL' => S::DELIVERY_POLL, 'STREAM_STATUSES' => S::STREAM_STATUSES }
  end

  VERIFY = ->(set, key, op) { parsed_out(S.verify_set(set, pub(key), op.is_a?(Hash) ? Ref.snake(op) : op)) }

  BUILD_SHAPE = lambda do |a|
    seed = priv(a['keyJwk'])
    shape(S.build_set(a['events'], a['issuer'], a['audience'], seed, subject: a['subject']))
  end

  STATE = lambda do |spec|
    st = S.create_revocation_state
    out = spec['ops'].map do |s|
      target = s['badState'] ? {} : st
      case s['op']
      when 'apply' then S.apply_set(st, s['parsed']) && state_out(st)
      when 'applyStd' then { 'plan' => S.apply_standard_revocations(target, s['parsed'], std_opts(s['std'])), 'state' => state_out(st) }
      when 'plan' then S.plan_standard_revocations(s['parsed'], std_opts(s['std']))
      when 'isRevoked' then S.revoked?(st, s['grant'], s['agent'])
      when 'isIntentRevoked' then S.intent_revoked?(st, s['id'])
      when 'stream' then state_out(S.stream_processor(s['sets'], s['useState'] ? st : nil))
      when 'snapshot' then S.snapshot_revocation_state(target)
      when 'restore'
        into = if s['fresh'] then S::DEFAULT
               elsif s['nullInto'] then nil
               else target
               end
        state_out(S.restore_revocation_state(s['snapshot'], into))
      else raise 'bad op'
      end
    rescue StandardError => e
      err_out(e)
    end
    out << state_out(st)
  end

  REPLAY = lambda do |spec|
    store = begin
      S.create_in_memory_set_replay_store(spec.key?('opts') ? Ref.snake(spec['opts']) : S::DEFAULT)
    rescue StandardError => e
      next [err_out(e)]
    end
    spec['ops'].map do |jti, exp, now|
      store.add_if_absent(jti, exp, now)
    rescue StandardError
      { '$err' => true }
    end
  end

  class ConstStore
    def initialize(v) = @v = v
    def add_if_absent(_jti, _exp, _now) = @v
  end

  class NoExpiryStore
    def initialize = @seen = {}

    def add_if_absent(jti, _exp, _now)
      return false if @seen.key?(jti)

      @seen[jti] = true
    end
  end

  class ThrowsStore
    def add_if_absent(_jti, _exp, _now) = raise('boom')
  end

  REPLAY_CONFORMANCE = lambda do |spec|
    make = lambda do
      case spec['store']
      when 'alwaysTrue' then ConstStore.new(true)
      when 'alwaysFalse' then ConstStore.new(false)
      when 'noExpiry' then NoExpiryStore.new
      else S.create_in_memory_set_replay_store(spec.key?('opts') ? Ref.snake(spec['opts']) : S::DEFAULT)
      end
    end
    S.run_set_replay_store_conformance(make)
  end

  RECEIVE = lambda do |spec|
    st = S.create_revocation_state
    store = case spec['store']
            when 'throws' then ThrowsStore.new
            when 'false' then ConstStore.new(false)
            when 'mem1' then S.create_in_memory_set_replay_store({ 'max_entries' => 1 })
            else S.create_in_memory_set_replay_store
            end
    out = spec['deliveries'].map do |d|
      op = Ref.snake(d['opts'] || {})
      op['replay_store'] = store unless d['noStore']
      op['state'] = st unless d['noState']
      op['standard_revocations'] = std_opts(d['std']) unless d['std'].nil?
      r = begin
        key = d.key?('key') ? d['key'] : nil
        S.receive_set(d['set'], key.nil? ? K1_PUB : pub(key), d['noOpts'] ? nil : op)
      rescue StandardError
        { '$err' => true }
      end
      if r['ok'] == false && r['code'] == 'verify_failed' && !r['reason'].to_s.start_with?('SET invalid:')
        r = r.merge('reason' => '<jose>')
      end
      r['ok'] == true ? { 'ok' => true, 'parsed' => parsed_out(r['parsed']) } : r
    end
    out << state_out(st)
  end

  ADAPTER = lambda do |spec|
    begin
      st = if spec.key?('badState')
             spec['badState'] == 'null' ? nil : {}
           else
             S.restore_revocation_state({ 'v' => 1, 'grants' => spec['grants'] || [], 'agents' => spec['agents'] || [], 'intents' => [] })
           end
      opts = { 'agent_of' => agent_of(spec['agentOf']) }
      hook = S.create_revocation_hook(st, opts)
      is_rev = S.create_is_revoked(st, opts)
    rescue StandardError => e
      next [err_out(e)]
    end
    spec['calls'].map do |c|
      a = begin
        hook.call({ 'pcactn' => c['pcactn'], 'grant' => c['grant'] })
      rescue StandardError
        { '$err' => true }
      end
      b = begin
        is_rev.call(c['grant'], c['pcactn'])
      rescue StandardError
        { '$err' => true }
      end
      { 'hook' => a, 'isRevoked' => b }
    end
  end

  CFG = { 'stream_id' => 's1', 'iss' => 'https://tx.example', 'aud' => 'rx', 'events_supported' => [ET['grantRevoked'], ET['killSwitch']],
          'events_delivered' => [ET['grantRevoked']], 'delivery' => { 'method' => S::DELIVERY_POLL, 'endpoint_url' => 'https://tx.example/poll/s1' },
          'min_verification_interval' => 30, 'description' => 'd' }.freeze

  HEALTH = lambda do |spec|
    h = S::StreamHealth.new(spec['config'] || CFG, spec['opts'].nil? ? nil : Ref.snake(spec['opts']))
    issued = []
    spec['ops'].map do |s|
      case s['op']
      when 'status'
        h.status = s['v']
        nil
      when 'event'
        h.record_event(s['now'])
        nil
      when 'request'
        r = h.request_verification(s['now'])
        if r.is_a?(String)
          issued << r
          "<state:#{issued.length - 1}>"
        end
      when 'ack'
        state = s.key?('ref') ? (s['ref'] >= 0 && s['ref'] < issued.length ? issued[s['ref']] : nil) : s['state']
        h.ack_verification(state, s['now'])
      when 'report' then h.report(s['now'])
      when 'fresh' then h.revocation_fresh_within(s['max'], s['now'])
      else raise 'bad op'
      end
    rescue StandardError
      { '$err' => true }
    end
  end

  VERIFICATION = lambda do |spec|
    streams = Marshal.load(Marshal.dump(spec['streams'] || {}))
    out = spec['ops'].map do |s|
      r = S.handle_verification_request(streams, s['req'], s['now'], s['noKey'] ? nil : K1_SEED)
      r['status'] == 204 ? { 'status' => 204, 'set' => shape(r['set']) } : r
    rescue StandardError
      { '$err' => true }
    end
    out << streams.transform_values { |v| v['lastVerification'] }
  end

  POLL = lambda do |spec|
    q = S::PollQueue.new
    out = spec['ops'].map do |s|
      if s.key?('enqueue')
        q.enqueue(s['enqueue'][0], s['enqueue'][1])
        nil
      elsif s['depth']
        q.depth
      else
        q.poll(s['poll'])
      end
    rescue StandardError
      { '$err' => true }
    end
    out << { 'depth' => q.depth, 'errors' => q.errors }
  end

  CAEP = lambda do |a|
    args = { 'issuer' => a['issuer'], 'audience' => a['audience'], 'key' => priv(a['keyJwk']), 'event' => a['event'], 'order' => a['order'] }
    shape(a['kind'] == 'risk' ? S.risk_level_change_set(args) : S.assurance_level_change_set(args))
  end

  MANAGE = lambda do |spec|
    store = S::MemoryStreamStore.new
    delivered = []
    ids = [0]
    cur = {}
    opts = { 'store' => store, 'issuer' => 'https://tx.example',
             'events_supported' => spec['eventsSupported'] || [ET['grantRevoked'], ET['killSwitch'], ET['sessionRevoked']],
             'poll_endpoint' => ->(i) { "https://tx.example/poll/#{i}" }, 'signing_key' => K1_SEED,
             'deliver' => ->(stream, set) { delivered << { 'stream' => Marshal.load(Marshal.dump(stream)), 'set' => shape(set) } },
             'now' => -> { cur['now'] }, 'new_id' => -> { "s#{ids[0] += 1}" } }
    opts.merge!(Ref.snake(spec['options'] || {}))
    auth = ->(_req) { cur['rcv'] == 'throws' ? raise('auth') : cur['rcv'] }
    h = S.ssf_management_handler(opts, auth)
    out = spec['steps'].map do |st|
      cur.replace('now' => st.fetch('now', 1000), 'rcv' => st.key?('rcv') ? st['rcv'] : { 'id' => 'rx1', 'aud' => 'rx' })
      begin
        h.call(st['req'])
      rescue StandardError
        { '$err' => true }
      end
    end
    dump = (spec['receivers'] || %w[rx1 rx2]).to_h { |rid| [rid, store.list_by_receiver(rid)] }
    out << { 'delivered' => delivered, 'store' => dump }
  end

  MAP = {
    'constants' => CONSTANTS,
    'verifySET' => VERIFY,
    'buildSETShape' => BUILD_SHAPE,
    'stateScenario' => STATE,
    'replayScenario' => REPLAY,
    'replayConformance' => REPLAY_CONFORMANCE,
    'receiveScenario' => RECEIVE,
    'adapterScenario' => ADAPTER,
    'validateStreamConfig' => ->(c) { S.validate_stream_config(c) },
    'healthScenario' => HEALTH,
    'verificationScenario' => VERIFICATION,
    'pollScenario' => POLL,
    'pushResponse' => ->(r) { S.push_response(r) },
    'caepSET' => CAEP,
    'manageScenario' => MANAGE,
    'transmitterMetadata' => ->(o, base, jwks) { S.transmitter_metadata(Ref.snake(o), base, jwks) }
  }.freeze

  def test_corpus_is_the_full_oracle
    assert_equal [], BY_FN.keys - MAP.keys
    assert_equal [], MAP.keys - BY_FN.keys
  end

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  def test_built_token_verifies_and_is_single_use_under_the_receiver
    st = S.create_revocation_state
    store = S.create_in_memory_set_replay_store
    now = Time.now.to_i
    tok = S.build_set({ ET['grantRevoked'] => { 'grant_ref' => 'g', 'reason' => 'r', 'event_timestamp' => now } }, 'iss', 'aud', K1_SEED)
    o = { 'issuer' => 'iss', 'audience' => 'aud', 'replay_store' => store, 'state' => st, 'max_age_sec' => 300 }
    assert_equal true, S.receive_set(tok, K1_PUB, o)['ok']
    assert S.revoked?(st, 'g')
    assert_equal 'replay', S.receive_set(tok, K1_PUB, o)['code']
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2465, BY_FN.values.sum(&:length), 'signals'
  end

end
