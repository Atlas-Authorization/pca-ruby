# frozen_string_literal: true

# Replays the TS-reference oracles of the CIBA bridge (test-data/ref-ciba.json.gz and ref-ciba-java.json.gz): the canonical
# action, binding message and auth request, gating, the cosign budget effect, the PING callback, scripted lifecycles of the
# in-memory and durable brokers (memory store and KV store), the KV approval store, client configuration and scripted client
# sessions. Random auth_req_ids and generated notification tokens are masked exactly as the generators mask them.
require_relative 'support/ref_oracle'
require 'minitest/autorun'
require 'tmpdir'

class TestRefCiba < Minitest::Test
  C = AtlasPca::Ciba
  MAIN = Ref.load('ciba')
  JAVA = Ref.load('ciba-java')
  T0 = 1_800_000_000_000
  SU = { 'id' => 'su1', 'verb' => 'stripe.payout', 'resource' => 'acct:1', 'params' => { 'amount' => 80, 'currency' => 'USD', 'payee' => 'bob' },
         'tier' => 3, 'reason' => 'r', 'goalCommit' => 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq', 'goal' => 'pay suppliers',
         'lineage' => {}, 'r' => 0.5, 'requestedAt' => 1 }.freeze

  def self.opts(o)
    return o unless o.is_a?(Hash)

    a = Ref.snake(o)
    a['binding_message'] = Ref.snake(a['binding_message']) if a['binding_message'].is_a?(Hash)
    a
  end

  def self.deep_map(v, &f)
    case v
    when Hash then v.to_h { |k, x| [k, deep_map(x, &f)] }
    when Array then v.map { |x| deep_map(x, &f) }
    else f.call(v)
    end
  end

  def self.call_broker(b, op, id)
    case op['op']
    when 'poll' then b.poll(id)
    when 'token' then b.token(id)
    when 'resolve' then b.resolve(id, op['decision'], op['by'])
    when 'get' then b.get(id)
    end
  end

  LIFECYCLE = lambda do |kind, ops|
    t = [1_000_000]
    now = -> { t[0] }
    b = if kind == 'memory'
          C.create_ciba_broker('now' => now, 'on_complete' => ->(_s) {})
        else
          C.create_durable_ciba_broker('store' => C.create_memory_approval_store, 'now' => now, 'decision_ttl_sec' => 100)
        end
    id = nil
    ops.map do |op|
      if op['op'] == 'now'
        t[0] = op['t']
        next nil
      end
      begin
        v = case op['op']
            when 'start'
              r = b.start(op['stepUp'] || SU, opts(op['opts']))
              id = r['auth_req_id']
              r.merge('auth_req_id' => 'ID')
            when 'unknown'
              op['fn'] == 'resolve' ? b.resolve('nope', 'approve', 'x') : b.public_send(op['fn'], 'nope')
            else call_broker(b, op, id)
            end
        { 'ok' => true, 'value' => deep_map(v) { |x| !id.nil? && x == id ? 'ID' : x } }
      rescue StandardError
        { 'ok' => false }
      end
    end
  end

  BROKER_SCENARIO = lambda do |s|
    clock = [T0]
    completes = []
    oc = s['opts'].is_a?(Hash) ? s['opts']['onComplete'] : nil
    on_complete = if %w[record throws].include?(oc)
                    lambda do |sess|
                      completes << JSON.parse(JSON.generate(Ref.norm(sess)))
                      raise 'notifier down' if oc == 'throws'
                    end
                  end
    kv = store = nil
    o = { 'now' => -> { clock[0] } }
    o['on_complete'] = on_complete if on_complete
    if s['kind'] == 'memory'
      broker = C.create_ciba_broker(o)
    else
      if s['kind'] == 'durable-kv'
        kv = C.create_memory_kv
        store = C.create_kv_approval_store(kv)
      else
        store = C.create_memory_approval_store
      end
      ttl = s['opts'].is_a?(Hash) ? s['opts']['decisionTtlSec'] : nil
      o['decision_ttl_sec'] = ttl unless ttl.nil?
      broker = C.create_durable_ciba_broker(o.merge('store' => store))
    end
    ids = []
    sub = lambda do |x|
      next x unless x.is_a?(String) && x.start_with?('$id')

      (x == '$id' ? ids.last : ids[x[3..].to_i - 1]) || x
    end
    trace = s['steps'].map do |st|
      entry = { 'op' => st['op'] }
      begin
        value = case st['op']
                when 'start'
                  r = broker.start(st['stepUp'], opts(st['opts']))
                  ids << r['auth_req_id'] unless ids.include?(r['auth_req_id'])
                  r
                when 'poll', 'token', 'resolve', 'get' then call_broker(broker, st, sub.call(st['id']))
                when 'advance' then clock[0] += st['ms']
                when 'storeSet'
                  key = AtlasPca::Js.string(st['key']).sub('$id', ids.last || '')
                  cur = store.get(key)
                  store.cas(key, cur ? cur['version'] : 0, st['value'])
                when 'kvRaw'
                  key = AtlasPca::Js.string(st['key']).sub('$id', ids.last || '')
                  kv.put_if_equals(key, kv.get(key), st['raw'])
                end
        entry['ok'] = true
        entry['value'] = value
      rescue StandardError => e
        entry['ok'] = false
        entry['msg'] = e.message
        entry['code'] = e.code if e.respond_to?(:code) && e.code.is_a?(String)
      end
      entry['complete'] = completes.slice!(0..) unless completes.empty?
      entry
    end
    deep_map(trace) do |x|
      next x unless x.is_a?(String)

      ids.each_with_index.reduce(x) { |acc, (id, i)| acc.gsub(id, "<ID#{i + 1}>") }
    end
  end

  KV_SCENARIO = lambda do |s|
    kv = C.create_memory_kv
    store = C.create_kv_approval_store(kv)
    s['steps'].map do |st|
      value = case st['op']
              when 'get' then store.get(st['key'])
              when 'cas' then store.cas(st['key'], st['expected'], st['value'])
              when 'kvSet' then kv.put_if_equals(st['key'], kv.get(st['key']), st['raw'])
              when 'kvGet' then kv.get(st['key'])
              end
      { 'op' => st['op'], 'ok' => true, 'value' => value }
    rescue StandardError => e
      { 'op' => st['op'], 'ok' => false, 'code' => e.respond_to?(:code) ? e.code : 'other' }
    end
  end

  CLIENT_SCENARIO = lambda do |s|
    clock = [T0]
    reqs = []
    sleeps = []
    queue = s['responses'].dup
    fetch = lambda do |url, init|
      reqs << { 'url' => url, 'method' => init['method'], 'headers' => init['headers'], 'body' => init['body'] }
      r = queue.shift
      raise(r.nil? ? 'no scripted response' : 'connection reset') if r.nil? || r['fail']

      { 'status' => r['status'], 'body' => r['body'].is_a?(String) ? r['body'] : AtlasPca::Js.json(r['body']) }
    end
    cfg = Ref.snake(s['cfg']).merge('fetch' => fetch, 'sleep' => ->(ms) { sleeps << ms; clock[0] += ms }, 'now' => -> { clock[0] })
    client = C.create_ciba_client(cfg)
    poller = nil
    nt = ''
    s['steps'].map do |st|
      entry = { 'op' => st['op'] }
      begin
        value = case st['op']
                when 'initiate'
                  flow = client.initiate(st['stepUp'], opts(st['opts']))
                  poller = client.poller(flow)
                  if flow['clientNotificationToken'] && !(st['opts'].is_a?(Hash) && st['opts'].key?('clientNotificationToken'))
                    nt = flow['clientNotificationToken']
                  end
                  flow
                when 'poll' then poller.poll
                when 'wait' then poller.wait
                when 'notify' then poller.notify
                when 'advance' then clock[0] += st['ms']
                when 'interval' then poller.interval_sec
                end
        entry['ok'] = true
        entry['value'] = value
      rescue C::CibaProviderError => e
        entry.merge!('ok' => false, 'error' => e.error, 'status' => e.status, 'retryable' => e.retryable, 'errorDescription' => e.error_description)
      rescue StandardError
        entry.merge!('ok' => false, 'other' => true)
      end
      entry['requests'] = reqs.slice!(0..)
      entry['sleeps'] = sleeps.slice!(0..)
      nt.empty? ? entry : deep_map(entry) { |x| x.is_a?(String) ? x.gsub(nt, '<NTOKEN>') : x }
    end
  end

  MAP = {
    'cibaActionFromStepUp' => ->(s) { C.ciba_action_from_step_up(s) },
    'asciiForm' => ->(s) { C.ascii_form(s) },
    'toCibaAuthRequest' => ->(s, *o) { C.to_ciba_auth_request(s, *o.map { |x| opts(x) }) },
    'requiresCiba' => ->(r) { C.requires_ciba(r) },
    'cibaDecisionToCosign' => ->(d, b, p, n, o = nil) { C.ciba_decision_to_cosign(d, b, p, n, o) },
    'verifyPingCallback' => ->(input, flow) { C.verify_ping_callback(input, flow) },
    'lifecycle' => LIFECYCLE,
    'createCibaClientConfig' => ->(cfg) { C.create_ciba_client(Ref.snake(cfg).merge('fetch' => ->(_u, _i) {})) && true },
    'brokerScenario' => BROKER_SCENARIO,
    'durableBrokerConfig' => lambda do |c|
      o = c['noStore'] ? {} : { 'store' => C.create_memory_approval_store }
      o['decision_ttl_sec'] = c['decisionTtlSec'] if !c['noStore'] && c.key?('decisionTtlSec')
      C.create_durable_ciba_broker(o)
      'ok'
    rescue StandardError
      'throws'
    end,
    'kvScenario' => KV_SCENARIO,
    'clientScenario' => CLIENT_SCENARIO
  }.freeze

  def test_every_fn_is_mapped
    assert_empty(MAIN.keys - MAP.keys)
    assert_empty(JAVA.keys - MAP.keys)
  end

  MAP.each_key do |fn|
    define_method("test_main_#{fn}") { Ref.run(self, MAIN[fn], MAP[fn]) } if MAIN.key?(fn)
    define_method("test_java_#{fn}") { Ref.run(self, JAVA[fn], MAP[fn]) } if JAVA.key?(fn)
  end

  # ---- stores beyond the corpus: the file and directory references -----------------------------------------------------------
  def test_file_and_directory_stores_survive_reopen
    Dir.mktmpdir do |d|
      path = File.join(d, 'a.json')
      st = C.create_file_approval_store(path)
      assert st.cas('k', 0, { 'v' => 1 })
      refute st.cas('k', 0, { 'v' => 2 })
      assert_equal({ 'version' => 1, 'value' => { 'v' => 1 } }, C.create_file_approval_store(path).get('k'))

      kv = C.create_directory_kv(File.join(d, 'kv'))
      ks = C.create_kv_approval_store(kv)
      assert ks.cas('k', 0, { 'v' => 1 })
      again = C.create_kv_approval_store(C.create_directory_kv(File.join(d, 'kv')))
      assert_equal({ 'version' => 1, 'value' => { 'v' => 1 } }, again.get('k'))
      kv.put_if_equals('bad', nil, 'not json')
      assert_raises(C::ApprovalStoreError) { ks.get('bad') }
      e = assert_raises(C::ApprovalStoreError) { kv.get('') }
      assert_equal 'bad_key', e.code
    end
  end

  def test_durable_broker_over_directory_kv_is_single_use
    Dir.mktmpdir do |d|
      t = [T0]
      b = C.create_durable_ciba_broker('store' => C.create_kv_approval_store(C.create_directory_kv(d)), 'now' => -> { t[0] })
      r = b.start(SU)
      b.resolve(r['auth_req_id'], 'approve', 'alice')
      t[0] += 5000
      assert_equal true, b.token(r['auth_req_id'])['ok']
      assert_equal 'invalid_grant', b.token(r['auth_req_id'])['error']
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 200, MAIN.values.sum(&:length), 'ciba'
    assert_equal 1129, JAVA.values.sum(&:length), 'ciba-java'
  end

end
