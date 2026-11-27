# frozen_string_literal: true

# Replays the TS-reference oracle of the outbound token vault (test-data/ref-connect.json.gz): oauth_scope caveats, token refresh,
# the proxy-mode request extractor, signed release receipts, the envelope-encrypted store and the TokenVault release and proxy
# scenarios. The vault keys derive from seed labels in the corpus.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/connect'
require 'minitest/autorun'

class TestRefConnect < Minitest::Test
  C = AtlasPca::Connect
  R = AtlasPca::ConnectReplay
  Js = AtlasPca::Js
  BY_FN = Ref.load('connect')

  def self.err_out(e)
    return { 'ok' => false, 'name' => 'Error' } unless e.is_a?(C::VaultError)

    out = { 'ok' => false, 'name' => e.class.name.split('::').last, 'code' => e.code }
    out['message'] = e.message unless e.code == 'not_authorized'
    out['status'] = e.status if e.respond_to?(:status) && !e.status.nil?
    out['missing'] = e.missing.dup if e.respond_to?(:missing) && !e.missing.empty?
    out
  end

  class Resp
    attr_reader :ok, :status

    def initialize(r)
      @r = r
      @ok = r['ok']
      @status = r['status']
    end

    def json
      raise 'bad json' if @r['jsonThrows']

      @r['json']
    end

    def text
      raise 'bad text' if @r['textThrows']

      @r.fetch('text', '')
    end
  end

  def self.transport(script, log)
    return nil if script.nil?

    n = [0]
    lambda do |url, init|
      log << { 'url' => url, 'method' => init['method'], 'headers' => init['headers'], 'body' => init['body'] }
      r = script[[n[0], script.length - 1].min]
      n[0] += 1
      raise r['throws'] if r.key?('throws')

      Resp.new(r)
    end
  end

  def self.refresh(c)
    log = []
    v = C.refresh_connection(c['connection'], c['config'], c['refreshToken'], c['requested'], transport(c['script'], log), c['now'], c['defaultTokenLifetimeMs'])
    { 'ok' => true, 'value' => v, 'calls' => log }
  rescue StandardError => e
    err_out(e).merge('calls' => log)
  end

  def self.decrypt(c)
    inner = C::InMemoryConnectionStore.new
    inner.set(c['record'])
    w = C::LocalKeyWrapper.new(c['ring'].transform_values { |v| Ref.b64d(v) }, c['active'])
    store = C::EncryptedConnectionStore.new(inner, w)
    r = store.get(c['key'])
    { 'ok' => true, 'value' => r.nil? ? nil : C.clone_connection(r) }
  rescue StandardError => e
    err_out(e)
  end

  SIMPLE = { 'insecureBearerRelease' => :insecure_bearer_release, 'insecureSkipPlanRootCheck' => :insecure_skip_plan_root_check,
             'authorizedPlanRoots' => :authorized_plan_roots, 'audience' => :audience, 'expiryLeewayMs' => :expiry_leeway_ms,
             'defaultTokenLifetimeMs' => :default_token_lifetime_ms, 'requireActionBinding' => :require_action_binding,
             'defaultConnectionId' => :default_connection_id, 'providers' => :providers, 'pqPins' => :pq_pins,
             'maxProxyResponseBytes' => :max_proxy_response_bytes }.freeze

  def self.vault(s)
    now = [s['nowMs']]
    store = C::InMemoryConnectionStore.new
    fetch_log = []
    proxy_log = []
    receipts = []
    op = s['opts'] || {}
    table = s['actionsTable']
    pi = [0]
    kw = { strict: false, store: store, now: -> { now[0] }, fetch: transport(s['fetchScript'], fetch_log) }
    SIMPLE.each do |k, v|
      if op.key?(k) && !op[k].nil? && op[k] != false then kw[v] = op[k]
      elsif op.key?(k) && op[k] == false && k == 'requireActionBinding' then kw[v] = false
      end
    end
    kw[:use_verb] = op['useVerb'] if op.key?('useVerb')
    kw[:replay] = R::InMemoryReplayStore.new if Js.truthy?(op['replay'])
    if Js.truthy?(op['revoked'])
      kw[:is_revoked] = lambda do |_p|
        raise 'src down' if op['revoked'] == 'throws'

        op['revoked'] == 'yes'
      end
    end
    if table
      kw[:actions] = lambda do |verb|
        t = table[verb]
        return nil if t.nil?

        a = { 'verb' => t['verb'], 'def_digest' => t['def_digest'], 'confirmed' => t['confirmed'], 'upstream' => t['upstream'] }
        a['extract'] = C.http_extractor(t['extract']) if Js.truthy?(t['extract'])
        a
      end
    end
    if Js.truthy?(op['proxy'])
      kw[:proxy_fetch] = lambda do |req|
        proxy_log << { 'method' => req['method'], 'url' => req['url'], 'headers' => req['headers'], 'body' => req['body'], 'redirect' => req['redirect'] }
        r = s['proxyScript'][[pi[0], s['proxyScript'].length - 1].min]
        pi[0] += 1
        raise 'net' if Js.truthy?(r['throws'])

        { 'status' => r['status'], 'headers' => r['headers'], 'body' => r['body'] }
      end
    end
    if Js.truthy?(op['receiptSeed'])
      sink = lambda do |r|
        receipts << r
        raise 'sink' if Js.truthy?(op['failingSink'])
      end
      kw[:receipts] = { 'secret_key' => Ref.b64d(op['receiptSeed']), 'sink' => sink }
    end
    v = C::TokenVault.new(**kw)
    results = []
    rec = lambda do |&f|
      results << { 'ok' => true, 'value' => f.call }
    rescue StandardError => e
      results << err_out(e)
    end
    s['calls'].each do |c|
      a = c['args']
      case c['op']
      when 'put'
        rec.call { v.put_connection(a['agentId'], a['provider'], a['accessToken'], a['expiresAt'], a['scopes'], a['authority'], a['connectionId'], a['refreshToken']) }
      when 'get' then rec.call { v.get_connection_token(c['pcActn'], a['provider'], a['connectionId'], a['scopes']) }
      when 'proxy' then rec.call { v.proxy_call(c['pcActn'], c['request'], a['provider'], a['connectionId']) }
      when 'delete' then rec.call { v.delete_connection(c['agentId'], c['provider'], c['connectionId']) }
      when 'now' then now[0] = c['now']
      end
    end
    out = (s['watch'] || []).map { |k| (g = store.get(k)).nil? ? nil : C.clone_connection(g) }
    { 'results' => results, 'store' => out, 'receipts' => receipts, 'fetchCalls' => fetch_log, 'proxyCalls' => proxy_log }
  end

  MAP = {
    'oauthScopeCaveat' => ->(p, s) { C.oauth_scope_caveat(p, s) },
    'isOAuthScopeCaveat' => ->(x) { C.oauth_scope_caveat?(x) },
    'grantedOAuthScopes' => lambda { |chain, p|
      r = C.granted_oauth_scopes(chain, p)
      r&.sort_by { |s| AtlasPca::Siem::U16.units(s) }
    },
    'httpExtractor' => ->(spec, req) { C.http_extractor(spec).call(req) },
    'checkProxyHeaders' => ->(h, a) { C.check_proxy_headers(h, a) },
    'DEFAULT_PROXY_HEADERS' => -> { C::DEFAULT_PROXY_HEADERS.dup },
    'outboundRequestDigest' => ->(m, u, h, b) { C.outbound_request_digest(m, u, h, b) },
    'signReleaseReceipt' => ->(b, seed) { C.sign_release_receipt(b, Ref.b64d(seed)) },
    'verifyReleaseReceipt' => ->(r, pk) { C.verify_release_receipt(r, pk) },
    'receiptActionDigest' => ->(p) { C.receipt_action_digest(p) },
    'refreshConnection' => ->(c) { refresh(c) },
    'decryptRecord' => ->(c) { decrypt(c) },
    'vault' => ->(s) { vault(s) }
  }.freeze

  # lone-surrogate safe comparison of canonical forms
  CMP = ->(g, o, _c) { AtlasPca::Js.json(Ref.sort_keys(Ref.norm(g))) == AtlasPca::Js.json(Ref.sort_keys(Ref.norm(o))) }

  def test_every_fn_is_mapped
    assert_empty BY_FN.keys - MAP.keys
    assert_empty MAP.keys - BY_FN.keys
  end

  MAP.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call, compare: CMP) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 845, BY_FN.values.sum(&:length), 'connect'
  end

end
