# frozen_string_literal: true

# Replays the TS-reference oracles of the SPIFFE / SPIRE bridge. Two corpora: test-data/ref-spiffe-svid.json.gz (SPIFFE IDs,
# X.509 / JWT-SVID verification, holder binding, scripted caches) and test-data/ref-spiffe.json.gz (parsing, DER facts,
# verification, scripted sessions). A reference refusal that is not a SPIFFE error (a JOSE error, a type error) is code "jose"
# in the second corpus, which is how the wrappers below name every non-SPIFFE refusal there.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefSpiffe < Minitest::Test
  S = AtlasPca::Spiffe
  ID = 'spiffe://example.org/workload/db'
  HOLDER = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE'
  A = Ref.load('spiffe-svid')
  B = Ref.load('spiffe')

  class Coded < StandardError
    attr_reader :code

    def initialize(code, msg)
      super(msg)
      @code = code
    end
  end

  # every non-SPIFFE refusal becomes code "jose" (the second corpus' name for them)
  def self.jose(fn)
    lambda do |*a|
      fn.call(*a)
    rescue S::SpiffeError
      raise
    rescue StandardError => e
      raise Coded.new('jose', e.message)
    end
  end

  def self.holder(h) = h

  def self.cam_x(s) = { 'spiffeId' => s['spiffe_id'], 'serialNumber' => s['serial_number'], 'fingerprint256' => s['fingerprint256'],
                        'position' => s['position'], 'isLeaf' => s['is_leaf'] }

  def self.cam_j(s)
    d = { 'spiffeId' => s['spiffe_id'] }
    d['jti'] = s['jti'] if s.key?('jti')
    d.merge('expiresAt' => s['expires_at'], 'tokenHash' => s['token_hash'])
  end

  # a revocation check named by its mode; nil / "notfn" is present but not callable
  def self.mk_rev(mode, calls, cam)
    return 'notfn' if mode.nil? || mode == 'notfn'

    at = if mode.include?('@') then mode.split('@')[1].to_i
         elsif mode.start_with?('at:') then mode[3..].to_i
         else -1
         end
    lambda do |s|
      calls << cam.call(s)
      case mode
      when 'throw' then raise 'backend down'
      when 'nonbool' then 'no'
      when 'one' then 1
      when 'undef' then nil
      when 'promise' then Object.new # a pending result is not the boolean the check requires
      when 'true' then true
      else at >= 0 ? s['position'] == at : false
      end
    end
  end

  def self.bundle_in(b) = b.is_a?(Hash) ? b.to_h { |k, v| [k == 'x509Authorities' ? 'x509_authorities' : k, v] } : b
  def self.bind(b) = b.nil? ? {} : b.to_h { |k, v| [k == 'acceptUnboundJwtHolder' ? 'accept_unbound_jwt_holder' : k, v] }

  def self.x509_opts(vo, calls)
    o = { 'trust_domain' => vo['trustDomain'], 'roots' => (vo['roots'] || []).dup }
    o['now_ms'] = vo['nowMs'] if vo.key?('nowMs')
    o['max_chain_length'] = vo['maxChainLength'] if vo.key?('maxChainLength')
    o['revocation'] = mk_rev(vo['revocation'], calls, method(:cam_x)) if vo.key?('revocation')
    o
  end

  def self.jwt_opts(vo, calls)
    o = { 'audience' => vo['audience'], 'trust_domain' => vo['trustDomain'] }
    key = vo['key']
    if key.is_a?(Hash)
      if key.key?('jwk') then o['key'] = key['jwk']
      elsif key.key?('jwks') then o['key'] = S.create_local_jwk_set(key['jwks'])
      elsif key.key?('bundle')
        bundle = bundle_in(key['bundle'])
        o['key'] = S.create_trust_bundle_source('fetch' => -> { bundle }, 'refresh_ms' => 1000, 'max_stale_ms' => 5000).method(:jwt_key)
      end
    end
    cur = vo.key?('currentSec') ? vo['currentSec'] : (vo.key?('currentDateMs') ? vo['currentDateMs'] / 1000.0 : nil)
    o['current_date'] = cur unless cur.nil?
    o['algorithms'] = vo['algorithms'] if vo.key?('algorithms')
    o['clock_tolerance'] = vo['clockTolerance'] if vo.key?('clockTolerance')
    o['revocation'] = mk_rev(vo['revocation'], calls, method(:cam_j)) if vo.key?('revocation')
    o
  end

  def self.verify_x509(chain, vo)
    calls = []
    s = S.verify_x509_svid(chain, x509_opts(vo, calls))
    s.spiffe_id.merge('publicKeyDer' => s.public_key_der, 'calls' => calls)
  end

  def self.verify_jwt(token, vo)
    calls = []
    s = S.verify_jwt_svid(token, jwt_opts(vo, calls))
    { 'spiffeId' => s.spiffe_id, 'claims' => s.claims, 'audience' => s.audience, 'expiresAt' => s.expires_at, 'calls' => calls }
  end

  def self.x509_verified(chain, vo) = S.verify_x509_svid(chain, x509_opts(vo, []))

  def self.parse_x509(c)
    s = S.parse_x509_svid(c)
    { 'spiffeId' => s.spiffe_id, 'publicKeyDer' => s.public_key_der }
  end

  def self.facts(der_b64u)
    f = S.read_cert_facts(Ref.b64d(der_b64u))
    { 'basicConstraintsPresent' => f.basic_constraints_present, 'isCa' => f.is_ca, 'pathLen' => f.path_len,
      'keyUsagePresent' => f.key_usage_present, 'digitalSignature' => f.digital_signature, 'keyCertSign' => f.key_cert_sign,
      'crlSign' => f.crl_sign, 'uriSans' => f.uri_sans, 'unknownCritical' => f.unknown_critical }
  end

  # ---- scripted caches (both corpora) ----------------------------------------------------------------------------------------

  def self.fetch_value(cur)
    raise cur['$throw'] if cur.is_a?(Hash) && cur['$throw']
    raise S::SpiffeError.new(cur['$spiffe'], 'x') if cur.is_a?(Hash) && cur['$spiffe']

    cur
  end

  def self.list_in(v) = v.is_a?(Hash) ? v.to_h { |k, x| [{ 'spiffeIds' => 'spiffe_ids', 'tokenHashes' => 'token_hashes' }.fetch(k, k), x] } : v

  def self.subject(s)
    d = { 'spiffe_id' => s['spiffeId'] }
    if s.key?('serialNumber')
      d.merge!('serial_number' => s['serialNumber'], 'fingerprint256' => s['fingerprint256'], 'position' => s['position'], 'is_leaf' => s['isLeaf'])
    else
      d['jti'] = s['jti'] if s.key?('jti')
      d.merge!('expires_at' => s['expiresAt'], 'token_hash' => s['tokenHash'])
    end
    d
  end

  def self.code_of(e) = e.respond_to?(:code) ? e.code : nil

  TB_SCENARIO = lambda do |opts, steps|
    st = { t: 0, cur: nil, n: 0 }
    fetch = lambda do
      st[:n] += 1
      bundle_in(fetch_value(st[:cur]))
    end
    begin
      src = S.create_trust_bundle_source('fetch' => fetch, 'refresh_ms' => opts['refreshMs'], 'max_stale_ms' => opts['maxStaleMs'], 'now' => -> { st[:t] })
    rescue S::SpiffeError => e
      next({ 'ctor' => e.code })
    end
    out = steps.map do |s|
      st[:t] = s['at']
      st[:cur] = s['fetch']
      st[:n] = 0
      begin
        if s['op'] == 'x509Roots'
          { 'ok' => src.x509_roots, 'fetches' => st[:n] }
        else
          src.jwt_key(s['header'].nil? ? { 'alg' => 'ES256' } : s['header'], 'tok')
          { 'ok' => 'key', 'fetches' => st[:n] }
        end
      rescue StandardError => e
        { 'code' => code_of(e), 'fetches' => st[:n] }
      end
    end
    { 'steps' => out }
  end

  RV_SCENARIO = lambda do |opts, steps|
    st = { t: 0, cur: nil, n: 0 }
    fetch = lambda do
      st[:n] += 1
      list_in(fetch_value(st[:cur]))
    end
    begin
      src = S.create_revocation_source('fetch' => fetch, 'refresh_ms' => opts['refreshMs'], 'max_stale_ms' => opts['maxStaleMs'], 'now' => -> { st[:t] })
    rescue S::SpiffeError => e
      next({ 'ctor' => e.code })
    end
    out = steps.map do |s|
      st[:t] = s['at']
      st[:cur] = s['fetch']
      st[:n] = 0
      begin
        v = case s['op']
            when 'ensureFresh' then src.ensure_fresh
            when 'refresh' then src.refresh && nil
            when 'x509' then src.x509(subject(s['subject']))
            else src.jwt(subject(s['subject']))
            end
        { 'ok' => v, 'fetches' => st[:n] }
      rescue StandardError => e
        { 'code' => code_of(e), 'fetches' => st[:n] }
      end
    end
    { 'steps' => out }
  end

  def self.proj(jwk) = jwk.slice('kty', 'crv', 'x', 'n')
  def self.session_code(e) = e.is_a?(S::SpiffeError) ? e.code : 'jose'

  # a scripted session over a cache (`make` builds it from the fetch and clock); a refused configuration is code "jose"
  def self.session(a, make, xform)
    st = { t: a['start'], n: 0 }
    fetches = a['fetches']
    fetch = lambda do
      f = fetches[[st[:n], fetches.length - 1].min]
      st[:n] += 1
      raise 'fetch failed' if f.key?('throw')

      xform.call(f['list'])
    end
    src = begin
      make.call('fetch' => fetch, 'refresh_ms' => a['refreshMs'], 'max_stale_ms' => a['maxStaleMs'], 'now' => -> { st[:t] })
    rescue S::SpiffeError => e
      raise Coded.new('jose', e.message)
    end
    out = a['steps'].map do |s|
      v = if s['op'] == 'adv'
            st[:t] += s['ms']
          else
            yield(src, s)
          end
      { 'v' => v }
    rescue StandardError => e
      { 'code' => session_code(e) }
    end
    { 'steps' => out, 'fetchCalls' => st[:n] }
  end

  BUNDLE_SESSION = lambda do |a|
    session(a, S.method(:create_trust_bundle_source), method(:bundle_in)) do |src, s|
      s['op'] == 'x509Roots' ? src.x509_roots : proj(src.jwt_key(s['header'], 'tok')[0])
    end
  end

  REVOCATION_SESSION = lambda do |a|
    session(a, S.method(:create_revocation_source), method(:list_in)) do |src, s|
      case s['op']
      when 'ensureFresh' then src.ensure_fresh
      when 'refresh' then src.refresh && nil
      when 'x509' then src.x509(subject(s['subject']))
      else src.jwt(subject(s['subject']))
      end
    end
  end

  # ---- holder binding sessions (second corpus) -------------------------------------------------------------------------------

  def self.unverified(kind, a)
    case kind
    when 'x509-parsed' then S.parse_x509_svid(a['chain'])
    when 'string' then ID
    when 'parsed-id' then S.parse_spiffe_id(ID)
    when 'hand-built' then S::X509Svid.new(S.parse_spiffe_id(ID), Object.new, 'x')
    end
  end

  HOLDER_SESSION = lambda do |a|
    svid = case a['svid']
           when 'x509' then S.verify_x509_svid(a['chain'], 'trust_domain' => 'example.org', 'roots' => a['roots'], 'now_ms' => a['nowMs'])
           when 'jwt'
             j = a['jwt']
             S.verify_jwt_svid(j['token'], 'audience' => j['audience'], 'key' => j['jwk'], 'trust_domain' => j['trustDomain'],
                                           'current_date' => j['currentDateMs'] / 1000.0)
           else unverified(a['svid'], a)
           end
    b = {}
    b['proof'] = a['proof'] if a.key?('proof')
    b['accept_unbound_jwt_holder'] = a['acceptUnbound'] if a.key?('acceptUnbound')
    hk = a['holderKey']
    case a['op']
    when 'holder' then { 'holder' => S.svid_to_holder(svid, hk, b) }
    when 'forHolder' then { 'spiffeId' => S.spiffe_id_for_holder(svid, hk, b) }
    else { 'pin' => S.workload_discharge_pin(a['label'], svid) }
    end
  end

  # the second corpus names a non-SPIFFE failure reason "other"
  ADMISSION_B = lambda do |a|
    e = if a['kind'] == 'x509'
          { 'kind' => 'x509', 'chain' => a['chain'], 'verify' => { 'trust_domain' => 'example.org', 'roots' => a['roots'], 'now_ms' => a['nowMs'] } }
        else
          { 'kind' => 'jwt', 'token' => a['token'],
            'verify' => { 'audience' => 'api', 'key' => a['jwk'], 'trust_domain' => 'example.org', 'current_date' => 1_800_000_060 } }
        end
    e['bind'] = bind(a['bind']) if a.key?('bind')
    r = S.spiffe_admission_evidence(e, a['instanceKey'])
    r['reason'] = 'other' if r['reason'].is_a?(String) && r['reason'].match?(/\AERR_|Error\z/)
    r
  end

  ADMISSION_A = lambda do |e, key|
    calls = []
    ee = { 'kind' => e['kind'] }
    if e['kind'] == 'x509'
      ee.merge!('chain' => e['chain'], 'verify' => x509_opts(e['verify'], calls))
    else
      ee.merge!('token' => e['token'], 'verify' => jwt_opts(e['verify'], calls))
    end
    ee['bind'] = bind(e['bind']) if e.key?('bind')
    S.spiffe_admission_evidence(ee, key)
  end

  def self.holder_unverified(kind, pem)
    v = case kind
        when 'string' then ID
        when 'object' then { 'spiffe_id' => S.parse_spiffe_id(ID) }
        when 'null' then nil
        when 'number' then 5
        when 'parsed jwt-like' then S::JwtSvid.new(S.parse_spiffe_id(ID), {}, [], 1)
        else S.parse_x509_svid(pem)
        end
    S.svid_to_holder(v, HOLDER, {})
  end

  BYTES = ->(b) { { '$bytes' => Ref.b64e(b) } }

  MAP_A = {
    'parseSpiffeId' => ->(s) { S.parse_spiffe_id(s) },
    'parseX509Svid' => method(:parse_x509),
    'verifyX509Svid' => method(:verify_x509),
    'verifyJwtSvid' => method(:verify_jwt),
    'svidToHolderX509' => ->(chain, vo, hk, b) { S.svid_to_holder(x509_verified(chain, vo), hk, bind(b)) },
    'svidToHolderJwt' => ->(token, vo, hk, b) { S.svid_to_holder(S.verify_jwt_svid(token, jwt_opts(vo, [])), hk, bind(b)) },
    'svidToHolderUnverified' => method(:holder_unverified),
    'spiffeIdForHolder' => ->(chain, vo, h, b) { S.spiffe_id_for_holder(x509_verified(chain, vo), h, bind(b)) },
    'workloadDischargePin' => ->(label, chain, vo) { S.workload_discharge_pin(label, x509_verified(chain, vo)) },
    'holderToSpiffeId' => ->(h) { S.holder_to_spiffe_id(h) },
    'holderBindingMessage' => ->(i, h) { BYTES.call(S.holder_binding_message(i, h)) },
    'spiffeAdmissionEvidence' => ADMISSION_A,
    'trustBundleScenario' => TB_SCENARIO,
    'revocationScenario' => RV_SCENARIO,
    'constants' => -> { { 'jwtSvidAlgorithms' => S::JWT_SVID_ALGORITHMS } }
  }.freeze

  # an asynchronous revocation check has no synchronous analogue in this port
  SKIP_ASYNC = lambda do |c|
    a = c['fn'] == 'jwtSession' && c['args'].is_a?(Array) ? c['args'][0] : {}
    a.is_a?(Hash) && a['revocation'].to_s.start_with?('async-') ? 'asynchronous revocation check' : nil
  end

  MAP_B = {
    'parseSpiffeId' => ->(s) { S.parse_spiffe_id(s) },
    'readCertFacts' => method(:facts),
    'parseX509Svid' => method(:parse_x509),
    'verifyX509Svid' => method(:verify_x509),
    'holderToSpiffeId' => ->(h) { S.holder_to_spiffe_id(h) },
    'holderBindingMessage' => ->(i, h) { BYTES.call(S.holder_binding_message(i, h)) },
    'constants' => -> { { 'JWT_SVID_ALGORITHMS' => S::JWT_SVID_ALGORITHMS } },
    'jwtSession' => jose(->(a) { verify_jwt(a['token'], a) }),
    'holderSession' => jose(HOLDER_SESSION),
    'admission' => ADMISSION_B,
    'bundleSession' => BUNDLE_SESSION,
    'revocationSession' => REVOCATION_SESSION
  }.freeze

  def test_every_fn_is_mapped
    assert_equal A.keys.sort, MAP_A.keys.sort
    assert_equal B.keys.sort, MAP_B.keys.sort
  end

  MAP_A.each_key { |fn| define_method("test_a_#{fn}") { Ref.run(self, A[fn], MAP_A[fn]) } }
  MAP_B.each_key { |fn| define_method("test_b_#{fn}") { Ref.run(self, B[fn], MAP_B[fn], skip: SKIP_ASYNC) } }

  def test_only_asynchronous_revocation_cases_are_skipped
    assert_equal 3, B['jwtSession'].count { |c| SKIP_ASYNC.call(c) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1157, A.values.sum(&:length), 'spiffe-svid'
    assert_equal 3346, B.values.sum(&:length), 'spiffe'
  end

end
