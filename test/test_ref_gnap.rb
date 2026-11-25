# frozen_string_literal: true

# Replays the TS-reference oracle of the GNAP bridge (test-data/ref-gnap.json.gz): access rights, holders, grant requests ->
# capability chains, action authorization, bound tokens, jwsd proofs (sign / verify / replay store), the step-up continuation,
# and the interaction modes (hash, validation, the AS state machine as scripted scenarios). Secrets travel as base64url seeds;
# options are the reference's camelCase names mapped to snake_case.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefGnap < Minitest::Test
  G = AtlasPca::Gnap
  CASES = Ref.load('gnap')

  def self.sn(o) = o.nil? ? {} : Ref.snake(o)
  def self.seed(s) = s.is_a?(String) ? Ref.b64d(s) : s

  G2C = lambda do |req, opts|
    o = sn(opts)
    o['issuer_secret'] = seed(o['issuer_secret']) if o.key?('issuer_secret')
    r = G.grant_request_to_capability(req, o)
    { 'grant' => r['grant'], 'chain' => r['chain'], 'holder' => r['holder'], 'grantedAccess' => r['granted_access'],
      'droppedAccess' => r['dropped_access'], 'provenance' => r['provenance'] }
  end

  SIGN = lambda do |a|
    o = sn(a)
    k = a['key']
    o['key'] = k.is_a?(Hash) ? { 'secret_key' => seed(k['secretKey']), 'public_key' => seed(k['publicKey']) } : k
    r = G.sign_gnap_request(o)
    { 'detachedJws' => r['detached_jws'], 'header' => r['header'], 'holder' => r['holder'] }
  end

  VERIFY = lambda do |a|
    seen = []
    o = sn(a)
    mode = o.delete('seen_proof_mode')
    if %w[fresh replayed throws undefined].include?(mode)
      o['seen_proof'] = lambda do |id, exp|
        seen << [id, exp]
        raise 'store down' if mode == 'throws'

        { 'fresh' => false, 'replayed' => true }[mode]
      end
    end
    r = G.verify_gnap_request(o)
    r = r.merge('reason' => r['reason'].sub(/(bad-json) \(.*\)\z/m, '\1')) if r['reason'].is_a?(String)
    { 'result' => r, 'seen' => seen }
  end

  BEGIN_CONT = lambda do |a|
    r = G.begin_gnap_continuation(sn(a))
    s = r['step_up']
    { 'response' => r['response'], 'stepUp' => { 'tier' => s['tier'], 't' => s['t'], 'signerSet' => s['signer_set'],
                                                  'reason' => s['reason'], 'continueToken' => s['continue_token'] } }
  end

  COMPLETE = lambda do |a|
    o = sn(a)
    o['agent_leaf_secret'] = seed(o['agent_leaf_secret'])
    o['cosign_secrets'] = o['cosign_secrets'].map { |c| { 'role' => c['role'], 'secret' => seed(c['secret']) } } if o.key?('cosign_secrets')
    G.complete_gnap_continuation(o)
  end

  def self.redact(v, pairs)
    case v
    when String then pairs.reduce(v) { |s, (k, t)| k.nil? || k.empty? ? s : s.gsub(k, t) }
    when Array then v.map { |x| redact(x, pairs) }
    when Hash then v.transform_values { |x| redact(x, pairs) }
    else v
    end
  end

  # The AS state machine, scripted: every random value (id, user code, ref, AS nonce, hash) becomes a token in the trace.
  SCENARIO = lambda do |s|
    clock = [1000]
    opts = s['opts']
    ge = opts.fetch('grantEndpoint', 'https://as.example/tx')
    o = { 'grant_endpoint' => ge, 'supports' => opts['supports'], 'redirect_uri' => ->(i) { "https://as.example/i/#{i}" },
          'now' => -> { clock[0] } }
    o['app_uri'] = ->(i) { "app://as/#{i}" } if opts['app']
    o['user_code_uri'] = opts['userCodeUri'] if opts['userCodeUri']
    o['ttl_sec'] = opts['ttlSec'] if opts.key?('ttlSec')
    srv = G::InteractionServer.new(o)
    v = {}
    last = {}
    sub = lambda do |x|
      next x unless x.is_a?(String) && x.start_with?('$')

      code = v['code'] || ''
      next code.downcase if x == '$code:lower'
      next "#{code[0, 4]} - #{code[4..]}" if x == '$code:spaced'

      v.fetch(x[1..], x)
    end
    s['steps'].map do |st|
      op = st['op']
      value = case op
              when 'start'
                last['req'] = st['req']
                r = srv.start(st['req'])
                it = r['interaction']
                v['id'] = it.id
                v['code'] = it.user_code || ''
                v['asnonce'] = it.finish ? it.finish['as_nonce'] : ''
                { 'interaction' => it.to_h, 'response' => r['response'] }
              when 'lookup' then srv.lookup_user_code(sub.(st['code']))&.to_h
              when 'approve'
                r = srv.approve(sub.(st['id']))
                v['ref'] = r['interact_ref']
                it = srv.get(v['id'])
                fin = r['finish']
                m = if fin && fin['method'] == 'push' then fin['body']['hash']
                    elsif fin && fin['url'] then fin['url'][/[?&]hash=([^&]+)/, 1]
                    end
                v['hash'] = m || ''
                expected = nil
                if it&.finish
                  f = it.finish
                  expected = G.interaction_hash({ 'client_nonce' => f['client_nonce'], 'as_nonce' => f['as_nonce'], 'interact_ref' => r['interact_ref'],
                                                  'grant_endpoint' => it.grant_endpoint, 'hash_method' => f['hash_method'] })
                end
                result = { 'interactRef' => r['interact_ref'] }
                result['finish'] = fin if fin
                { 'result' => result, 'hashOk' => m == expected }
              when 'consume' then srv.consume(sub.(st['ref'])).to_h
              when 'finalize' then srv.finalize(sub.(st['id']))
              when 'get' then srv.get(sub.(st['id']))&.to_h
              when 'advance' then clock[0] += st['sec']
              else
                fin = last['req']['finish']
                ctx = { 'client_nonce' => fin['nonce'], 'as_nonce' => v['asnonce'], 'grant_endpoint' => ge }
                ctx['hash_method'] = fin['hash_method'] if AtlasPca::Js.truthy?(fin['hash_method'])
                G.accept_finish({ 'hash' => sub.(st['hash']), 'interact_ref' => sub.(st['ref']) }, ctx)
              end
      pairs = [[v['ref'], '<REF>'], [v['hash'], '<HASH>'], [v['asnonce'], '<ASNONCE>'], [v['id'], '<ID>'], [v['code'], '<CODE>']]
      { 'op' => op, 'ok' => true, 'value' => redact(value, pairs) }
    rescue StandardError => e
      { 'op' => op, 'ok' => false, 'code' => e.is_a?(G::InteractionError) ? e.code : 'other' }
    end
  end

  # an earlier interaction's id is random and outside the redaction (the reference trace carries it verbatim): any id
  # other than the current one compares as one token
  def self.other_ids(v)
    case v
    when Hash then v.to_h { |k, x| [k, k == 'id' && x.is_a?(String) && x != '<ID>' ? '<OTHER-ID>' : other_ids(x)] }
    when Array then v.map { |x| other_ids(x) }
    else v
    end
  end
  CMP_SCENARIO = ->(g, o, _c) { Ref.canon(other_ids(Ref.norm(g))) == Ref.canon(other_ids(o)) }

  BYTES = ->(b) { { '$bytes' => Ref.b64e(b) } }

  FNS = {
    'constants' => [lambda {
      { 'GNAP_GRANT_CAVEAT' => G::GNAP_GRANT_CAVEAT, 'GNAP_ACCESS_CAVEAT' => G::GNAP_ACCESS_CAVEAT,
        'MAX_DETACHED_JWS_CHARS' => G::MAX_DETACHED_JWS_CHARS, 'START_MODES' => G::START_MODES, 'FINISH_METHODS' => G::FINISH_METHODS,
        'HASH_METHODS' => G::HASH_METHODS.keys }
    }],
    'AGENT_GNAP_PROFILE' => [-> { G::AGENT_GNAP_PROFILE }],
    'gnapActionResource' => [->(t, l) { G.gnap_action_resource(t, l) }],
    'normalizeAccess' => [->(i) { G.normalize_access(i) }],
    'accessToPredicates' => [->(a) { G.access_to_predicates(a) }],
    'accessContains' => [->(g, r) { G.access_contains(g, r) }],
    'accessWithin' => [->(g, r) { G.access_within(g, r) }],
    'clampAccess' => [->(g, r) { G.clamp_access(g, r) }],
    'resolveHolder' => [->(req, *o) { o.empty? ? G.resolve_holder(req) : G.resolve_holder(req, o[0]) }],
    'holderJwk' => [->(h) { G.holder_jwk(h) }],
    'grantRequestToCapability' => [G2C],
    'grantedAccessOf' => [->(c) { G.granted_access_of(c) }],
    'authorizeGnapAction' => [->(c, a, o = nil) { G.authorize_gnap_action(c, a, sn(o)) }],
    'encodeBoundToken' => [->(c) { G.encode_bound_token(c) }],
    'capabilityToGrantResponse' => [->(c, o = nil) { G.capability_to_grant_response(c, sn(o)) }],
    'verifyGnapToken' => [->(v, o = nil) { G.verify_gnap_token(v, sn(o)) }],
    'gnapContentDigest' => [->(b) { BYTES.(G.gnap_content_digest(b)) }],
    'gnapContentDigestAbsent' => [-> { BYTES.(G.gnap_content_digest) }],
    'signGnapRequest' => [SIGN],
    'verifyGnapRequest' => [VERIFY],
    'gnapRequestRequiresStepUp' => [->(r, o = nil) { G.gnap_request_requires_step_up(r, sn(o)) }],
    'beginGnapContinuation' => [BEGIN_CONT],
    'gnapStepUpShare' => [->(b, r, s, ss, t) { G.gnap_step_up_share(b, r, seed(s), ss, t) }],
    'completeGnapContinuation' => [COMPLETE],
    'callbackUriOk' => [->(u) { G.callback_uri_ok(u) }],
    'validateInteractRequest' => [->(r) { G.validate_interact_request(r) }],
    'interactionHash' => [->(a) { G.interaction_hash(sn(a)) }],
    'verifyInteractionHash' => [->(r, a) { G.verify_interaction_hash(r, sn(a)) }],
    'acceptFinish' => [->(cb, ctx) { G.accept_finish(cb, sn(ctx)) }],
    'newUserCode' => [->(n) { G.new_user_code(n) }],
    'accessToNeeds' => [->(a) { G.access_to_needs(a) }],
    'interactionScenario' => [SCENARIO, { compare: CMP_SCENARIO }]
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, (call, kw)| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call, **(kw || {})) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 2119, CASES.values.sum(&:length), 'gnap'
  end

end
