# frozen_string_literal: true

# Replays the TS-reference oracle of the PCA gateway (test-data/ref-gateway.json.gz): canonical query, request binding, path
# hardening, replay guard, provenance log, presented artifacts, authorize / create_gateway over real signed proofs, the Envoy HTTP
# and gRPC shapes and the Lambda authorizers.
#
# Compared after masking: the verdict objects print "<verdict>" and the strict-JSON parser's own message in "undecodable PCA-Action
# header: <message>" prints "<json>".
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/gateway'
require 'minitest/autorun'

class TestRefGateway < Minitest::Test
  G = AtlasPca::Gateway
  Js = AtlasPca::Js
  BY_FN = Ref.load('gateway')

  def self.mask(s)
    case s
    when String then s.gsub(/undecodable PCA-Action header: (?!PCA-Action header)[\s\S]*/, 'undecodable PCA-Action header: <json>')
    when Array then s.map { |x| mask(x) }
    when Hash
      out = s.to_h { |k, v| [k, %w[x-pca-verdict pcaVerdict].include?(k) && v.is_a?(String) && v != '' ? '<verdict>' : mask(v)] }
      h = out['header']
      out['header'] = h.merge('value' => '<verdict>') if h.is_a?(Hash) && h['key'] == 'x-pca-verdict' && h['value'] != ''
      out
    else s
    end
  end

  class Raising
    def claim(*) = raise('store down')
  end

  class Fixed
    def initialize(v) = @v = v
    def claim(*) = @v
  end

  def self.build(spec)
    now = spec['now']
    kw = { audience: spec['audience'], routes: spec['routes'], resolve_grant: ->(ref, _p = nil) { spec['grants'][ref] }, now: -> { now } }
    b = spec['bindRequest']
    if b == 'off' then kw[:bind_request] = false
    elsif !b.nil? then kw[:bind_request] = b
    end
    kw[:unmatched_route] = spec['unmatched'] unless spec['unmatched'].nil?
    kw[:path_policy] = spec['pathPolicy'] unless spec['pathPolicy'].nil?
    kw[:require_checks] = spec['requireChecks'] unless spec['requireChecks'].nil?
    kw[:realm] = spec['realm'] unless spec['realm'].nil?
    kw[:insecure_skip_plan_root_check] = true if Js.truthy?(spec['skipPlan'])
    kw[:authorized_plan_roots] = spec['planRoots'] unless spec['planRoots'].nil?
    guards = { 'always' => -> { Fixed.new(true) }, 'false' => -> { Fixed.new(false) }, 'throws' => -> { Raising.new },
               'memory' => -> { G.memory_replay_guard(100_000, -> { now }) }, 'memory-full' => -> { G.memory_replay_guard(1, -> { now }) } }
    kw[:replay_guard] = guards.fetch(spec['replay']).call if spec['replay'] != 'none'
    revs = { 'ok' => ->(_c) { { 'enforced' => true, 'ok' => true } }, 'revoked' => ->(_c) { { 'enforced' => true, 'ok' => false, 'reason' => 'grant revoked' } },
             'revoked-noreason' => ->(_c) { { 'enforced' => true, 'ok' => false } }, 'notEnforced' => ->(_c) { { 'enforced' => false } },
             'throws' => ->(_c) { raise 'rev down' } }
    kw[:hooks] = { 'revocation' => revs.fetch(spec['revocation']) } if spec['revocation'] != 'none'
    cps = { 'true' => ->(_c) { true }, 'false' => ->(_c) { false }, 'obj-true' => ->(_c) { { 'allow' => true } }, 'obj-false' => ->(_c) { { 'allow' => false } },
            'obj-false-reason' => ->(_c) { { 'allow' => false, 'reason' => 'over limit' } }, 'throws' => ->(_c) { raise 'policy down' } }
    kw[:check_proof] = cps.fetch(spec['checkProof']) if Js.truthy?(spec['checkProof'])
    case spec['policy']
    when 'sig' then kw[:policy] = { 'mode' => 'signature-only' }
    when 'bogus' then kw[:policy] = { 'mode' => 'bogus' }
    when 'full-missing' then kw[:policy] = { 'mode' => 'full', 'params' => 'body' }
    end
    G::GatewayOptions.new(**kw)
  end

  def self.proj(d)
    out = { 'allow' => d['allow'], 'status' => d['status'], 'code' => d['code'], 'reason' => d['reason'], 'headers' => d['headers'] }
    out['matched'] = d['matched'] if d.key?('matched')
    out['grant'] = d['pcactn']['grant_ref'] if !d['pcactn'].nil? && !d['pcactn']['grant_ref'].nil?
    out['verdictAllow'] = d['verdict']['allow'] unless d['verdict'].nil?
    mask(out)
  end

  def self.authorize_scenario(spec)
    gw = G.create_gateway(build(spec))
    spec['requests'].map { |r| proj(gw.call(r)) }
  rescue TypeError, ArgumentError => e
    { 'create' => e.message }
  end

  def self.adapter(name)
    lambda do |spec|
      fn = G.send(name, build(spec))
      mask(fn.call(spec['events'][0]))
    rescue TypeError, ArgumentError => e
      { 'create' => e.message }
    end
  end

  def self.lambda_lone(name)
    lambda do |spec|
      mask(G.send(name, build(spec)).call(spec['events'][0]))
    rescue ArgumentError => e
      { 'threw' => e.message }
    end
  end

  def self.replay(spec)
    clock = [spec.fetch('clock', 0)]
    g = G.memory_replay_guard(spec['max'], -> { clock[0] })
    out = []
    spec['ops'].each do |op|
      if op.key?('setClock')
        clock[0] = op['setClock']
        next
      end
      out << g.claim(op['key'], op['exp'], op['now'])
    rescue StandardError => e
      out << { 'threw' => e.message }
    end
    out
  end

  def self.prov_log(spec)
    log = G.memory_provenance_log(spec['max'])
    spec['ops'].map do |op|
      if Js.truthy?(op['add'])
        log.add(op['session'], op['o'])
        'added'
      else
        log.seen(op['session'])
      end
    end
  end

  def self.policy(kind) = kind == 'body' ? { 'params' => 'body' } : { 'params' => ->(_r) { {} } }

  def self.presented(name)
    lambda do |rq, kind|
      v = G.send(name, { 'method' => 'POST', 'path' => '/' }.merge(rq), policy(kind))
      v.equal?(G::ABSENT) ? { 'undef' => true } : v
    end
  end

  MAP = {
    'canonicalQuery' => ->(q = nil) { G.canonical_query(q) },
    'requestBinding' => ->(r, o = nil) { G.request_binding(r.merge('headers' => {}), o) },
    'bindParams' => ->(p, b = nil) { G.bind_params(p, b) },
    'ambiguousPathReason' => ->(p) { G.ambiguous_path_reason(p) },
    'replayScenario' => ->(s) { replay(s) },
    'provenanceLogScenario' => ->(s) { prov_log(s) },
    'presentedProvenance' => presented(:presented_provenance),
    'presentedArtifacts' => presented(:presented_artifacts),
    'authorizeScenario' => ->(s) { authorize_scenario(s) },
    'envoyScenario' => adapter(:envoy_ext_authz),
    'grpcScenario' => adapter(:envoy_grpc_ext_authz),
    'lambdaScenario' => lambda_lone(:lambda_authorizer),
    'lambdaSimpleScenario' => lambda_lone(:lambda_simple_authorizer)
  }.freeze

  CMP = ->(g, o, _c) { Js.json(Ref.sort_keys(Ref.norm(g))) == Js.json(Ref.sort_keys(Ref.norm(o))) }

  def test_every_fn_is_mapped
    assert_empty BY_FN.keys - MAP.keys
    assert_empty MAP.keys - BY_FN.keys
  end

  MAP.each do |fn, call|
    define_method("test_#{fn}") do
      ran = Ref.run(self, BY_FN[fn], call, compare: CMP)
      assert_equal BY_FN[fn].length, ran
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 444, BY_FN.values.sum(&:length), 'gateway'
  end

end
