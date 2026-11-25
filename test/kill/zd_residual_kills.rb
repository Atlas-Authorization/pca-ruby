# frozen_string_literal: true

# zd: kill tests for the remaining mutation survivors of authorize.rb (the replay head read twice, the budget seed hook, plan shapes,
# the beacon pin, the budget DDL), risk.rb (safety bound), mesh.rb (ceiling text), attest/azure.rb and attest/intel.rb (policy shapes
# handed past construction) and the registry conformance kits (an uneven refusal, the exact epoch boundary after a restart).
# Reference: packages/pca/src/server/authorize.ts, risk.ts, mesh.ts. AtlasPca is resolved at call time.

module MutationKill
  module ZD
    module_function

    def gate?(file) = (f = ENV['MUT_FILE']).nil? || f.empty? || f == file
    def ck(label, got, want) = got == want || raise("#{label}: got #{got.inspect}, want #{want.inspect}")
  end

  t('zd authorize: a replay seen only by the second read of the store head still denies and is reported') do
    next true unless ZD.gate?('authorize.rb')

    st = Class.new do
      attr_reader :claims

      def initialize
        @reads = 0
        @claims = []
      end

      def claim(key, counter)
        @claims << [key, counter]
        AtlasPca::ClaimResult.new(true)
      end

      def last(_key)
        @reads += 1
        @reads == 1 ? nil : 7
      end
    end.new
    r = Seam.with(AtlasPca, { decision_of: ->(_v) { 'escalate' } }) { C06.go(is_revoked: ->(_p, _g) { true }, state_store: st) }
    ZD.ck('denied', [r.allow, r.decision, r.escalation, st.claims], [false, 'deny', nil, []]) &&
      ZD.ck('replay check', [r.checks['replay'], r.reasons.select { |w| w.start_with?('replay: ') }],
            ['fail', ['replay: 1 is not greater than last seen 7 (replay)']])
  end

  t('zd authorize: a budget seed that is not callable is no hook, and a plan that is not an Array supplies no distance') do
    next true unless ZD.gate?('authorize.rb')

    r = ZB.step(ctx: { 'budget' => nil }, store: ZB::Bs.new(nil), seed: ZB.bud(40))
    ZD.ck('seed is not callable', [r['persist'], r['stored'], r['after']], [true, nil, ZB.bud(100)]) &&
      begin
        r = ZB.step(plan_nodes: { 'id' => 'a' }, node_id: 'a', risk: ZB.no_sd)
        ZD.ck('a Hash plan', [r['r'], r['reasons'].first], [1, 'risk input(s) missing, assumed worst case: semanticDistance'])
      end &&
      begin
        r = C06.go(risk: {}, require_risk_inputs: ['semanticDistance'], context: ->(_p) { { 'plan' => { 'id' => 'x' } } })
        ZD.ck('a Hash plan does not supply the distance', [r.checks['risk_inputs'], r.reasons.include?('risk_inputs: required risk input(s) not supplied by the server: semanticDistance')],
              ['fail', true])
      end
  end

  t('zd authorize: a beacon pin that is not an Integer is no replay head; the budget table DDL is exact') do
    next true unless ZD.gate?('authorize.rb')

    g1 = ZaA.gid
    bk = F03.beacon(seq: 7, issued_at: C06::NOW - 1000, scope: g1)
    pc = C06.fixture_pcactn.merge('freshness' => { 'beacon_ref' => AtlasPca.beacon_ref(bk), 'epoch' => 1, 'accumulator_witness' => '' })
    odd = Class.new(AtlasPca::MemoryStateStore) do
      def pin(key)
        key.to_s.end_with?(':beacon') ? 9.5 : super
      end
    end.new
    r = ZaA.go(pc, beacon: { 'beacon' => bk, 'issuers' => [F03::ISSUER], 'instance' => F03::INSTANCE }, state_store: odd)
    ZD.ck('a Float pin', [r.allow, r.checks['beacon'], ZaA.why(r, 'beacon')], [true, 'pass', []]) &&
      ZD.ck('budget ddl', C06.sql_store(table: 'tb')[0].create_budget_table_sql, 'CREATE TABLE IF NOT EXISTS tb_budget (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)')
  end

  t('zd risk safety_bound: kappa of exactly 1 and a fractional kappa still divide') do
    next true unless ZD.gate?('risk.rb')

    ZD.ck('kappa 1', AtlasPca::Risk.safety_bound({ 'kappa' => 1, 'bMax' => 5 }), 5.0) &&
      ZD.ck('kappa 0.5', AtlasPca::Risk.safety_bound({ 'kappa' => 0.5, 'bMax' => 1 }), 2.0)
  end

  t('zd mesh: the ceiling text is printed as a JS number even for a numeric string') do
    next true unless ZD.gate?('mesh.rb')

    e = { 'actions' => nil, 'prefixes' => [], 'max_amount' => '7', 'expires_at' => nil, 'audience' => nil, 'max_hops' => nil }
    ZD.ck('ceiling', AtlasPca.mesh_admits(e, { 'type' => 'a', 'resource' => 'r', 'service_domain' => 's' }, 0, 1), 'amount exceeds ceiling 7')
  end

  t('zd azure: an allowlist that is not an Array is not consulted by sev_result / tdx_result') do
    next true if C09.skip?('azure.rb')

    k = C09.att::AzureMaaVerifier
    fl = ->(r) { { 'ok' => false, 'reason' => r } }
    mk = ->(pol) { k.new('trustedIssuers' => ['https://i'], 'trustAnchors' => { 'rootSpkiSha256' => ['aa'] }, 'policy' => pol) }
    vs = mk.call({ 'sevSnpMeasurements' => ['ab'] })
    sev = vs.send(:sev_result, vs.instance_variable_get(:@policy).merge('sevSnpHostData' => 'zz'), { 'x-ms-sevsnpvm-launchmeasurement' => 'AB' }, fl)
    vt = mk.call({ 'tdxMrtds' => ['cd'] })
    tdx = vt.send(:tdx_result, vt.instance_variable_get(:@policy).merge('tdxRtmrs' => 'zz'), { 'x-ms-tdx-mrtd' => 'CD' }, fl)
    ZD.ck('sev', [sev['ok'], sev['reason']], [true, nil]) && ZD.ck('tdx', [tdx['ok'], tdx['reason']], [true, nil])
  end

  t('zd intel: a collateral policy that reads falsy is handed over as nil') do
    next true if C11Intel.skip?

    c = C11Intel
    m96 = 'ab' * 48
    exp = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }
    want = c.cm.attestation_binding(exp)
    ok_quote = ->(*_a) { { 'ok' => true, 'report' => { 'reportData' => want }, 'measured' => { 'm' => 1 }, 'fmspc' => 'ab12' } }
    got = [false, '', 0].map do |val|
      seen = []
      ver = AtlasPca::Attest::IntelDcapVerifier.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [m96] }, 'trustAnchorRootCaSpkiSha256' => 'AA' * 32,
                                                      'resolve_evidence' => ->(_d) { { 'quote' => 'Qq'.b, 'collateral' => { 'k' => 1 } } } })
      ver.instance_variable_set(:@policy, ver.instance_variable_get(:@policy).merge('collateral' => val))
      stubs = { verify_genuine_tdx_quote: ok_quote, verify_intel_tdx_collateral: ->(*a) { seen << a; { 'ok' => true } } }
      MutationKill::Seam.with(c.i, stubs) { ver.verify({}, exp, 77) }
      seen.first[3]
    end
    ZD.ck('falsy policy values', got, [nil, nil, nil])
  end

  t('zd registry kits: one refused handle among accepted ones, and the epoch exactly at the post-restart bound') do
    next true unless ZD.gate?('store_conformance.rb')

    d = ZCKit
    su = d::SU.inspect
    lease = d.by(d.lease(d::Env.new(faults: [d.drop(4, :update)]), threads: 4, handles: 4))
    ZD.ck('first refusal is reported, not the first result', lease['lease-accept-race'], ['fail', "an identical record was refused: #{su}"]) &&
      begin
        bp = d.by(d.bp(d::Env.new(faults: [d.via(8, 2..3) { |_v| { 'v' => 1, 'max' => 3 } }]), threads: 4, handles: 4))['blueprint-durability']
        ZD.ck('epoch 3 meets the bound', bp[1].to_s.include?('epoch() is'), false)
      end
  end
end
