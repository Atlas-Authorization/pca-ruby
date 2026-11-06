# frozen_string_literal: true
# Exact-outcome kill tests for passport.rb, ledger.rb and optimistic.rb against the shared vectors (passport-vectors.json
# incl. the hardware seam, ledger-vectors.json, optimistic-vectors.json).
module MutationKill
  module Ext
    module_function
    CONF = File.expand_path('../../conformance', __dir__)
    def load(n) = AtlasPca.parse_json(File.read(File.join(CONF, n), encoding: 'UTF-8'), loose: true)
    def passport = (@passport ||= load('passport-vectors.json')['passport_vectors'])
    def opt = (@opt ||= load('optimistic-vectors.json'))
    def led = (@led ||= load('ledger-vectors.json'))

    def passport_ok?(vs)
      docs = {}
      supported = AtlasPca.supported_suites
      vs.all? do |v|
        signed = v.key?('signed_ref') ? docs[v['signed_ref']] : v['signed']
        docs[v['name']] = signed
        revoked = v['revoked']
        seen = []
        attest = nil
        if v.key?('hardware')
          h = v['hardware']
          attest = lambda do |_d, exp|
            seen << exp
            raise 'down' if h['throws']

            { 'ok' => h['ok'], 'bound' => h['bound'], 'measured' => h['measured'] }
          end
        end
        got = AtlasPca.verify_passport(signed, v['trustedIssuers'], v['now'], clock_skew_ms: v['clockSkewMs'], max_evidence_age_ms: v['maxEvidenceAgeMs'],
                                       subject: v['subject'], revoked: ->(i, _a, _b) { revoked.include?(i) }, pq_pins: v['pqPins'], attest: attest)
        want = v['expect']['ok'] ? nil : v['expect']['reason']
        alg = signed.is_a?(Hash) ? signed['alg'] : nil
        want = 'unsupported_suite' if !alg.nil? && !supported.include?(alg)
        eb = v['expectBinding']
        got == want && (eb.nil? || seen == [{ 'holder_pub' => eb['holderPub'], 'grant_ref' => eb['grantRef'], 'epoch' => eb['epoch'], 'nonce' => eb['nonce'] }])
      end
    end

    def opt_row(table, v)
      case table
      when 'optimistic_claim'
        c = AtlasPca.claim_check(v['claim'], v['pcactn_digest'], v['signer_public'], v['server_now'], opt['window_policy'])
        { 'ok' => c == 'ok', 'check' => c }
      when 'optimistic_window'
        c = { 'issued_at' => v['issued_at'], 'challenge_window_ms' => v['challenge_window_ms'] }
        { 'end' => AtlasPca.challenge_window_end(c), 'within' => AtlasPca.within_challenge_window(c, v['now']), 'phase' => AtlasPca.claim_status(c, v['now']) }
      when 'optimistic_fraud_proof'
        c = AtlasPca.fraud_proof_wire_check(v['claim'], v['proof'])
        { 'check' => c, 'ok' => c == 'ok' }
      else
        c = AtlasPca.settlement_wire_check(v['record'], v['guardian_public'], v['pins'])
        c = 'suite' if lacks?(v)
        { 'check' => c, 'ok' => c == 'ok' }
      end
    end

    def led_row(table, v)
      case table
      when 'ledger_inclusion' then { 'ok' => AtlasPca.verify_ledger_inclusion(v['root'], v['proof'], v['leaf']) }
      when 'ledger_consistency' then { 'ok' => AtlasPca.verify_ledger_consistency(v['old_root'], v['new_root'], v['proof']) }
      when 'ledger_tree_head' then { 'ok' => AtlasPca.verify_tree_head(v['sth'], v['guardian_public'], nil, v['pins']) }
      when 'ledger_cosign' then { 'ok' => AtlasPca.verify_tree_head(v['sth'], v['guardian_public'], v['policy'], v['pins']) }
      when 'ledger_head_consistency' then { 'ok' => AtlasPca.verify_head_consistency(v['older'], v['newer'], v['proof'], v['guardian_public'], nil, v['pins']) }
      when 'ledger_checkpoint_chain' then AtlasPca.verify_checkpoint_chain(v['chain'], v['guardian_public'], v['policy'], v['pins'])
      when 'ledger_witnessed_head' then { 'ok' => AtlasPca.verify_witnessed_head(v['head'], v['witness_public'], v['pins']) }
      else { 'equivocation' => AtlasPca.detect_equivocation(v['a'], v['b'], v['witness_public'], v['pins']) }
      end
    end

    # `pins` absent (nil: cosigners fall back to the policy) vs `{}` (explicit empty set). A row whose suite this runtime lacks
    # (`requires_suite`, or a `pq-*` row other than `*-ml-skipped-*`, which needs ml-dsa-65) must be refused, never accepted.
    def lacks?(v)
      pq = v['name'].start_with?('pq-') && !v['name'].include?('-ml-skipped-')
      need = v['requires_suite'] || (pq ? 'ml-dsa-65' : nil)
      need && !AtlasPca.supported_suites.include?(need)
    end

    def row_ok?(v, got) = lacks?(v) ? (got['ok'] != true && got['equivocation'] != true && got['check'] != 'ok') : got == v['expect']

    def table_ok?(doc, table, meth) = doc[table].all? { |v| row_ok?(v, send(meth, table, v)) }
  end

  t('passport: vectors (reason codes, suites, hardware seam and binding)') { Ext.passport_ok?(Ext.passport) }
  t('passport: total on garbage and exact first reasons') do
    [nil, 5, 'x', [], {}, { 'typ' => 'atlas-pca/passport' }].all? { |g| AtlasPca.verify_passport(g, ['i'], 1, revoked: ->(*) { false }) == 'malformed' } &&
      AtlasPca.verify_passport({ 'typ' => 'atlas-pca/passport', 'passport' => {}, 'ver' => 2 }, ['i'], 1) == 'unsupported_version'
  end
  %w[optimistic_claim optimistic_window optimistic_fraud_proof optimistic_settlement].each do |tb|
    t("optimistic: #{tb} vectors") { Ext.table_ok?(Ext.opt, tb, :opt_row) }
  end
  %w[ledger_inclusion ledger_consistency ledger_tree_head ledger_cosign ledger_head_consistency ledger_checkpoint_chain ledger_witnessed_head ledger_equivocation].each do |tb|
    t("ledger: #{tb} vectors") { Ext.table_ok?(Ext.led, tb, :led_row) }
  end
  t('ledger: constants and totality') do
    AtlasPca::STH_DOMAIN == Ext.led['domains']['sth'] && AtlasPca::STH_WITNESS_DOMAIN == Ext.led['domains']['sth_witness'] &&
      AtlasPca::EMPTY_TREE_ROOT == Ext.led['empty_tree_root'] &&
      [nil, 5, 'x', [], {}].all? { |g| !AtlasPca.verify_tree_head(g, 'k') && !AtlasPca.verify_ledger_consistency(g, g, g) && !AtlasPca.verify_witnessed_head(g, 'k') }
  end
  t('optimistic: totality') do
    [nil, 5, 'x', []].all? { |g| AtlasPca.fraud_proof_wire_check(g, g) == 'malformed' && AtlasPca.settlement_wire_check(g, 'k') == 'malformed' && AtlasPca.claim_check(g, 'd', 'k', 1) == 'malformed' }
  end
end
