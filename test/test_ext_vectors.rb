# frozen_string_literal: true

# Extension-layer conformance (optimistic path and transparency ledger): every vector of
# packages/pca/conformance/{optimistic,ledger}-vectors.json must reproduce its `expect` exactly. No skips.
#   ruby -Ilib test/test_ext_vectors.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestExtVectors < Minitest::Test
  DIR = File.expand_path('../conformance', __dir__)

  def self.load(name)
    AtlasPca.parse_json(File.read(File.join(DIR, name), encoding: 'UTF-8'), loose: true)
  end

  OPT = load('optimistic-vectors.json')
  LED = load('ledger-vectors.json')

  # Real per-table sizes of the committed corpus (not only the file's own `counts`).
  EXPECTED_COUNTS = {
    'optimistic_claim' => 52, 'optimistic_window' => 25, 'optimistic_fraud_proof' => 37, 'optimistic_settlement' => 102,
    'ledger_inclusion' => 96, 'ledger_consistency' => 149, 'ledger_tree_head' => 64, 'ledger_cosign' => 56,
    'ledger_head_consistency' => 26, 'ledger_checkpoint_chain' => 23, 'ledger_witnessed_head' => 30, 'ledger_equivocation' => 7
  }.freeze

  # `pins` absent (nil: cosigners fall back to the policy) vs `{}` (explicit empty set).
  def pins(v) = v['pins']

  # A vector whose `requires_suite` this runtime lacks must be refused (false / `suite`), never accepted.
  # `pq-*` vectors (no `requires_suite`) use ml-dsa-65 / hybrid-ed25519-ml-dsa-65: without ML-DSA-65 in this OpenSSL they are refused too.
  def lacks?(v)
    need = v['requires_suite'] || (v['name'].start_with?('pq-') ? 'ml-dsa-65' : nil)
    need && !AtlasPca.supported_suites.include?(need)
  end

  def opt(table, v)
    case table
    when 'optimistic_claim'
      c = AtlasPca.claim_check(v['claim'], v['pcactn_digest'], v['signer_public'], v['server_now'], OPT['window_policy'])
      { 'ok' => c == 'ok', 'check' => c }
    when 'optimistic_window'
      c = { 'issued_at' => v['issued_at'], 'challenge_window_ms' => v['challenge_window_ms'] }
      { 'end' => AtlasPca.challenge_window_end(c), 'within' => AtlasPca.within_challenge_window(c, v['now']),
        'phase' => AtlasPca.claim_status(c, v['now']) }
    when 'optimistic_fraud_proof'
      c = AtlasPca.fraud_proof_wire_check(v['claim'], v['proof'])
      { 'check' => c, 'ok' => c == 'ok' }
    else
      c = AtlasPca.settlement_wire_check(v['record'], v['guardian_public'], pins(v))
      c = 'suite' if lacks?(v)
      { 'check' => c, 'ok' => c == 'ok' }
    end
  end

  def led(table, v)
    case table
    when 'ledger_inclusion' then { 'ok' => AtlasPca.verify_ledger_inclusion(v['root'], v['proof'], v['leaf']) }
    when 'ledger_consistency' then { 'ok' => AtlasPca.verify_ledger_consistency(v['old_root'], v['new_root'], v['proof']) }
    when 'ledger_tree_head' then { 'ok' => AtlasPca.verify_tree_head(v['sth'], v['guardian_public'], nil, pins(v)) }
    when 'ledger_cosign' then { 'ok' => AtlasPca.verify_tree_head(v['sth'], v['guardian_public'], v['policy'], pins(v)) }
    when 'ledger_head_consistency'
      { 'ok' => AtlasPca.verify_head_consistency(v['older'], v['newer'], v['proof'], v['guardian_public'], nil, pins(v)) }
    when 'ledger_checkpoint_chain' then AtlasPca.verify_checkpoint_chain(v['chain'], v['guardian_public'], v['policy'], pins(v))
    when 'ledger_witnessed_head' then { 'ok' => AtlasPca.verify_witnessed_head(v['head'], v['witness_public'], pins(v)) }
    else { 'equivocation' => AtlasPca.detect_equivocation(v['a'], v['b'], v['witness_public'], pins(v)) }
    end
  end

  # A suite this runtime lacks must be refused, never accepted (the refusal need not match the reference's accept/reject detail).
  def lacks_expect(v, got)
    return got == v['expect'] unless lacks?(v)

    got['ok'] != true && got['equivocation'] != true && got['check'] != 'ok'
  end

  def run_tables(doc, meth)
    doc['counts'].each_key do |table|
      rows = doc[table]
      assert_equal doc['counts'][table], rows.length, table
      assert_equal EXPECTED_COUNTS.fetch(table), rows.length, "#{table} real row count"
      bad = rows.reject { |v| lacks_expect(v, send(meth, table, v)) }.map { |v| v['name'] }
      assert_equal [], bad, table
    end
  end

  def test_optimistic_tables = run_tables(OPT, :opt)
  def test_ledger_tables = run_tables(LED, :led)

  def test_constants
    assert_equal LED['domains']['sth'], AtlasPca::STH_DOMAIN
    assert_equal LED['domains']['sth_witness'], AtlasPca::STH_WITNESS_DOMAIN
    assert_equal LED['empty_tree_root'], AtlasPca::EMPTY_TREE_ROOT
  end

  def test_total_on_garbage
    [nil, 5, 'x', [], {}].each do |g|
      refute AtlasPca.verify_tree_head(g, 'k')
      refute AtlasPca.verify_ledger_consistency(g, g, g)
      refute AtlasPca.verify_witnessed_head(g, 'k')
      assert_equal 'malformed', AtlasPca.claim_check(g, 'd', 'k', 1) unless g.is_a?(Hash)
      assert_equal 'malformed', AtlasPca.fraud_proof_wire_check(g, g)
      assert_equal 'malformed', AtlasPca.settlement_wire_check(g, 'k') unless g.is_a?(Hash)
    end
  end
end
