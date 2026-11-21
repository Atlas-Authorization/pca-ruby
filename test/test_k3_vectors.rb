# frozen_string_literal: true

# K3 operational-plane artifacts (policy bundles, decision log, list receipts / cursors, grant management) against the shared
# vectors (packages/pca/conformance/k3-vectors.json): every entry must reproduce its `expect` exactly.
#   ruby -Ilib test/test_k3_vectors.rb
require_relative '../lib/atlas_pca'
require_relative '../lib/atlas_pca/k3'
require 'minitest/autorun'

class TestK3Vectors < Minitest::Test
  FILE = File.expand_path('../conformance/k3-vectors.json', __dir__)
  P = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)['primitives']

  COUNTS = {
    'fresh_at_verify' => 5, 'fresh_at_digest' => 2, 'fresh_at_check' => 14, 'bundle_digest' => 2, 'bundle_verify' => 15,
    'log_commit' => 3, 'log_head_verify' => 4, 'log_inclusion' => 6, 'log_batch_verify' => 9, 'list_objects_digest' => 1,
    'list_receipt_verify' => 6, 'list_bind' => 2, 'list_cursor_verify' => 11, 'authority_digest' => 2, 'authority_compare' => 11,
    'amend_verify' => 16, 'revoke_verify' => 7, 'need_approve_verify' => 11
  }.freeze

  def test_the_corpus_is_complete
    assert_equal COUNTS, P.transform_values(&:length)
  end

  def amend(i)
    r = AtlasPca.verify_amendment(i['grant'], i['request'], i['step_up_ok'])
    r['ok'] ? { 'ok' => true, 'widens' => r['widens'], 'next_digest' => AtlasPca.authority_digest(r['next']) } : r
  end

  def need(i)
    r = AtlasPca.verify_need_approval(i['need_request'], i['grant'], i['approved'], i['sig'], i['step_up_ok'])
    r['ok'] ? { 'ok' => true, 'authority_digest' => AtlasPca.authority_digest(r['authority']) } : r
  end

  def run_entry(kind, i)
    case kind
    when 'fresh_at_verify' then { 'valid' => AtlasPca.verify_fresh_at(i['token'], i['signer']) }
    when 'fresh_at_digest' then { 'digest' => AtlasPca.fresh_at_digest(i['token']) }
    when 'fresh_at_check'
      o = i['options']
      AtlasPca.check_fresh_at(i['token'], i['local'], signer: o['signer'], scope: o['scope'], now: o['now'], max_token_age_ms: o['maxTokenAgeMs'])
    when 'bundle_digest' then { 'digest' => AtlasPca.bundle_digest(i['bundle']) }
    when 'bundle_verify' then AtlasPca.verify_bundle(i['bundle'], i['options'])
    when 'log_commit' then { 'commit' => AtlasPca.record_commit(i['record']) }
    when 'log_head_verify' then { 'valid' => AtlasPca.verify_log_head(i['head'], i['signer']) }
    when 'log_inclusion' then { 'valid' => AtlasPca.verify_record_inclusion(i['record'], i['proof'], i['head'], i['signer']) }
    when 'log_batch_verify' then AtlasPca.verify_batch(i['batch'], i['state'], i['signer'])
    when 'list_objects_digest' then { 'digest' => AtlasPca.objects_digest(i['objects']) }
    when 'list_receipt_verify' then { 'valid' => AtlasPca.verify_list_receipt(i['receipt'], i['signer'], i['objects']) }
    when 'list_bind' then { 'digest' => AtlasPca.list_bind(i['bind']) }
    when 'list_cursor_verify' then AtlasPca.verify_list_cursor(i['cursor'], i['signer'], i['bind'])
    when 'authority_digest' then { 'digest' => AtlasPca.authority_digest(i['authority']) }
    when 'authority_compare' then { 'order' => AtlasPca.compare_authority(i['old'], i['new']) }
    when 'amend_verify' then amend(i)
    when 'revoke_verify' then AtlasPca.verify_revoke_signature(i['root'], i['scope'], i['sig'])
    when 'need_approve_verify' then need(i)
    else flunk "unhandled vector kind #{kind}"
    end
  end

  def test_every_entry
    bad = []
    P.each do |kind, entries|
      entries.each do |e|
        got = run_entry(kind, e['input'])
        bad << "#{kind}/#{e['name']}: got #{got.inspect} want #{e['expect'].inspect}" if got != e['expect']
      end
    end
    assert_equal [], bad
  end

  # Total: hostile input yields the failure value and never raises.
  def test_hostile_input_never_raises
    [nil, 7, 'x', [], {}, { 'v' => 1 }].each do |junk|
      refute AtlasPca.verify_fresh_at(junk, 'k')
      refute AtlasPca.verify_log_head(junk, 'k')
      refute AtlasPca.verify_list_receipt(junk, 'k')
      refute AtlasPca.verify_record_inclusion(junk, junk, junk, 'k')
      refute AtlasPca.verify_bundle(junk, { 'signers' => [], 'threshold' => 1, 'verifierVersion' => '1.0.0' })['ok']
      refute AtlasPca.verify_batch(junk, junk, 'k')['ok']
      refute AtlasPca.verify_list_cursor(junk, 'k')['ok']
      refute AtlasPca.verify_amendment(junk, junk, true)['ok']
      refute AtlasPca.verify_revoke_signature(junk, 'grant', junk)['ok']
      refute AtlasPca.verify_need_approval(junk, junk, junk, junk, true)['ok']
    end
  end
end
