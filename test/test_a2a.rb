# frozen_string_literal: true

# The A2A binding against the shared vectors (packages/pca/conformance/a2a-vectors.json).
#   ruby -Ilib test/test_a2a.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestA2a < Minitest::Test
  FILE = File.expand_path('../conformance/a2a-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)

  def test_need
    assert_operator DOC['need'].length, :>=, 20
    DOC['need'].each do |c|
      need, code = AtlasPca.decode_a2a_need(c['input'])
      assert_equal c['expect']['ok'], code.nil?, c['name']
      if code.nil?
        assert_equal c['expect']['digest'], AtlasPca.a2a_need_digest(need), c['name']
      else
        assert_equal c['expect']['code'], code, c['name']
      end
    end
  end

  def test_push
    DOC['push']['tokens'].each { |t| assert_equal t['token'], AtlasPca.a2a_push_token(t['task_id'], t['chain_ids'], t['salt']) }
    DOC['push']['weak_salts'].each { |s| assert_nil AtlasPca.a2a_push_token('t', ['a'], s) }
    DOC['push']['checks'].each do |c|
      e = c['expected']
      assert_equal c['expect'], AtlasPca.check_a2a_push(e['task_id'], e['chain_ids'], e['salt'], c['delivered']['token'], c['delivered']['payload']), c['name']
    end
  end

  def test_chains
    DOC['chains'].each { |c| assert_equal c['expect'], AtlasPca.check_a2a_chain_extension(c['chains']), c['name'] }
  end

  def test_resume
    DOC['resume'].each do |c|
      got = AtlasPca.a2a_resume_gate(c['state'], c['need_encoded'], c['answer_need_digest'], c['proof_action'])
      c['expect'].nil? ? assert_nil(got, c['name']) : assert_equal(c['expect'], got, c['name'])
    end
  end

  def test_receipts
    r = DOC['receipts']
    r['verify'].each { |v| assert_equal v['ok'], AtlasPca.verify_a2a_receipt(r['records'][v['record']], r['signer']), v.to_s }
    r['digests'].each { |d| assert_equal d['digest'], AtlasPca.a2a_receipt_digest(r['records'][d['record']]) }
    r['scenarios'].each do |s|
      list = s['indices'].map { |i| r['records'][i] }
      assert_equal s['expect'], AtlasPca.check_a2a_receipt_chain(list, r['signer'], s['task_id'], s['chain_ids']), s['name']
      assert_equal s['may_trigger_next'], AtlasPca.a2a_may_trigger_next?(list, r['signer'], s['task_id'], s['chain_ids']), s['name']
    end
  end
  # a2a-auth.ts:273-278: a constant-time compare, length first
  def test_push_token_compare
    e = DOC['push']['tokens'][0]
    tok = e['token']
    check = ->(t) { AtlasPca.check_a2a_push(e['task_id'], e['chain_ids'], e['salt'], t, { 'task' => { 'id' => e['task_id'] } }) }
    flipped = tok[0...-1] + (tok[-1] == 'A' ? 'B' : 'A')
    calls = []
    orig = OpenSSL.method(:fixed_length_secure_compare)
    OpenSSL.define_singleton_method(:fixed_length_secure_compare) do |a, b|
      calls << [a, b]
      orig.call(a, b)
    end
    begin
      assert_equal({ 'ok' => true }, check.call(tok))
      assert_equal [[tok, tok]], calls
      [flipped, tok[0...-1], "#{tok}x"].each { |t| assert_equal({ 'ok' => false, 'reason' => 'token_mismatch' }, check.call(t)) }
      assert_equal 2, calls.length # the two wrong lengths never reach the compare
    ensure
      OpenSSL.define_singleton_method(:fixed_length_secure_compare, orig)
    end
    weak = DOC['push']['weak_salts'][0]
    assert_equal({ 'ok' => false, 'reason' => 'token_mismatch' }, AtlasPca.check_a2a_push('t', ['a'], weak, tok, {}))
  end
end
