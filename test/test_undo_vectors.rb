# frozen_string_literal: true

# Undo windows, the pure layer: replays packages/pca/conformance/undo-vectors.json (compensation digests, the one-click token,
# receipts and chains, every transition, the window clamp and the undo_window obligation; a missing file fails). The signer is
# re-derived from its seed label, so tokens and receipts are re-signed and compared byte for byte.
#   ruby -Ilib test/test_undo_vectors.rb
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'digest'

class TestUndoVectors < Minitest::Test
  FILE = File.expand_path('../conformance/undo-vectors.json', __dir__)
  DOC = AtlasPca.parse_json(File.read(FILE, encoding: 'UTF-8'), loose: true)
  KEY = AtlasPca::KeyPair.new(Digest::SHA256.digest(DOC['signer']['seed_label']))

  def test_format_and_signer
    assert_equal ['pca-undo-vectors', 1], [DOC['format'], DOC['ver']]
    assert_equal DOC['signer']['public'], KEY.public
    assert_equal [3, 12, 4, 12, 33, 9, 6],
                 [DOC['compensation'].length, DOC['token']['checks'].length, DOC['receipts']['list'].length,
                  DOC['receipts']['chains'].length, DOC['transitions'].length, DOC['window'].length, DOC['obligation'].length]
  end

  def test_compensation_digest
    DOC['compensation'].each { |c| assert_equal c['digest'], AtlasPca.compensation_digest(c['compensation']), c['name'] }
  end

  def test_token_sign_encode_decode_digest
    t = DOC['token']
    assert_equal t['token'], AtlasPca.sign_undo_token(t['record'], KEY)
    assert_equal t['encoded'], AtlasPca.encode_undo_token(t['token'])
    assert_equal t['token'], AtlasPca.decode_undo_token(t['encoded'])
    assert_equal t['digest'], AtlasPca.undo_token_digest(t['token'])
  end

  DOC['token']['checks'].each do |c|
    define_method("test_token_check_#{c['name'].tr('-', '_')}") do
      assert_equal c['expect'], AtlasPca.undo_token_check(c['token'], c['signer'], c['record'], c['now'])
    end
  end

  def test_receipts_resign_and_digest
    DOC['receipts']['list'].each_with_index do |x, i|
      r = x['receipt']
      body = r.reject { |k, _| %w[v kind signer sig].include?(k) }
      assert_equal r, AtlasPca.sign_undo_receipt(body, KEY), "receipt #{i}"
      assert_equal x['digest'], AtlasPca.undo_receipt_digest(r), "receipt #{i}"
      assert AtlasPca.verify_undo_receipt(r, KEY.public)
      refute AtlasPca.verify_undo_receipt(r, DOC['signer']['other_public'])
    end
  end

  DOC['receipts']['chains'].each do |c|
    define_method("test_chain_#{c['name'].tr('-', '_')}") do
      err = AtlasPca.undo_receipt_chain_error(c['record'].merge('receipts' => c['receipts']), c['signer'])
      if c['expect']['ok']
        assert_nil err
      else
        refute_nil err
      end
    end
  end

  DOC['transitions'].each do |t|
    define_method("test_transition_#{t['name'].tr('-', '_')}") do
      got = AtlasPca.undo_transition(t['record'], t['event'], t['now'])
      e = t['expect']
      assert_equal e['outcome'], got['outcome']
      case e['outcome']
      when 'refused' then assert_equal e['code'], got['code']
      when 'applied'
        assert_equal e['state'], got['record']['state']
        assert_equal e['ver'], got['record']['ver']
        assert_equal e['attempt'], got['record']['attempt'] if e.key?('attempt')
      when 'replayed' then assert_equal t['record'], got['record']
      end
    end
  end

  def test_window
    DOC['window'].each { |w| assert_equal w['expect'], AtlasPca.resolve_undo_window(w['requested'], w['policy']), w['name'] }
  end

  def test_obligation
    DOC['obligation'].each { |o| assert_equal o['expect']['ok'], AtlasPca.obligation_error(o['obligation']).nil?, o['name'] }
  end
end
