# frozen_string_literal: true

# Replays the TS-reference oracle of the Transaction Token bridge (test-data/ref-txn-tokens.json.gz).
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefTxnTokens < Minitest::Test
  T = AtlasPca::TxnTokens
  CASES = Ref.load('txn-tokens')

  # Issue is random (iat, exp, jti / txn): compare {header, claims} with iat dropped, exp as `ttl`, a generated id as true.
  ISSUE = lambda do |a|
    a = Ref.snake(a)
    tok = T.to_transaction_token(a.merge('issuer_key' => Ref.b64d(a.delete('seed'))))
    header, c = tok.split('.')[0, 2].map { |s| JSON.parse(Ref.b64d(s)) }
    keep = c.except('iat', 'exp', 'jti', 'txn').merge('ttl' => c['exp'] - c['iat'])
    keep['jti'] = true if c.key?('jti')
    keep['txn'] = a.key?('txn') ? c['txn'] : true if c.key?('txn')
    { 'header' => header, 'claims' => keep }
  end

  VERIFY = lambda do |jwt, pk, w|
    o = Ref.snake(w.slice('profile', 'audience', 'clockToleranceSec', 'nowMs'))
    if w['seen']
      seen = w['seen']
      o['seen_txn'] = ->(id, _exp) { seen.include?(id) }
    end
    o['replay_check'] = 'unchecked' if w['unchecked']
    T.from_transaction_token(jwt, Ref.b64d(pk), o)
  end

  FNS = {
    'subActChain' => ->(c) { T.sub_act_chain(c) },
    'actDepth' => ->(c) { T.act_depth(c) },
    'toRfc8693Act' => ->(c) { T.to_rfc8693_act(c) },
    'toTransactionToken' => ISSUE,
    'fromTransactionToken' => VERIFY
  }.freeze

  def test_every_fn_is_mapped
    assert_empty CASES.keys - FNS.keys
  end

  FNS.each { |fn, call| define_method("test_#{fn}") { Ref.run(self, CASES[fn], call) } }

  def test_a_replayed_id_is_refused_only_after_every_other_check
    calls = []
    jwt = CASES['fromTransactionToken'].find { |c| c['name'].end_with?('/act deep bad') }['args'][0]
    pk = CASES['fromTransactionToken'].find { |c| c['name'].end_with?('/draft ok') }['args'][1]
    assert_raises(ArgumentError) do
      T.from_transaction_token(jwt, Ref.b64d(pk), 'audience' => 'td.example', 'now_ms' => 1_800_000_000_500,
                                                  'seen_txn' => ->(id, _) { calls << id && false })
    end
    assert_empty calls, 'a token refused for another reason never burns its id'
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 106, CASES.values.sum(&:length), 'txn-tokens'
  end

end
