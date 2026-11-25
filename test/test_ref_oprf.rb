# frozen_string_literal: true

# Replays the TS-reference oracle of RFC 9497 ristretto255-SHA512 OPRF / VOPRF / POPRF and the PCA private-revocation and private
# rate-limit layer (test-data/ref-oprf.json.gz). The keys are fixed throwaway test constants; needs libsodium (ratchet group).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/oprf'
require 'minitest/autorun'

class TestRefOprf < Minitest::Test
  O = AtlasPca::Oprf
  MAIN = Ref.load('oprf')
  GEN = Ref.load_gen('oprf')
  BY_FN = Ref.merge_cases(MAIN, GEN)
  NUL = Object.new.freeze # a JSON null where the reference distinguishes it from "absent": not bytes, so it is refused
  CAMEL = { 'secret_key' => 'secretKey', 'public_key' => 'publicKey', 'blind' => 'blind', 'blinded_element' => 'blindedElement',
            'evaluated_element' => 'evaluatedElement', 'tweaked_key' => 'tweakedKey', 'proof' => 'proof' }.freeze

  # binary Strings become {"$bytes"} so the comparison cannot confuse bytes with text
  def self.wire(v)
    case v
    when Hash then v.to_h { |k, x| [k, wire(x)] }
    when Array then v.map { |x| wire(x) }
    when String then v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v
    else v
    end
  end

  def self.cm(d) = wire(d.to_h { |k, v| [CAMEL.fetch(k), v] })
  def self.nn(v) = v.nil? ? NUL : v
  def self.opts(o) = o || {}

  def self.revocation(sk, ids, mode)
    x = O.build_revocation_set(sk, ids, mode)
    out = { 'outputs' => x['outputs'].to_a.sort, 'mode' => x['mode'] }
    out['publicKey'] = wire(x['public_key']) if x.key?('public_key')
    out
  end

  def self.revocation_eq(got, out, c)
    got = got.dup
    got.delete('publicKey') if c['name'].end_with?('-dups')
    got = got['mode'] if c['name'].end_with?('-surrogate')
    Ref.canon(got) == Ref.canon(out)
  end

  # without a pinned proof nonce the reference's proof is random: only the deterministic part is comparable
  def self.poprf_eval_eq(got, out, c)
    return Ref.canon(got['evaluatedElement']) == Ref.canon(out['evaluatedElement']) if c['name'].end_with?('bep-sk0')

    Ref.canon(got) == Ref.canon(out)
  end

  def self.revoked?(cap_id, op)
    sk = op['sk']
    st = O.build_revocation_set(sk, op['revoked'], op['mode'])
    real = O.make_revocation_evaluator(op['lie'] == 'wrong-key' ? O.serialize_scalar(12_345) : sk, op['mode'])
    ev = op['lie'] == 'no-proof' ? ->(b) { { 'evaluated_element' => real.call(b)['evaluated_element'] } } : real
    O.revoked_private?(cap_id, ev, st)
  end

  def self.private_rate(identifier, window, op)
    sk = op['sk']
    O.private_rate_token(identifier, window, O.make_rate_evaluator(sk), op['pk'] || O.public_key_for(sk))
  end

  def self.counter(limit, steps)
    c = O::RateWindowCounter.new(limit)
    steps.map do |s|
      case s[0]
      when 'hit' then c.hit(s[1])
      when 'count' then c.count(s[1])
      else
        c.reset
        nil
      end
    end
  end

  def self.finalize(data, blind, ev, mode, o = nil)
    o ||= {}
    wire(O.finalize(data, blind, ev, mode, o['proof'], o['publicKey'], o['blindedElement']))
  end

  MAP = {
    'deriveKeyPair' => [->(s, i, m) { cm(O.derive_key_pair(s, i, m)) }, {}],
    'publicKeyFor' => [->(sk) { wire(O.public_key_for(sk)) }, {}],
    'deserializeScalar' => [->(b) { O.deserialize_scalar(b).to_s }, {}],
    'serializeScalar' => [->(s) { wire(O.serialize_scalar(Integer(s))) }, {}],
    'hashToGroup' => [->(a, m) { wire(O.serialize_element(O.hash_to_group(a, m))) }, {}],
    'deserializeElement' => [->(b) { wire(O.serialize_element(O.deserialize_element(b))) }, {}],
    'blind' => [->(i, m, *r) { cm(O.blind(i, m, *r.map { |x| nn(x) })) }, {}],
    'blindEvaluate' => [->(sk, b, m, *r) { cm(O.blind_evaluate(sk, b, m, *r.map { |x| nn(x) })) }, {}],
    'evaluate' => [->(*a) { wire(O.evaluate(*a)) }, {}],
    'finalize' => [method(:finalize), {}],
    'blindPoprf' => [->(i, n, pk, *r) { cm(O.blind_poprf(i, n, pk, *r.map { |x| nn(x) })) }, {}],
    'blindEvaluatePoprf' => [->(sk, b, n, *r) { cm(O.blind_evaluate_poprf(sk, b, n, *r.map { |x| nn(x) })) }, { compare: method(:poprf_eval_eq) }],
    'finalizePoprf' => [->(data, blind, ev, info, o) { wire(O.finalize_poprf(data, blind, ev, info, o['proof'], o['blindedElement'], o['tweakedKey'])) }, {}],
    'evaluatePoprf' => [->(*a) { wire(O.evaluate_poprf(*a)) }, {}],
    'toHex' => [->(b) { O.to_hex(b) }, {}],
    'bytesEqual' => [->(a, b) { O.bytes_equal(a, b) }, {}],
    'buildRevocationSet' => [method(:revocation), { compare: method(:revocation_eq) }],
    'isRevokedPrivate' => [method(:revoked?), {}],
    'rateToken' => [->(*a) { wire(O.rate_token(*a)) }, {}],
    'rateTokenHex' => [->(*a) { O.rate_token_hex(*a) }, {}],
    'privateRateToken' => [->(*a) { wire(private_rate(*a)) }, {}],
    'rateCounter' => [method(:counter), {}]
  }.freeze

  def test_every_function_is_covered
    Ref.check_covered(self, BY_FN, GEN, MAP.keys)
  end

  def test_secret_corpus_present
    Ref.need_gen(self, 'oprf') if GEN.nil?
  end

  MAP.each do |fn, (call, kw)|
    define_method("test_#{fn}") do
      skip 'ref-oprf-gen.json.gz absent' if BY_FN[fn].nil? && GEN.nil?
      Ref.run(self, BY_FN[fn], call, **kw)
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 508, MAIN.values.sum(&:length), 'oprf'
  end

end
