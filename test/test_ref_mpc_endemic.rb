# frozen_string_literal: true

# Replays the TS-reference oracle of the endemic LWE base OT (test-data/ref-mpc-endemic.json.gz) through AtlasPca::MpcLweOt. Needs liblweot
# (ATLAS_PCA_LIBLWEOT) through ffi. Receiver key seeds are labels: seed = sha256("atlas-pca-conformance/" + label). Every byte string is wrapped
# explicitly ({"$bytes"}), so a binary result is never read as text.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/mpc_lwe_ot'
require 'minitest/autorun'

class TestRefMpcEndemic < Minitest::Test
  E = AtlasPca::MpcLweOt
  CASES = Ref.load('mpc-endemic')

  def self.seed(label) = Digest::SHA256.digest("atlas-pca-conformance/#{label}")
  def self.bj(b) = { '$bytes' => Ref.b64e(b) }
  def self.bl(a) = a.map { |x| bj(x) }
  def self.bp(a) = a.map { |x| bl(x) }
  def self.rng(s) = E::SplitMix64.new(Integer(s, 10))
  def self.flip(b) = b.bytes.map { |x| x ^ 1 }.pack('C*')
  def self.fill(n, k) = Array.new(n) { |i| (i * 31 + k * 7 + (i >> 3)) & 255 }.pack('C*')

  def setup
    E.lib
  rescue LoadError => e
    raise if ENV['ATLAS_PCA_LIBLWEOT_REQUIRED'] == '1'

    skip e.message
  end

  def go(fn, call) = Ref.run(self, CASES[fn], call)

  def test_lwe_keygen_fips
    go('lweKeygenFips', lambda { |label|
      pk, sk = E.kpke_keygen_fips203(self.class.seed(label))
      { 'pk' => self.class.bj(pk), 'skSha256' => Digest::SHA256.hexdigest(sk) }
    })
  end

  def test_lwe_keygen
    go('lweKeygen', lambda { |label|
      pk, sk = E.kpke_keygen(self.class.seed(label))
      { 'pk' => self.class.bj(pk), 'skSha256' => Digest::SHA256.hexdigest(sk) }
    })
  end

  def test_lwe_enc = go('lweEnc', ->(label, msg, coins) { self.class.bj(E.kpke_enc(E.kpke_keygen(self.class.seed(label))[0], msg, coins)) })
  def test_lwe_dec = go('lweDec', ->(label, ct) { self.class.bj(E.kpke_dec(E.kpke_keygen(self.class.seed(label))[1], ct)) })
  def test_lwe_ring = go('lweRing', ->(op, a, b) { self.class.bj(op == 'add' ? E.ring_add(a, b) : E.ring_sub(a, b)) })
  def test_lwe_hash = go('lweHash', ->(x) { self.class.bj(E.hash_to_ring(x)) })

  def test_random_ot
    go('randomOt', lambda { |choices, rs, ss|
      msg, st = E.receive(choices, self.class.rng(rs))
      sm = E.send_random(msg, self.class.rng(ss))
      c = self.class
      { 'rn' => c.bj(msg.rn), 'points' => c.bp(msg.points), 'rhos' => c.bl(msg.rhos), 'ciphertexts' => c.bp(sm.ciphertexts),
        'senderPads' => c.bp(sm.sender_pads), 'recvPads' => c.bl(E.recover_random(st, sm)) }
    })
  end

  def test_random_ot_tamper
    go('randomOtTamper', lambda { |choices, rs, ss|
      msg, st = E.receive(choices, self.class.rng(rs))
      sm = E.send_random(msg, self.class.rng(ss), ->(c) { c[0][0] = c[0][0].byteslice(0, 1087) })
      self.class.bl(E.recover_random(st, sm))
    })
  end

  def test_base_ot
    go('baseOt', lambda { |messages, choices, sd, tamper|
      one = self.class.rng(sd) # one generator serves the receiver, then the sender, as the reference does
      c = self.class
      t = case tamper
          when 'enc' then ->(e) { e[0][0] = c.flip(e[0][0]) }
          when 'encChosen' then ->(e) { e[0][choices[0] & 1] = c.flip(e[0][choices[0] & 1]) }
          end
      received, tr = E.base_ot(messages, choices, one, one, t)
      { 'received' => c.bl(received), 'ciphertexts' => c.bp(tr.ciphertexts), 'encrypted' => c.bp(tr.encrypted), 'commitments' => c.bp(tr.commitments) }
    })
  end

  def test_send_malformed
    go('sendMalformed', lambda { |kind|
      c = self.class
      m, = E.receive([0, 1], c.rng('77'))
      rn = m.rn
      points = m.points.map(&:dup)
      rhos = m.rhos.dup
      rn = c.fill(31, 1) if kind == 'nonce'
      rhos = rhos.drop(1) if kind == 'count'
      points[1][0] = c.fill(1151, 1) if kind == 'point'
      rhos[0] = c.fill(33, 1) if kind == 'rho'
      E.send_random(E::ReceiverMessage.new(rn, points, rhos), c.rng('78')).ciphertexts.length
    })
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'lweKeygenFips' => 5, 'lweKeygen' => 5, 'lweEnc' => 14, 'lweDec' => 16, 'lweRing' => 13, 'lweHash' => 9, 'randomOt' => 5, 'randomOtTamper' => 1, 'baseOt' => 8, 'sendMalformed' => 4 }, CASES.transform_values(&:length))
  end

end
