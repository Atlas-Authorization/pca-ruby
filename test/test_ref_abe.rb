# frozen_string_literal: true

# Replays the TS-reference oracle of FAME CP-ABE on BLS12-381 (test-data/ref-abe.json.gz): scheme arithmetic, decrypt, policies,
# capability attributes. Needs libblst built together with the GT shim (PCA_BLST_LIB). The corpus carries no key bytes: master and
# user keys are recipes ({"$abeMsk": label}, {"$abeKey": {msk, attrs, id}}, optionally edited by "$patch" / "$edits" or merged by
# "$pool"), and the fixed scalars of the scheme cases are {"$seed": label}; every scalar is sha512("abe-oracle/" + label) mod r
# (1 for 0), so the keys are re-derived here.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/abe'
require 'minitest/autorun'

class TestRefAbe < Minitest::Test
  A = AtlasPca::Abe
  P = AtlasPca::AbePolicy
  F = AtlasPca::Fame
  B = AtlasPca::Bls12
  R = B::R

  def self.sc(label)
    n = Digest::SHA512.digest("abe-oracle/#{label}").unpack1('H*').to_i(16) % R
    n.zero? ? 1 : n
  end

  def self.b64(b) = Ref.b64e(b)
  def self.wire(b) = { '$bytes' => b64(b) }
  def self.enc(points) = points.map { |p| b64(p.compress) }

  MSKS = {} # rubocop:disable Style/MutableConstant

  def self.msk_raw(label)
    MSKS[label] ||= begin
      s = ->(n) { sc("#{label}/#{n}") }
      F.setup([s['a1'], s['a2']], [s['b1'], s['b2']], [s['d1'], s['d2'], s['d3']]).msk
    end
  end

  def self.seed_msk(label)
    m = msk_raw(label)
    { 'v' => 2, 'curve' => 'bls12-381', 'a' => m.a.map { |x| b64(B.i2osp(x, 32)) }, 'b' => m.b.map { |x| b64(B.i2osp(x, 32)) }, 'g' => enc(m.g) }
  end

  def self.seed_key(spec)
    id = spec['id']
    names = spec['attrs'].uniq.select { |a| a.is_a?(String) && !a.empty? && a.valid_encoding? }
    sigmas = names.each_index.map { |i| sc("#{id}/sg#{i}") }
    key = F.keygen(msk_raw(spec['msk']), names, [sc("#{id}/r1"), sc("#{id}/r2")], sigmas, sc("#{id}/sgp"))
    { 'v' => 2, 'curve' => 'bls12-381', 'k0' => enc(key.k0), 'kp' => enc(key.kp), 'attrs' => names.to_h { |n| [n, { 'k' => enc(key.attrs[n]) }] } }
  end

  def self.at(v, path) = path.reduce(v) { |x, p| x.is_a?(Array) ? x[p.to_i] : x[p] }

  def self.set(v, path, val, del)
    return val if path.empty?

    case v
    when Hash
      k = path[0]
      if path.length == 1 && del then v.delete(k) else v[k] = set(v[k], path[1..], val, del) end
    when Array
      i = path[0].to_i
      v << nil if i == v.length
      v[i] = path.length == 1 && del ? nil : set(v[i], path[1..], val, del)
    else raise 'path through a scalar'
    end
    v
  end

  # replaces every key recipe inside v by the derived key
  def self.resolve(v)
    case v
    when Array then v.map { |e| resolve(e) }
    when Hash
      return seed_msk(v['$abeMsk']) if v['$abeMsk'].is_a?(String)
      return seed_key(v['$abeKey']) if v['$abeKey'].is_a?(Hash)

      if v['$pool'].is_a?(Array)
        base = resolve(v['$pool'][0])
        v['$pool'][1..].each { |o| base['attrs'].merge!(resolve(o)['attrs']) }
        return base
      end
      if v.key?('$patch')
        base = resolve(v['$patch'])
        edits = v['$edits']
        vals = edits.map do |e| # a $ref reads the base as it was before any edit
          val = e['value']
          val.is_a?(Hash) && val['$ref'].is_a?(Array) ? Marshal.load(Marshal.dump(at(base, val['$ref']))) : val
        end
        edits.each_with_index { |e, i| base = set(base, e['path'], vals[i], vals[i].is_a?(Hash) && vals[i].key?('$undefined')) }
        return base
      end
      v.transform_values { |e| resolve(e) }
    else v
    end
  end

  GEN = Ref.load_gen('abe', seeds: false)
  CASES = Ref.merge_cases(Ref.load('abe', seeds: false), GEN).to_h { |fn, cs| [fn, cs.map { |c| c.merge('args' => resolve(c['args'])) }] }

  def self.fame(policy, attrs, scalars)
    n = P.normalize(policy)
    raise ArgumentError, n['reason'] unless n['ok']

    if scalars.key?('$seed') # a corpus that kept the label instead of the scalars
      l = scalars['$seed']
      scalars = { 'a' => %w[a1 a2], 'b' => %w[b1 b2], 'd' => %w[d1 d2 d3], 'r' => %w[r1 r2], 's' => %w[s1 s2],
                  'sigma' => attrs.each_index.map { |i| "sg#{i}" } }.transform_values { |ns| ns.map { |q| sc("#{l}#{q}").to_s(16) } }
                                                                      .merge('sigmaPrime' => sc("#{l}sgp").to_s(16))
    end
    x = ->(k) { scalars[k].map { |h| h.to_i(16) } } # the generator's scalars, as hex
    master = F.setup(x['a'], x['b'], x['d'])
    key = F.keygen(master.msk, attrs, x['r'], x['sigma'], scalars['sigmaPrime'].to_i(16))
    e = F.encrypt(master.mpk, n['tree'], x['s'])
    dec = F.decrypt(key, n['tree'], e.ct)
    w = ->(points) { points.map { |p| wire(p.compress) } }
    { 'h' => w.([master.mpk.h1, master.mpk.h2]), 't' => [wire(master.mpk.t1), wire(master.mpk.t2)], 'mskg' => w.(master.msk.g),
      'k0' => w.(key.k0), 'kp' => w.(key.kp), 'key' => key.attrs.transform_values { |c| w.(c) }, 'ct0' => w.(e.ct.ct0),
      'rows' => e.ct.rows.map { |r| w.(r) }, 'k' => wire(e.k), 'dec' => dec && wire(dec) }
  end

  def self.opt(r) = r && wire(r)

  MAP = {
    'fame' => ->(policy, attrs, seed) { fame(policy, attrs, seed) },
    'gtIsElement' => ->(b) { B::Gt.element?(b) },
    'gtPow' => ->(b, s) { wire(B::Gt.pow(b, s.to_i(16))) },
    'gtMul' => ->(a, b) { wire(B::Gt.mul(a, b)) },
    'pairingProduct' => lambda { |g1s, g2s|
      wire(B::Gt.pairing_product(g1s.map { |b| B::G1.decode(b) }, g2s.map { |b| B::G2.decode(b) }))
    },
    'normalizePolicy' => ->(p) { P.normalize(p) },
    'satisfies' => ->(tree, attrs) { P.satisfies?(tree, attrs) },
    'policyAttributes' => ->(tree) { P.policy_attributes(tree) },
    'parseCiphertext' => ->(x) { A.parse_ciphertext(x) },
    'decrypt' => ->(k, c) { opt(A.decrypt(k, c)) },
    'decryptText' => ->(k, c) { A.decrypt_text(k, c) },
    'decryptWithCapability' => ->(k, c) { A.decrypt_with_capability(k, c) },
    'encryptAccepts' => ->(mpk, policy) { A.encrypt_for_policy(mpk, policy, 'x') && true },
    'keygenForAttributes' => ->(msk, attrs) { A.keygen_for_attributes(msk, attrs)['attrs'].keys },
    'keygenForCapability' => lambda { |msk, cap, extra, opts|
      k = A.keygen_for_capability(msk, cap, extra, opts)
      { 'holder' => k['holder'], 'attrs' => k['attrs'].keys }
    },
    'capabilityAttributes' => ->(cap, opts) { P.js_sort(A.capability_attributes(cap, opts)) }
  }.freeze

  def test_corpus_is_covered
    Ref.check_covered(self, CASES, GEN, MAP.keys)
  end

  def test_secret_corpus_present
    Ref.need_gen(self, 'abe') if GEN.nil?
  end

  MAP.each_key do |fn|
    define_method("test_#{fn}_matches_the_reference") do
      skip 'ref-abe-gen.json.gz absent' if CASES[fn].nil? && GEN.nil?
      Ref.run(self, CASES[fn], MAP[fn])
    end
  end

  def test_round_trip_and_collusion
    m = A.setup
    policy = { 'allOf' => [{ 'attr' => 'a' }, { 'attr' => 'b' }] }
    ct = A.encrypt_for_policy(m['mpk'], policy, 'hello')
    both = A.keygen_for_attributes(m['msk'], %w[a b])
    one_a = A.keygen_for_attributes(m['msk'], ['a'])
    one_b = A.keygen_for_attributes(m['msk'], ['b'])
    assert_equal 'hello'.b, A.decrypt(both, ct)
    assert_nil A.decrypt(one_a, ct)
    other = A.setup
    assert_nil A.decrypt(A.keygen_for_attributes(other['msk'], %w[a b]), ct)
    colluding = one_a.merge('attrs' => one_a['attrs'].merge(one_b['attrs']))
    assert_nil A.decrypt(colluding, ct)
    tampered = ct.merge('ct' => ct['ct'].sub(/.\z/) { |c| c == 'A' ? 'B' : 'A' })
    assert_nil A.decrypt(both, tampered)
  end
end
