# frozen_string_literal: true

# Behaviour of the public helpers of the Ruby verifier, pinned exactly (the conformance corpus reaches most of them only
# through verify_pcactn, whose wire checks run first). Written to kill surviving mutants of tools/pca-audit/ruby-mutate.
module MutationKill
  module H
    module_function

    def malformed_msg
      yield
      nil
    rescue AtlasPca::Malformed => e
      e.message
    end

    def strictly_false(v) = v.equal?(false)
    def strictly_nil(v) = v.nil?
  end

  # ---------------------------------------------------------------- constants are frozen, domains are binary
  t('constants frozen, domain strings binary') do
    m = AtlasPca
    [m::SIG_DOMAIN, m::CAP_DOMAIN, m::SIGNERSET_DOMAIN, m::HOLDER_PQ_DOMAIN].all? { |c| c.frozen? && c.encoding == Encoding::BINARY } &&
      [m::CAVEAT_LIMIT_REASON, m::ARTIFACT_SIZE_REASON, m::CHECK_ORDER, m::Ed25519Strict::IDENTITY, m::THRESHOLD_ROLES,
       m::PQ_PK_LENGTHS, m::SIG_SUITES, m::TOP_REQUIRED].all?(&:frozen?) &&
      m::DEFAULT_REV == 'reversible'
  end

  # ---------------------------------------------------------------- caveat caps: 256 per hop, 1024 per chain (inclusive)
  t('caveat caps 256/hop, 1024/chain') do
    hop = ->(n) { { 'caveats' => Array.new(n) { { 'type' => 'x' } } } }
    !AtlasPca.caveat_limit_exceeded?([hop.call(256)]) && AtlasPca.caveat_limit_exceeded?([hop.call(257)]) &&
      !AtlasPca.caveat_limit_exceeded?([hop.call(256)] * 4) && AtlasPca.caveat_limit_exceeded?([hop.call(256)] * 4 + [hop.call(1)]) &&
      !AtlasPca.caveat_limit_exceeded?([hop.call(255)] * 4 + [hop.call(4)]) && AtlasPca.caveat_limit_exceeded?([hop.call(255)] * 4 + [hop.call(5)])
  end

  # ---------------------------------------------------------------- strict parser messages and encodings
  t('parse_json: not a string / invalid UTF-8 / not an object') do
    H.malformed_msg { AtlasPca.parse_json(5) } == 'not a string' &&
      H.malformed_msg { AtlasPca.parse_json("[\"\xff\"]".dup.force_encoding('UTF-8'), any_top: true) } == 'invalid UTF-8' &&
      H.malformed_msg { AtlasPca.parse_json("[\"\xff\"]".b, any_top: true) } == 'invalid UTF-8' &&
      H.malformed_msg { AtlasPca.parse_json('[1]') } == 'document must be an object'
  end
  t('parse_json does not touch the caller string') do
    s = '{"a":1}'.b
    AtlasPca.parse_json(s) == { 'a' => 1 } && s.encoding == Encoding::BINARY && AtlasPca.parse_json('{"a":1}'.freeze) == { 'a' => 1 }
  end
  t('parse_json numeric lexeme cap 64 KiB') do
    H.malformed_msg { AtlasPca.parse_json("[#{'1' * 65_536}]", any_top: true) } == 'unsafe integer' &&
      H.malformed_msg { AtlasPca.parse_json("[#{'1' * 65_537}]", any_top: true) } == 'bad value'
  end
  t('parse_json magnitude floor is exactly 1e-6') do
    AtlasPca.parse_json('[0.000001]', any_top: true) == [0.000001] &&
      H.malformed_msg { AtlasPca.parse_json('[0.0000009999995]', any_top: true) } == 'magnitude below 1e-6'
  end
  # surrogate ranges: high D800..DBFF, low DC00..DFFF; U+E000 is an ordinary character
  t('parse_json surrogate ranges') do
    e = ->(*hex) { hex.map { |h| "#{92.chr}u#{h}" }.join } # JSON \uXXXX escapes, built so no tool can decode them
    j = ->(s) { AtlasPca.parse_json("[\"#{s}\"]", any_top: true) }
    H.malformed_msg { j.call(e.call('dc00', 'dc00')) } == 'lone surrogate' &&
      H.malformed_msg { j.call(e.call('d800', 'e000')) } == 'lone surrogate' &&
      H.malformed_msg { j.call(e.call('d800')) } == 'lone surrogate' &&
      j.call(e.call('e000')) == [[0xe000].pack('U')] && j.call(e.call('dbff', 'dfff')) == [[0x10ffff].pack('U')] &&
      j.call(e.call('d800', 'dc00')) == [[0x10000].pack('U')]
  end
  # loose mode keeps a lone surrogate as its exact WTF-8 bytes (an invalid UTF-8 string, refused later at the wire)
  t('parse_json loose: lone surrogates are exact WTF-8') do
    w = ->(e) { AtlasPca.parse_json("[\"#{e}\"]", loose: true, any_top: true)[0].b }
    w.call('\ud800') == "\xed\xa0\x80".b && w.call('\udfff') == "\xed\xbf\xbf".b && w.call('\udc01') == "\xed\xb0\x81".b &&
      w.call('\ud9a5') == "\xed\xa6\xa5".b
  end

  # ---------------------------------------------------------------- number_ok? / tree_ok?
  t('number_ok? exact values') do
    n = ->(x) { AtlasPca.number_ok?(x) }
    [Float::NAN, Float::INFINITY, -Float::INFINITY, 0.0, -0.0, 1.0, 2.0**60, 0.0000009, '1', nil, true].all? { |x| H.strictly_false(n.call(x)) } &&
      n.call(1.5) == true && n.call(0) == true && n.call(2**53 - 1) == true && n.call(2**53) == false && n.call(-(2**53)) == false
  end
  t('tree_ok? depth 32 and key rules') do
    arr = ->(k) { v = []; (k - 1).times { v = [v] }; v }
    obj = ->(k) { v = 1; k.times { v = { 'a' => v } }; v }
    AtlasPca.tree_ok?(arr.call(32)) && !AtlasPca.tree_ok?(arr.call(33)) && AtlasPca.tree_ok?(obj.call(32)) && !AtlasPca.tree_ok?(obj.call(33)) &&
      AtlasPca.tree_ok?({ 'k' => [obj.call(30)] }) && !AtlasPca.tree_ok?({ 'k' => [obj.call(31)] }) &&
      !AtlasPca.tree_ok?({ "\xff".dup.force_encoding('UTF-8') => 1 }) && !AtlasPca.tree_ok?({ 1 => 1 }) && !AtlasPca.tree_ok?({ k: 1 }) &&
      !AtlasPca.tree_ok?('ab'.b) && !AtlasPca.tree_ok?("\xff".b) && AtlasPca.tree_ok?('ab') && H.strictly_false(AtlasPca.tree_ok?(Object.new))
  end

  # ---------------------------------------------------------------- base64url
  t('b64d rejects non-strings without raising') do
    [5, nil, :sym, ['AA']].all? { |x| H.strictly_nil(AtlasPca.b64d(x)) } && AtlasPca.b64d('AA') == "\x00".b
  end

  # ---------------------------------------------------------------- float formatting (plain decimal, shortest round-trip)
  t('fmt_float exact') do
    f = ->(x) { AtlasPca.fmt_float(x) }
    f.call(0.0) == '0' && f.call(-0.0) == '0' && f.call(1.0) == '1' && f.call(2.0) == '2' && f.call(1.5) == '1.5' &&
      f.call(0.00001) == '0.00001' && f.call(0.000015) == '0.000015' && f.call(-0.000012) == '-0.000012' && f.call(1e20) == '100000000000000000000' &&
      f.call(1.5e17) == '150000000000000000'
  end
  t('BigDecimalLike.plain exact') do
    p = ->(x) { AtlasPca::BigDecimalLike.plain(x) }
    p.call(1.0e20) == '100000000000000000000' && p.call(1.25e18) == '1250000000000000000' && p.call(-3.0e16) == '-30000000000000000' &&
      p.call(1.0e-05) == '0.00001' && p.call(1.2e-07) == '0.00000012'
  end

  # ---------------------------------------------------------------- canonical form
  t('canonicalize symbol keys, bytewise order, unsupported type message') do
    AtlasPca.canonicalize({ b: 1, a: 2 }) == '{"a":2,"b":1}' &&
      AtlasPca.canonicalize({ "\u{e9}" => 1, "\u{10000}" => 2, 'z' => 3 }) == "{\"z\":3,\"\u{e9}\":1,\"\u{10000}\":2}" &&
      H.malformed_msg { AtlasPca.canonicalize(Object.new) } == 'unsupported type Object' &&
      AtlasPca.canon_bytes({ 'a' => 1 }).encoding == Encoding::BINARY
  end

  # ---------------------------------------------------------------- Merkle inclusion: false (never nil / true) on every bad proof
  t('verify_inclusion is strictly false on bad proofs') do
    leaves = [{ 'n' => 1 }, { 'n' => 2 }, { 'n' => 3 }]
    root = AtlasPca.merkle_root(leaves)
    one = AtlasPca.merkle_root([leaves[0]])
    hb = AtlasPca.b64e(AtlasPca.leaf_hash(leaves[1]))
    good = { 'index' => 0, 'size' => 2, 'path' => [{ 'side' => 'R', 'hash' => hb }] }
    r2 = AtlasPca.merkle_root(leaves[0, 2])
    vi = ->(rt, pr, lf) { AtlasPca.verify_inclusion(rt, pr, lf) }
    vi.call(r2, good, leaves[0]) == true &&
      vi.call(one, { 'index' => 0, 'size' => 1, 'path' => [] }, leaves[0]) == true &&
      [nil, 5, { 'index' => 0, 'size' => 2 }, { 'index' => 0, 'size' => 2, 'path' => 'x' },
       good.merge('index' => 0.0), good.merge('size' => 2.0), good.merge('index' => 2), good.merge('index' => -1),
       good.merge('size' => 0), good.merge('path' => []), good.merge('path' => [5]), good.merge('path' => [{ 'side' => 'L', 'hash' => hb }]),
       good.merge('path' => [{ 'side' => 'R', 'hash' => 'AA' }]), good.merge('path' => [{ 'side' => 'R', 'hash' => 5 }])].all? { |pr| H.strictly_false(vi.call(r2, pr, leaves[0])) } &&
      H.strictly_false(vi.call(one, { 'index' => 0.0, 'size' => 1, 'path' => [] }, leaves[0])) &&
      H.strictly_false(vi.call(one, { 'index' => 0, 'size' => 1.0, 'path' => [] }, leaves[0])) &&
      H.strictly_false(vi.call(r2, good, Object.new)) && H.strictly_false(vi.call(root, good, leaves[0]))
  end
  t('safe_int? bounds') do
    AtlasPca.safe_int?(2**53 - 1) && AtlasPca.safe_int?(-(2**53 - 1)) && !AtlasPca.safe_int?(2**53) && !AtlasPca.safe_int?(-(2**53)) && !AtlasPca.safe_int?(1.0)
  end
  t('plan_leaf defaults and missing node_id') do
    l = AtlasPca.plan_leaf('n1', { 'verb' => 'v', 'resource' => 'r' }, 'c')
    l == { 'node_id' => 'n1', 'verb' => 'v', 'resource' => 'r', 'params_digest' => AtlasPca.params_digest(nil),
           'reversibility_class' => 'reversible', 'conditions' => 'c' } &&
      AtlasPca.plan_leaf('n1', { 'params_digest' => 'p', 'reversibility_class' => 'irreversible' }, nil).values_at('params_digest', 'reversibility_class') == %w[p irreversible] &&
      H.malformed_msg { AtlasPca.plan_leaf(nil, {}, nil) } == 'missing node_id'
  end

  # ---------------------------------------------------------------- strict Ed25519 point decoding
  t('Ed25519Strict.decode: length, sign bit, exact coordinates') do
    e = AtlasPca::Ed25519Strict
    by = 4 * 5.pow(e::P - 2, e::P) % e::P # base point y = 4/5
    le = ->(n) { (0...32).map { |i| (n >> (8 * i)) & 0xff }.pack('C*') }
    b = e.decode(le.call(by))
    nb = e.decode(le.call(by | (1 << 255)))
    b && nb && b[1] == by && nb[1] == by && b[0] == 15_112_221_349_535_400_772_501_151_409_588_531_511_454_012_693_041_857_206_046_113_283_949_847_762_202 &&
      nb[0] == e::P - b[0] && e.decode(le.call(by)[0, 31]).nil? && e.decode(le.call(by) + "\x00").nil?
  end
end
