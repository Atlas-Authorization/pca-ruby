# frozen_string_literal: true

# Replays the TS-reference oracle of the SCITT receipts (test-data/ref-scitt.json.gz): the deterministic CBOR codec, the
# RFC 9162 tree, COSE Signed Statements and Receipts (EdDSA byte-exact, ES256 by verification outcome), the in-memory and
# durable transparency services and the file-backed log store.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/jose'
require_relative '../lib/atlas_pca/scitt'
require_relative '../lib/atlas_pca/scitt_log'
require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'digest'

class TestRefScitt < Minitest::Test
  S = AtlasPca::Scitt
  L = AtlasPca::ScittLog
  BY_FN = Ref.load('scitt')
  HALF_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 >> 1
  TMP = Dir.mktmpdir('scitt-rb-')
  Minitest.after_run { FileUtils.rm_rf(TMP) }
  @@n = 0

  # a corpus key spec -> the native key: raw seed / public key bytes (EdDSA) or an OpenSSL P-256 key (ES256)
  def self.key(spec, priv)
    return Ref.b64d(priv ? spec['seed'] : spec['pub']) if spec['alg'] == 'EdDSA'

    jwk = { 'kty' => 'EC', 'crv' => 'P-256', 'x' => spec['x'], 'y' => spec['y'] }
    priv ? AtlasPca::Jose.private_key_from_jwk(jwk.merge('d' => spec['d'])) : AtlasPca::Jose.public_key_from_jwk(jwk)
  end

  # native bytes -> the oracle's {"$bytes"} form, anywhere in a result
  def self.wire(v)
    case v
    when S::CborTag then { '$tag' => v.tag, 'v' => wire(v.value) }
    when Hash then v.transform_values { |x| wire(x) }
    when Array then v.map { |x| wire(x) }
    when String then v.encoding == Encoding::BINARY ? { '$bytes' => Ref.b64e(v) } : v
    else v
    end
  end

  def self.w(fn) = ->(*a) { wire(fn.call(*a)) }

  def self.from_cj(v)
    case v
    when Hash
      return v['$map'].to_h { |k, x| [k, from_cj(x)] } if v.key?('$map')
      return S::CborTag.new(v['$tag'], from_cj(v['v'])) if v.key?('$tag')

      v
    when Array then v.map { |x| from_cj(x) }
    else v
    end
  end

  def self.to_cj(v)
    case v
    when S::CborTag then { '$tag' => v.tag, 'v' => to_cj(v.value) }
    when Hash then { '$map' => v.map { |k, x| [k, to_cj(x)] } }
    when Array then v.map { |x| to_cj(x) }
    else v
    end
  end

  def self.high(op) = { 'allow_high_s' => (op || {})['allowHighS'] || false }

  def self.sign_statement(payload, spec)
    opts = {}
    opts['subject'] = spec['subject'] if spec.key?('subject')
    opts['content_type'] = spec['contentType']
    S.sign_statement(payload, spec['alg'], key(spec['key'], true), spec['issuer'], opts)
  end

  def self.build_receipt(root, proof, signer)
    S.build_receipt(root, proof, signer['alg'], key(signer['key'], true), signer.key?('issuer') ? { 'issuer' => signer['issuer'] } : {})
  end

  # a key member that is present is passed (nil / empty as is, so it is checked and refused); an absent one is omitted
  def self.vopts(op)
    op ||= {}
    o = {}
    o['tree_root'] = op['treeRoot'] if op.key?('treeRoot')
    o['allow_high_s'] = op['allowHighS'] if op.key?('allowHighS')
    { 'verificationKey' => 'verification_key', 'statementKey' => 'statement_key' }.each do |js, rb|
      o[rb] = op[js].nil? || op[js] == {} ? op[js] : key(op[js], false) if op.key?(js)
    end
    o
  end

  def self.decode_cose(b)
    c = S.decode_cose_sign1(b)
    wire({ 'protectedBytes' => c['protectedBytes'], 'protectedMap' => to_cj(c['protectedMap']), 'unprotected' => to_cj(c['unprotected']),
           'payload' => c['payload'], 'signature' => c['signature'] })
  end

  def self.es256_sign_verify(k, payload, issuer)
    st = S.sign_statement(payload, 'ES256', key(k, true), issuer)
    c = S.decode_cose_sign1(st)
    pub = key({ 'alg' => 'ES256', 'x' => k['x'], 'y' => k['y'] }, false)
    wire({ 'check' => S.check_statement(st, pub), 'payload' => S.statement_payload(st),
           'lowS' => c['signature'].byteslice(32, 32).unpack1('H*').to_i(16) <= HALF_N, 'protectedBytes' => c['protectedBytes'] })
  end

  def self.es256_receipt(k, n, index, ed_priv, wrong_pub)
    ts = L::TransparencyService.new('ES256', key(k, true), { 'issuer' => 'ts' })
    sts = Array.new(n) { |i| ts.append_and_receipt({ 'i' => i }, 'EdDSA', key(ed_priv, true), 'iss')['statement'] }
    pub = key({ 'alg' => 'ES256', 'x' => k['x'], 'y' => k['y'] }, false)
    r = ts.get_receipt(index)
    st = sts[index]
    ed_pub = AtlasPca.b64d(AtlasPca::KeyPair.new(key(ed_priv, true)).public, 32)
    other = (index + 1) % n < sts.length ? sts[(index + 1) % n] : ("\x00".b * 3)
    {
      'key' => S.verify_receipt(r['receipt'], st, { 'verification_key' => pub }),
      'root' => S.verify_receipt(r['receipt'], st, { 'tree_root' => r['root'] }),
      'both' => S.verify_receipt(r['receipt'], st, { 'tree_root' => r['root'], 'verification_key' => pub, 'statement_key' => ed_pub }),
      'wrongKey' => S.verify_receipt(r['receipt'], st, { 'verification_key' => key(wrong_pub, false) }),
      'otherStatement' => S.verify_receipt(r['receipt'], other, { 'verification_key' => pub }),
      'none' => S.verify_receipt(r['receipt'], st)
    }
  end

  # the reference's store fault injection over the in-memory store
  class Faulty
    def initialize(fault)
      @inner = L::MemoryScittLogStore.new
      @f = fault
    end

    def size = @f['negSize'] ? -1 : @inner.size
    def get_entry(i) = @inner.get_entry(i)

    def get_node(level, i)
      return nil if @f['dropNode'] && @f['dropNode'] == [level, i]
      return ("\x00".b * 31) if @f['shortNode'] && @f['shortNode'] == [level, i]

      @inner.get_node(level, i)
    end

    def append(n, e, nodes) = @f['stale'] ? false : @inner.append(n, e, nodes)
  end

  def self.service(spec)
    k = key(spec['key'], true)
    alg = spec['key']['alg']
    extra = spec.key?('issuer') ? { 'issuer' => spec['issuer'] } : {}
    memory = spec['kind'] == 'memory'
    svc = if memory
            L::TransparencyService.new(alg, k, extra)
          else
            L::DurableTransparencyService.new(spec['storeFault'] ? Faulty.new(spec['storeFault']) : L::MemoryScittLogStore.new, alg, k, extra)
          end
    spec['ops'].map do |op|
      v = case op['op']
          when 'append'
            o = { 'content_type' => op['contentType'] }
            o['subject'] = op['subject'] if op.key?('subject')
            svc.append_and_receipt(op['payload'], 'EdDSA', key(spec['stmtKey'], true), 'https://issuer.example', o)
          when 'register' then svc.register(op['statement'])
          when 'receipt' then svc.get_receipt(op['i'])
          when 'consistency' then svc.consistency_proof(op['m'])
          when 'entry' then svc.get_entry(op['i'])
          when 'snapshot' then svc.snapshot
          when 'root' then svc.root
          when 'size' then svc.size
          else raise ArgumentError, 'op'
          end
      { 'ok' => wire(v) }
    rescue StandardError => e
      { 'err' => e.respond_to?(:code) && e.code.is_a?(String) ? e.code : true }
    end
  end

  def self.path = File.join(TMP, "f#{@@n += 1}.log")

  def self.file_store_bytes(ops)
    p = path
    s = L::FileScittLogStore.open(p)
    begin
      ops.each do |op|
        nodes = op['nodes'].map { |n| { 'level' => n[0], 'index' => n[1], 'hash' => Ref.b64d(n[2]) } }
        begin
          s.append(op['expected'], op['entry'], nodes)
        rescue StandardError # a refused / malformed append writes nothing
          nil
        end
      end
    ensure
      s.close
    end
    wire(File.binread(p))
  end

  def self.file_store_open(blob)
    p = path
    File.binwrite(p, blob)
    s = L::FileScittLogStore.open(p)
    begin
      size = s.size
      out = { 'size' => size, 'entries' => Array.new(size) { |i| s.get_entry(i) }, 'nodes0' => Array.new(size) { |i| s.get_node(0, i) } }
    ensure
      s.close
    end
    out['after'] = File.binread(p)
    wire(out)
  end

  def self.check_store(kind)
    return L.check_scitt_log_store(-> { L::MemoryScittLogStore.new }) if kind == 'memory'

    L.check_scitt_log_store(-> { L::FileScittLogStore.open(path) })
  end

  CONST_NAMES = %i[COSE_SIGN1_TAG HDR_ALG HDR_CONTENT_TYPE HDR_CWT_CLAIMS CWT_ISS CWT_SUB HDR_VDS HDR_VDS_PROOFS VDS_RFC9162_SHA256
                   PROOF_TYPE_INCLUSION DEFAULT_CONTENT_TYPE].freeze

  MAP = {
    'cborEncode' => ->(v) { wire(S.encode(from_cj(v))) },
    'cborDecode' => ->(b) { wire(to_cj(S.decode(b))) },
    'emptyRoot' => w(S.method(:empty_root)),
    'leafHash' => w(S.method(:leaf_hash)),
    'nodeHash' => w(S.method(:node_hash)),
    'treeHash' => w(S.method(:tree_hash)),
    'inclusionPath' => w(S.method(:inclusion_path)),
    'rootFromInclusionPath' => w(S.method(:root_from_inclusion_path)),
    'verifyInclusionPath' => S.method(:verify_inclusion_path),
    'consistencyPath' => w(S.method(:consistency_path)),
    'verifyConsistencyPath' => S.method(:verify_consistency_path),
    'siblingSides' => S.method(:sibling_sides),
    'encodeInclusionProof' => w(S.method(:encode_inclusion_proof)),
    'decodeInclusionProof' => S.method(:decode_inclusion_proof),
    'signStatement' => ->(payload, spec) { wire(sign_statement(payload, spec)) },
    'decodeCoseSign1' => ->(b) { decode_cose(b) },
    'checkStatement' => ->(st, pub, op = nil) { S.check_statement(st, key(pub, false), high(op)) },
    'verifyStatement' => ->(st, pub, op = nil) { S.verify_statement(st, key(pub, false), high(op)) },
    'statementPayload' => w(S.method(:statement_payload)),
    'statementLeaf' => S.method(:statement_leaf),
    'buildReceipt' => ->(root, proof, signer) { wire(build_receipt(root, proof, signer)) },
    'verifyReceipt' => ->(r, st, op = nil) { S.verify_receipt(r, st, vopts(op)) },
    'verifyConsistencyProof' => S.method(:verify_consistency_proof),
    'constants' => -> { CONST_NAMES.to_h { |c| [c.to_s, S.const_get(c)] } },
    'es256SignVerify' => ->(k, payload, issuer) { es256_sign_verify(k, payload, issuer) },
    'es256Receipt' => ->(*a) { es256_receipt(*a) },
    'service' => ->(spec) { service(spec) },
    'fileStoreBytes' => ->(ops) { file_store_bytes(ops) },
    'fileStoreOpen' => ->(blob) { file_store_open(blob) },
    'checkScittLogStore' => ->(kind) { check_store(kind) }
  }.freeze

  def test_corpus_is_the_full_oracle
    assert_equal [], BY_FN.keys - MAP.keys
    assert_equal [], MAP.keys - BY_FN.keys
  end

  MAP.each do |fn, call|
    define_method("test_matches_the_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  def test_file_store_reopens_what_it_wrote
    p = self.class.path
    s = L::FileScittLogStore.open(p)
    svc = L::DurableTransparencyService.new(s, 'EdDSA', "\x00".b * 32)
    5.times { |i| svc.append_and_receipt({ 'i' => i }, 'EdDSA', "\x01".b * 32, 'iss') }
    root = svc.root
    s.close
    again = L::DurableTransparencyService.new(L::FileScittLogStore.open(p), 'EdDSA', "\x00".b * 32)
    assert_equal 5, again.size
    assert_equal root, again.root
  end

  # A key that is present but nil / empty is checked (and fails), never skipped; only an omitted key means "no key".
  def test_verify_receipt_present_but_empty_key_is_refused
    seed = Digest::SHA256.digest('scitt-empty-key')
    ts = L::TransparencyService.new('EdDSA', seed, { 'issuer' => 'ts' })
    st = ts.append_and_receipt({ 'i' => 0 }, 'EdDSA', seed, 'iss')['statement']
    rc = ts.get_receipt(0)
    pub = AtlasPca.b64d(AtlasPca::KeyPair.new(seed).public, 32)
    assert_equal true, S.verify_receipt(rc['receipt'], st, { 'verification_key' => pub })
    assert_equal true, S.verify_receipt(rc['receipt'], st, { 'tree_root' => rc['root'] })
    [''.b, nil].each do |bad|
      assert_equal false, S.verify_receipt(rc['receipt'], st, { 'verification_key' => bad })
      assert_equal false, S.verify_receipt(rc['receipt'], st, { 'tree_root' => rc['root'], 'verification_key' => bad })
      assert_equal false, S.verify_receipt(rc['receipt'], st, { 'tree_root' => rc['root'], 'statement_key' => bad })
    end
  end

  def test_services_refuse_an_empty_signing_key
    [nil, ''.b].each do |bad|
      assert_raises(ArgumentError) { L::TransparencyService.new('EdDSA', bad) }
      assert_raises(ArgumentError) { L::DurableTransparencyService.new(L::MemoryScittLogStore.new, 'EdDSA', bad) }
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 8036, BY_FN.values.sum(&:length), 'scitt'
  end

end
