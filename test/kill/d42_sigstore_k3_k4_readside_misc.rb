# frozen_string_literal: true

# d42 (round 3): the mutants that survived c21 / c24 / c25 in sigstore_bundle.rb, k3.rb, k4.rb, readside.rb, read_vault.rb,
# runtime_claim.rb, refusal_help.rb and forbid_certificate.rb. Each test isolates the one operand / constant / encoding the
# earlier test did not decide. AtlasPca is dropped and re-evaluated for every mutant, so everything under it is resolved at CALL time.
# Helpers are borrowed from c21 (MutationKill::C21Sig), c24 (MutationKill::C24) and c25 (MutationKill::C25), which load first.
require 'openssl'

module MutationKill
  module D42
    module_function

    FILES = %w[sigstore_bundle.rb k3.rb k4.rb readside.rb read_vault.rb runtime_claim.rb refusal_help.rb forbid_certificate.rb].freeze

    def skip?
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !FILES.include?(f)
    end

    def skip_for?(*names)
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !names.include?(f)
    end

    # rows: [label, got, want]; strict equality including the class.
    def ck(rows)
      bad = rows.reject { |_l, got, want| got == want && got.class == want.class }
      return true if bad.empty?

      raise "d42 mismatch (#{bad.length}/#{rows.length}): #{bad.first(4).map { |l, g, w| "#{l}: got #{g.inspect[0, 200]} want #{w.inspect[0, 200]}" }.join(' | ')}"
    end

    def frozen_bin(const_owner, name, text)
      v = const_owner.const_get(name)
      [[name, v.bytes, text.bytes], [name, v.encoding, Encoding::BINARY], [name, v.frozen?, true]]
    end
  end

  # ================================================================================================================ constants
  t('d42 sigstore constants: RSA_ALG_ID, DIGEST_OIDS and MEDIA_TYPES are frozen') do
    next true if D42.skip_for?('sigstore_bundle.rb')

    s = AtlasPca::SigstoreBundle
    D42.ck([['RSA_ALG_ID', s::RSA_ALG_ID.frozen?, true], ['RSA_ALG_ID bytes', s::RSA_ALG_ID, ['300d06092a864886f70d0101010500'].pack('H*')],
            ['DIGEST_OIDS', s::DIGEST_OIDS.frozen?, true], ['MEDIA_TYPES', s::MEDIA_TYPES.frozen?, true]])
  end

  t('d42 domain constants of readside, read_vault and runtime_claim are the exact frozen BINARY strings') do
    next true if D42.skip_for?('readside.rb', 'read_vault.rb', 'runtime_claim.rb')

    a = AtlasPca
    D42.ck(D42.frozen_bin(a, :READ_GRANT_DOMAIN, "atlas-pca/read-grant/v1\x00") +
           D42.frozen_bin(a, :READ_RECEIPT_DOMAIN, "atlas-pca/read-receipt/v1\x00") +
           D42.frozen_bin(a, :AGGREGATE_DOMAIN, "atlas-pca/aggregate-grant/v1\x00") +
           D42.frozen_bin(a, :RUNTIME_CLAIM_DOMAIN, "atlas-pca/runtime-class-claim/v1\x00"))
  end

  t('d42 refusal_help: the table and each of its rows are frozen, the unknown entry is frozen') do
    next true if D42.skip_for?('refusal_help.rb')

    a = AtlasPca
    D42.ck([['table', a::REFUSAL_TABLE.frozen?, true], ['rows', a::REFUSAL_TABLE.all?(&:frozen?), true], ['unknown', a::REFUSAL_UNKNOWN.frozen?, true],
            ['unknown check', a::REFUSAL_UNKNOWN.check, 'unknown']])
  end

  # ================================================================================================================ sigstore
  t('d42 sigstore date_ms: a two-digit offset hour is read from its own two digits') do
    next true if D42.skip_for?('sigstore_bundle.rb')

    s = AtlasPca::SigstoreBundle
    # 2024-03-01T12:34:56Z is 1_709_296_496_000
    D42.ck([['+10:00', s.date_ms('2024-03-01T12:34:56+10:00'), 1_709_296_496_000 - 36_000_000],
            ['-11:00', s.date_ms('2024-03-01T12:34:56-11:00'), 1_709_296_496_000 + 39_600_000],
            ['+12:45', s.date_ms('2024-03-01T12:34:56+12:45'), 1_709_296_496_000 - ((12 * 60) + 45) * 60_000]])
  end

  t('d42 sigstore pinned_log: an Ed25519 base URL without a host is the signed-note refusal, not a NoMethodError') do
    next true if D42.skip_for?('sigstore_bundle.rb')

    c = MutationKill::C21Sig
    s = c.s
    ed = MutationKill::C21Sig::ED.public_to_der
    id = c.sha("\n", "\x01", ed.byteslice(-32, 32))
    note = [:fail, 'log id is not the signed-note key hash of its key']
    D42.ck([['no scheme', c.fail_msg { s.pinned_log(c.entry(ed, 'PKIX_ED25519', id, baseUrl: 'nohost'), true) }, note],
            ['relative path', c.fail_msg { s.pinned_log(c.entry(ed, 'PKIX_ED25519', id, baseUrl: 'x/y'), true) }, note]])
  end

  t('d42 sigstore generalized_time: a genTime that is not valid UTF-8 is read as bytes and is malformed, not an ArgumentError') do
    next true if D42.skip_for?('sigstore_bundle.rb')

    c = MutationKill::C21Sig
    s = c.s
    b = c.tl(0x18, "2024010100\xFF000Z".b).force_encoding(Encoding::UTF_8)
    D42.ck([['broken utf-8', c.fail_msg { s.generalized_time(b, s.tlv(b, 0)) }, [:fail, 'genTime malformed']]])
  end

  t('d42 sigstore verify_checkpoint: a 4-byte signature body is skipped before any verification (seam)') do
    next true if D42.skip_for?('sigstore_bundle.rb')

    c = MutationKill::C21Sig
    s = c.s
    key = MutationKill::C21Sig::EC256
    key_id = OpenSSL::Digest::SHA256.digest(key.public_to_der)
    log = s::PinnedLog.new(key_id, key, s::Validity.new(0, Float::INFINITY), nil)
    root = OpenSSL::Digest::SHA256.digest('root')
    body = "origin.example\n5\n#{c.b64(root)}\n"
    four = "#{body}\n— log.example #{c.b64(key_id.byteslice(0, 4))}\n"
    five = "#{body}\n— log.example #{c.b64(key_id.byteslice(0, 4) + 'x')}\n"
    got = MutationKill::Seam.with(s, { verify_sig: ->(*) { true } }) do
      [s.verify_checkpoint(four, log, 5, root), s.verify_checkpoint(five, log, 5, root)]
    end
    D42.ck([['4 bytes', got[0], 'no checkpoint signature by the pinned log key'], ['5 bytes reach the verifier', got[1], nil]])
  end

  # ================================================================================================================ k3
  t('d42 k3.rb requires only fresh_at (fresh ruby: it does not pull in atlas_pca.rb)') do
    next true if D42.skip_for?('k3.rb')
    next true if MutationKill::C24.mutating? && !MutationKill::C24.header_changed?('atlas_pca/k3.rb', 12)

    code = "require 'atlas_pca/k3'; puts $LOADED_FEATURES.grep(%r{/atlas_pca/fresh_at\\.rb\\z}).size; " \
           'puts $LOADED_FEATURES.grep(%r{/atlas_pca\.rb\z}).size'
    out, ok = MutationKill::C24.fresh('atlas_pca/k3.rb', code)
    ok && out == "1\n0\n"
  end

  t('d42 k3 verify_list_receipt: the object count must equal the receipt count even when the digest matches') do
    next true if D42.skip_for?('k3.rb')

    c = MutationKill::C24
    c.fast do
      sg = c.pub(:ls)
      # signed digest of two objects, signed count 3
      r = c.sr('count' => 3)
      c.ck([['count differs, digest matches', AtlasPca.verify_list_receipt(r, sg, %w[a b]), false],
            ['count equals, digest matches', AtlasPca.verify_list_receipt(c.sr, sg, %w[a b]), true]])
    end
  end

  t('d42 k3 verify_list_cursor: each shape operand alone refuses an otherwise validly signed cursor') do
    next true if D42.skip_for?('k3.rb')

    c = MutationKill::C24
    c.fast do
      sg = c.pub(:cur)
      mal = { 'ok' => false, 'reason' => 'malformed' }
      vc = ->(t) { AtlasPca.verify_list_cursor(t, sg) }
      tok = c.cur
      p64 = tok.split('.')[0]
      c.ck([['valid', vc.(tok), { 'ok' => true, 'skip' => 3 }],
            ['third part', vc.(c.cur({}, :cur, '.x')), mal], ['empty signature', vc.("#{p64}."), mal],
            ['v 2', vc.(c.cur('v' => 2)), mal], ['bind int', vc.(c.cur('bind' => 5)), mal], ['skip -1', vc.(c.cur('skip' => -1)), mal],
            ['inner int', vc.(c.cur('inner' => 5)), mal], ['payload array', vc.("#{AtlasPca.b64e('[1]'.b)}.#{tok.split('.')[1]}"), mal],
            ['payload string', vc.("#{AtlasPca.b64e('"v"'.b)}.#{tok.split('.')[1]}"), mal]])
    end
  end

  t('d42 k3 verify_amendment: a request that merely quacks like a Hash is bad_request, not processed') do
    next true if D42.skip_for?('k3.rb')

    c = MutationKill::C24
    c.fast do
      auth = { 'verbs' => ['a'], 'resources' => ['r'] }
      cur = { 'id' => 'g', 'rev' => 1, 'status' => 'active', 'principal' => c.pub(:p), 'agent' => c.pub(:h),
              'authority' => { 'verbs' => %w[a b], 'resources' => ['r'] } }
      sig = c.sign(c::D_AMEND, AtlasPca.amend_message(cur, 'narrow', auth), :h)
      req = { 'action' => 'narrow', 'authority' => auth, 'signed_by' => 'holder', 'sig' => sig }
      c.ck([['hash', AtlasPca.verify_amendment(cur, req, false), { 'ok' => true, 'widens' => false, 'next' => auth }],
            ['duck', AtlasPca.verify_amendment(cur, c::Duck.new(req), false), { 'ok' => false, 'code' => 'bad_request' }]])
    end
  end

  # ================================================================================================================ k4
  t('d42 k4 pricing_config_error: a config whose v is 1.0 (== 1 but not an Integer) is malformed') do
    next true if D42.skip_for?('k4.rb')

    c = MutationKill::C24
    cfg = c.cbody('v' => 1.0).merge('sig' => 'x')
    ok = c.cbody.merge('sig' => 'x')
    got = MutationKill::Seam.with(AtlasPca, { k4_sig: ->(*) { true } }) { [AtlasPca.pricing_config_error(cfg), AtlasPca.pricing_config_error(ok)] }
    c.ck([['float v', got[0], 'config_malformed'], ['integer v', got[1], nil]])
  end

  t('d42 k4 k4_answer_ok?: the answer principal must equal the pinned principal') do
    next true if D42.skip_for?('k4.rb')

    c = MutationKill::C24
    c.fast do
      body = { 'v' => 1, 'principal' => 'someone-else', 'nonce' => '12345678', 'action_digest' => 'd', 'answer' => 'approve' }
      other = body.merge('sig' => c.k4sign('pca.escalation_answer', body, :pr))
      own_body = body.merge('principal' => c.pub(:pr))
      own = own_body.merge('sig' => c.k4sign('pca.escalation_answer', own_body, :pr))
      c.ck([['signed by the pinned key but names another principal', AtlasPca.k4_answer_ok?(other, c.pub(:pr)), false],
            ['names the pinned principal', AtlasPca.k4_answer_ok?(own, c.pub(:pr)), true]])
    end
  end

  t('d42 k4 k4_sig: the verified message is the canonical digest as BINARY bytes (seam)') do
    next true if D42.skip_for?('k4.rb')

    c = MutationKill::C24
    seen = []
    sig = c.k4sign('k', { 'x' => 1 }, :pr)
    r = MutationKill::Seam.with(AtlasPca, { verify_b64u: ->(_p, m, _s) { seen << m; true } }) { AtlasPca.k4_sig(c.pub(:pr), 'k', { 'x' => 1, 'sig' => sig }) }
    want = AtlasPca.hash_canonical('kind' => 'k', 'body' => { 'x' => 1 })
    c.ck([['result', r, true], ['bytes', seen[0], want.b], ['encoding', seen[0].encoding, Encoding::BINARY]])
  end

  # ================================================================================================================ readside
  t('d42 readside k5_valid_read_receipt?: a negative seq with a set prev is invalid (seq operand alone)') do
    next true if D42.skip_for?('readside.rb')

    c = MutationKill::C25
    v = ->(r) { AtlasPca.k5_valid_read_receipt?(r) }
    D42.ck([['seq -1 with prev', v.(c.rc(seq: -1, prev: c::PRINCIPAL)), false], ['seq 1.5 with prev', v.(c.rc(seq: 1.5, prev: c::PRINCIPAL)), false],
            ['seq 2**53 with prev', v.(c.rc(seq: 2**53, prev: c::PRINCIPAL)), false], ['seq 1 with prev', v.(c.rc(seq: 1, prev: c::PRINCIPAL)), true]])
  end

  t('d42 readside read_chain_labels: shape, seq position and uniq are each decided on their own') do
    next true if D42.skip_for?('readside.rb')

    c = MutationKill::C25
    ap = AtlasPca
    chain = ->(rcs) { ap.read_chain_labels(rcs, c::RS, c::PRINCIPAL, 1500) }
    r0 = c.rc
    ref0 = ap.read_receipt_ref(r0)
    bad_shape = c.rc(seq: 1, prev: ref0, fields: { 'f2' => c.fld(class: 'Bad', kind: 'bucket') }, labels: ['Bad'])
    seq_two = c.rc(seq: 2, prev: ref0, fields: { 'f2' => c.fld(class: 'fin', kind: 'bucket') }, labels: ['fin'])
    ok_one = c.rc(seq: 1, prev: ref0, fields: { 'f2' => c.fld(class: 'fin', kind: 'bucket') }, labels: ['fin'])
    same_class = c.rc(fields: { 'f1' => c.fld, 'f2' => c.fld }, labels: ['pii'])
    c.with_verify(true) do
      D42.ck([['control', chain.([r0, ok_one]), { 'labels' => %w[fin pii] }],
              ['label not in the label alphabet', chain.([r0, bad_shape]), { 'code' => 'bad_receipt', 'at' => 1 }],
              ['seq 2 at index 1', chain.([r0, seq_two]), { 'code' => 'bad_receipt', 'at' => 1 }],
              ['two fields of one class, one label', chain.([same_class]), { 'labels' => ['pii'] }]])
    end
  end

  # ================================================================================================================ forbid_certificate
  t('d42 forbid_certificate: the kind and the winner kind are each decided on their own') do
    next true if D42.skip_for?('forbid_certificate.rb')

    c = MutationKill::C21Sig
    ok = ->(cert) { AtlasPca.forbid_certificate_consistent?(cert) }
    permit = c.row('p', 'permit')
    good = c.fc([permit], 'allow', { 'kind' => 'permit', 'id' => 'p' })
    D42.ck([['control', ok.(good), true], ['other certificate kind', ok.(good.merge('kind' => 'forbid-all')), false],
            ['winner kind forbid for a permit', ok.(c.fc([permit], 'allow', { 'kind' => 'forbid', 'id' => 'p' })), false]])
  end
end
