# frozen_string_literal: true

# c24: mutation-kill tests for lib/atlas_pca/k3.rb (policy bundles, decision log, list receipts and cursors, grant management) and
# lib/atlas_pca/k4.rb (risk-priced escalation, network-token binding, ERC-7715 granted permission). References: packages/pca-grants/src/
# {bundle,list-authorized,grant-resource}.ts, packages/pca-wallet/src/escalation-pricing.ts, packages/pca-erc7715/src/index.ts,
# packages/pca-payments/src/network-token.ts and the shared vectors k3-vectors.json / k4-vectors.json.
# AtlasPca is dropped and re-evaluated for every mutant, so it is resolved at CALL time everywhere. Signatures are made in-test with
# OpenSSL Ed25519 from fixed seeds over LITERAL domain strings; the bulk of the checks run with the strict verifier swapped for a plain
# OpenSSL verify (same verdict on honest signatures, ~100x cheaper), one test runs the real strict verifier.
require 'openssl'
require 'digest'
require 'timeout'
require 'tmpdir'
require 'fileutils'
require 'rbconfig'

module MutationKill
  module C24
    module_function

    def skip?(*files)
      f = ENV['MUT_FILE']
      !f.nil? && !f.empty? && !(files.empty? ? %w[k3.rb k4.rb] : files).include?(f)
    end

    def mutating? = (f = ENV['MUT_FILE']) && !f.empty?

    # rows: [label, got, want]; strict equality including the class (true vs truthy, nil vs false, 1 vs 1.0).
    def ck(rows)
      bad = rows.reject { |_l, got, want| got == want && got.class == want.class }
      return true if bad.empty?

      raise "c24 mismatch (#{bad.length}/#{rows.length}): #{bad.first(4).map { |l, g, w| "#{l}: got #{g.inspect[0, 200]} want #{w.inspect[0, 200]}" }.join(' | ')}"
    end

    def deep(x) = Marshal.load(Marshal.dump(x))

    # merge where the value :del removes the key
    def mrg(base, over)
      out = base.dup
      over.each { |k, v| v == :del ? out.delete(k) : out[k] = v }
      out
    end

    # Quacks like a Hash but is none (is_a?(Hash) is false).
    class Duck
      def initialize(obj)
        @obj = obj
      end

      def method_missing(name, *args, &blk)
        @obj.respond_to?(name) ? @obj.public_send(name, *args, &blk) : super
      end

      def respond_to_missing?(name, include_private = false)
        @obj.respond_to?(name, include_private) || super
      end
    end

    # ---- a fresh Ruby over the mutated text (an in-process require is already satisfied) -------------------------------------
    LIB = File.expand_path('../../lib', __dir__)

    def source(rel)
      path = File.join(LIB, rel)
      if defined?(::Oracle) && (tgt = ::Oracle.instance_variable_get(:@target)) && File.expand_path(tgt) == path
        ::Oracle.instance_variable_get(:@text)
      else
        File.read(path)
      end
    end

    def header_changed?(rel, nlines)
      source(rel).lines.first(nlines) != File.read(File.join(LIB, rel)).lines.first(nlines)
    end

    def fresh(rel, code)
      Dir.mktmpdir('c24fresh') do |d|
        FileUtils.cp_r(LIB, d)
        File.write(File.join(d, 'lib', rel), source(rel))
        gems = Gem.loaded_specs.values.flat_map(&:full_require_paths).flat_map { |g| ['-I', g] }
        out = IO.popen([RbConfig.ruby, '--disable-gems', '-I', File.join(d, 'lib'), *gems, '-e', code], 'r', err: File::NULL, &:read)
        [out, $?.success?]
      end
    end

    # ---- keys and signatures --------------------------------------------------------------------------------------------------
    D_BUNDLE = "atlas-pca/policy-bundle/v1\x00"
    D_HEAD = "atlas-pca/decision-log-head/v1\x00"
    D_LREC = "atlas-pca/list-receipt/v1\x00"
    D_CUR = "atlas-pca/list-cursor/v1\x00"
    D_AMEND = "atlas-pca/grant-amend/v1\x00"
    D_REVOKE = "atlas-pca/grant-revoke/v1\x00"
    D_NEED = "atlas-pca/need-approve/v1\x00"

    KEYS = {}

    def key(label) = (KEYS[label] ||= OpenSSL::PKey.new_raw_private_key('ED25519', Digest::SHA256.digest("atlas-c24/#{label}")))
    def pub(label) = AtlasPca.b64e(key(label).raw_public_key)
    def sign(domain, body, label) = AtlasPca.b64e(key(label).sign(nil, domain.b + AtlasPca.canon_bytes(body)))
    def k4sign(kind, body, label) = AtlasPca.b64e(key(label).sign(nil, AtlasPca.hash_canonical('kind' => kind, 'body' => body).b))

    # The strict verifier replaced by a plain OpenSSL verify (identical verdict for honest keys and signatures).
    def fv(pub, msg, sig)
      pk = pub.is_a?(String) ? AtlasPca.b64d(pub, 32) : nil
      sg = sig.is_a?(String) ? AtlasPca.b64d(sig, 64) : nil
      return false if pk.nil? || sg.nil?

      OpenSSL::PKey.new_raw_public_key('ED25519', pk).verify(nil, sg, msg)
    rescue StandardError
      false
    end

    def fast
      Seam.with(AtlasPca, { verify_b64u: ->(p, m, s) { C24.fv(p, m, s) } }) { yield }
    end

    # ---- K3 builders ----------------------------------------------------------------------------------------------------------
    def bbody(over = {})
      mrg({ 'v' => 1, 'kind' => 'pca-policy-bundle', 'revision' => 1, 'issued_at' => 100, 'grants' => ['g1'], 'template_digests' => ['t1'],
            'min_verifier_version' => '1.2.0' }, over)
    end

    def sb(body, labels) = body.merge('sigs' => labels.map { |l| { 'signer' => pub(l), 'sig' => sign(D_BUNDLE, body, l) } })
    def ref(body) = AtlasPca.hash_canonical('d' => 'atlas-pca/policy-bundle-ref/v1', 'b' => body)

    def hbody(over = {}) = mrg({ 'v' => 1, 'size' => 2, 'root' => 'rt', 'last_commit' => 'lc', 'issued_at' => 5, 'signer' => pub(:log) }, over)

    def sh(over = {}, label = :log)
      b = hbody(over)
      b.merge('sig' => sign(D_HEAD, b, label))
    end

    def rc(rec) = AtlasPca.hash_canonical('d' => 'atlas-pca/decision-record/v1', 'r' => rec)
    def od(objs) = AtlasPca.hash_canonical('d' => 'atlas-pca/list-objects/v1', 'o' => objs)

    def rbody(over = {})
      mrg({ 'v' => 1, 'subject' => 's', 'resource_type' => 'doc', 'count' => 2, 'issued_at' => 7, 'signer' => pub(:ls),
            'objects_digest' => od(%w[a b]), 'policy_digest' => 'p' }, over)
    end

    def sr(over = {}, label = :ls)
      b = rbody(over)
      b.merge('sig' => sign(D_LREC, b, label))
    end

    # a cursor token: base64url(canonical JSON) "." signature (signed over the same body)
    def cur(over = {}, label = :cur, suffix = '')
      b = mrg({ 'v' => 1, 'bind' => 'B', 'skip' => 3, 'signer' => pub(:cur) }, over)
      "#{AtlasPca.b64e(AtlasPca.canonicalize(b).b)}.#{sign(D_CUR, b, label)}#{suffix}"
    end

    def au(verbs, res, limits = nil, exp = nil)
      h = { 'verbs' => verbs, 'resources' => res }
      h['limits'] = limits unless limits.nil?
      h['expires_at'] = exp unless exp.nil?
      h
    end

    def adig(a)
      AtlasPca.hash_canonical('d' => 'atlas-pca/authority/v1',
                              'a' => a.merge('verbs' => a['verbs'].sort_by { |x| x.encode('UTF-16BE').b },
                                             'resources' => a['resources'].sort_by { |x| x.encode('UTF-16BE').b }))
    end

    # ---- K4 builders ----------------------------------------------------------------------------------------------------------
    def cbody(over = {})
      mrg({ 'v' => 1, 'principal' => pub(:pr), 'currency' => 'USD', 'interruptionCost' => 100, 'maxInterruptionCost' => 500,
            'hardCeilingLoss' => 100_000, 'tightenStepPpm' => 500_000, 'epoch' => 1 }, over)
    end

    def sc(over = {}, label = :pr)
      b = cbody(over)
      # a value the canonical form refuses (1.5, 2**53) cannot be signed; the amount / step checks refuse it before any signature is read
      sig = begin
        k4sign('pca.escalation_pricing', b, label)
      rescue AtlasPca::Malformed
        'AAAA'
      end
      b.merge('sig' => sig)
    end

    def ans(over = {}, label = :pr)
      b = mrg({ 'v' => 1, 'principal' => pub(:pr), 'nonce' => 'nonce-001', 'action_digest' => 'd1', 'answer' => 'deny' }, over)
      b.merge('sig' => k4sign('pca.escalation_answer', b, label))
    end

    # ---- shared vectors, parsed once at load (unmutated library) ----------------------------------------------------------------
    CONF = File.expand_path('../../conformance', __dir__)

    def load_vec(name)
      AtlasPca.parse_json(File.read(File.join(CONF, name), encoding: 'UTF-8'), loose: true)
    rescue StandardError
      nil
    end
  end

  C24_VEC3 = (C24.load_vec('k3-vectors.json') unless C24.skip?('k3.rb'))
  C24_VEC4 = (C24.load_vec('k4-vectors.json') unless C24.skip?('k4.rb'))

  # ================================================================================================================ K3: loading
  t('c24 k3.rb loads on its own: it requires fresh_at (k3_int?, k3_str?, k3_verify_body) and defines its constants (fresh ruby over the mutated text)') do
    next true if C24.skip?('k3.rb')
    next true if C24.mutating? && !C24.header_changed?('atlas_pca/k3.rb', 12)

    code = "require 'atlas_pca/k3'; puts [AtlasPca.respond_to?(:k3_int?), AtlasPca.respond_to?(:k3_str?), AtlasPca.respond_to?(:k3_verify_body), " \
           'AtlasPca.respond_to?(:compare_authority)].inspect'
    out, ok = C24.fresh('atlas_pca/k3.rb', code)
    ok && out == "[true, true, true, true]\n"
  end

  t('c24 k3 constants: domain prefixes are the exact frozen BINARY strings, the references are exact, the list cap is 4096') do
    next true if C24.skip?('k3.rb')

    a = AtlasPca
    bin = { BUNDLE_DOMAIN: "atlas-pca/policy-bundle/v1\x00", LOG_HEAD_DOMAIN: "atlas-pca/decision-log-head/v1\x00",
            LIST_RECEIPT_DOMAIN: "atlas-pca/list-receipt/v1\x00", LIST_CURSOR_DOMAIN: "atlas-pca/list-cursor/v1\x00",
            GRANT_AMEND_DOMAIN: "atlas-pca/grant-amend/v1\x00", GRANT_REVOKE_DOMAIN: "atlas-pca/grant-revoke/v1\x00",
            NEED_APPROVE_DOMAIN: "atlas-pca/need-approve/v1\x00" }
    rows = bin.map { |n, s| v = a.const_get(n); [n, [v.bytes, v.encoding, v.frozen?], [s.bytes, Encoding::BINARY, true]] }
    rows << [:bundle_ref, a::BUNDLE_REF_DOMAIN, 'atlas-pca/policy-bundle-ref/v1']
    rows << [:record, a::RECORD_DOMAIN, 'atlas-pca/decision-record/v1']
    rows << [:max_list, a::BUNDLE_MAX_LIST, 4096]
    C24.ck(rows)
  end

  # ================================================================================================================ K3: small helpers
  t('c24 k3 k3_obj? / k3_without / compare_version / bundle_digest') do
    next true if C24.skip?('k3.rb')

    a = AtlasPca
    cv = ->(x, y) { a.compare_version(x, y) }
    d = { 'v' => 1, 'kind' => 'pca-policy-bundle', 'x' => [1, { 'y' => 2 }] }
    rows = [
      ['obj {}', a.k3_obj?({}), true], ['obj []', a.k3_obj?([]), false], ['obj str', a.k3_obj?('x'), false], ['obj nil', a.k3_obj?(nil), false],
      ['without', a.k3_without({ 'a' => 1, 'b' => 2, 'c' => 3 }, 'a', 'c'), { 'b' => 2 }],
      ['without none', a.k3_without({ 'a' => 1 }), { 'a' => 1 }],
      ['5 vs "5"', cv.(5, '5'), 0], ['"5" vs 5', cv.('5', 5), 0], ['nil vs 0', cv.(nil, '0'), 0], ['2 vs "10"', cv.('2', '10'), -1],
      ['1 vs 1.1', cv.('1', '1.1'), -1], ['1.1 vs 1', cv.('1.1', '1'), 1], ['1.0 vs 1', cv.('1.0', '1'), 0], ['1 vs 1.0', cv.('1', '1.0'), 0],
      ['1.2.3 vs 1.2.4', cv.('1.2.3', '1.2.4'), -1], ['1.10 vs 1.9', cv.('1.10', '1.9'), 1], ['1. vs 1', cv.('1.', '1'), 0],
      ['digest', a.bundle_digest(d), AtlasPca.hash_canonical('d' => 'atlas-pca/policy-bundle-ref/v1', 'b' => d)],
      ['digest ignores sigs', a.bundle_digest(d.merge('sigs' => [1])), AtlasPca.hash_canonical('d' => 'atlas-pca/policy-bundle-ref/v1', 'b' => d)],
      ['digest of nil', a.bundle_digest(nil), nil], ['digest of object', a.bundle_digest(Object.new), nil],
      ['record_commit', a.record_commit({ 'seq' => 0 }), AtlasPca.hash_canonical('d' => 'atlas-pca/decision-record/v1', 'r' => { 'seq' => 0 })],
      ['record_commit of object', a.record_commit(Object.new), nil],
      ['objects_digest', a.objects_digest(%w[a b]), C24.od(%w[a b])], ['objects_digest of object', a.objects_digest(Object.new), nil]
    ]
    C24.ck(rows)
  end

  # ================================================================================================================ K3: bundle shape
  t('c24 k3 bundle_shape_error: every rule refuses with its exact reason; list, string and version boundaries on both sides') do
    next true if C24.skip?('k3.rb')

    np = 'not a policy bundle'
    br = 'bad revision or time'
    pv = 'prev must be absent at revision 1 and present after'
    bm = 'bad min_verifier_version'
    long = ->(n) { 'x' * n }
    table = [
      ['valid', {}, nil], ['v 2', { 'v' => 2 }, np], ['v str', { 'v' => '1' }, np], ['kind', { 'kind' => 'x' }, np], ['no kind', { 'kind' => :del }, np],
      ['rev 0', { 'revision' => 0, 'prev' => 'p' }, br], ['rev 1.5', { 'revision' => 1.5, 'prev' => 'p' }, br],
      ['rev 2.0', { 'revision' => 2.0, 'prev' => 'p' }, br], ['rev str', { 'revision' => '2', 'prev' => 'p' }, br],
      ['rev nil', { 'revision' => nil }, br], ['rev -1', { 'revision' => -1, 'prev' => 'p' }, br], ['rev gone', { 'revision' => :del }, br],
      ['issued -1', { 'issued_at' => -1 }, br], ['issued 1.5', { 'issued_at' => 1.5 }, br], ['issued str', { 'issued_at' => '1' }, br],
      ['issued nil', { 'issued_at' => nil }, br], ['issued 2^53', { 'issued_at' => 2**53 }, br], ['issued 2^53-1', { 'issued_at' => (2**53) - 1 }, nil],
      ['issued 0', { 'issued_at' => 0 }, nil],
      ['rev 1 with prev', { 'prev' => 'p' }, pv], ['rev 1 with prev nil', { 'prev' => nil }, pv], ['rev 2 no prev', { 'revision' => 2 }, pv],
      ['rev 2 prev empty', { 'revision' => 2, 'prev' => '' }, pv], ['rev 2 prev int', { 'revision' => 2, 'prev' => 5 }, pv],
      ['rev 2 prev 129', { 'revision' => 2, 'prev' => long.(129) }, pv], ['rev 2 prev 128', { 'revision' => 2, 'prev' => long.(128) }, nil],
      ['rev 2 prev ok', { 'revision' => 2, 'prev' => 'p' }, nil]
    ]
    %w[grants template_digests].each do |k|
      bad = "bad #{k}"
      table.push(["#{k} empty list", { k => [] }, nil], ["#{k} 4096", { k => Array.new(4096, 'g') }, nil], ["#{k} 4097", { k => Array.new(4097, 'g') }, bad],
                 ["#{k} 128 chars", { k => [long.(128)] }, nil], ["#{k} 129 chars", { k => [long.(129)] }, bad], ["#{k} empty str", { k => [''] }, bad],
                 ["#{k} int", { k => [5] }, bad], ["#{k} nil elt", { k => [nil] }, bad], ["#{k} hash", { k => {} }, bad],
                 ["#{k} str", { k => 'abc' }, bad], ["#{k} nil", { k => nil }, bad], ["#{k} int val", { k => 5 }, bad], ["#{k} gone", { k => :del }, bad],
                 ["#{k} bad item in long list", { k => Array.new(4097, 5) }, bad])
    end
    %w[schema_digest constitution_digest flow_rules_digest].each do |k|
      bad = "bad #{k}"
      table.push(["#{k} ok", { k => 'd' }, nil], ["#{k} 128", { k => long.(128) }, nil], ["#{k} 129", { k => long.(129) }, bad], ["#{k} empty", { k => '' }, bad],
                 ["#{k} int", { k => 5 }, bad], ["#{k} nil", { k => nil }, bad], ["#{k} list", { k => ['d'] }, bad])
    end
    table.push(['mv gone', { 'min_verifier_version' => :del }, bm], ['mv int', { 'min_verifier_version' => 5 }, bm], ['mv nil', { 'min_verifier_version' => nil }, bm],
               ['mv list', { 'min_verifier_version' => ['1'] }, bm], ['mv empty', { 'min_verifier_version' => '' }, bm],
               ['mv trailing dot', { 'min_verifier_version' => '1.' }, bm], ['mv 5 parts', { 'min_verifier_version' => '1.2.3.4.5' }, bm],
               ['mv 7 digits', { 'min_verifier_version' => '1234567' }, bm], ['mv v prefix', { 'min_verifier_version' => 'v1' }, bm],
               ['mv leading space', { 'min_verifier_version' => ' 1' }, bm], ['mv newline', { 'min_verifier_version' => "1.0\n" }, bm],
               ['mv 0', { 'min_verifier_version' => '0' }, nil], ['mv 4 parts', { 'min_verifier_version' => '1.2.3.4' }, nil],
               ['mv 6 digits', { 'min_verifier_version' => '999999.999999.999999.999999' }, nil])
    sh16 = (1..16).map { |i| "s#{i}" }
    bs = 'bad shadow'
    table.push(['shadow one', { 'shadow' => ['a'] }, nil], ['shadow 16', { 'shadow' => sh16 }, nil], ['shadow 17', { 'shadow' => sh16 + ['s17'] }, bs],
               ['shadow empty', { 'shadow' => [] }, bs], ['shadow dup', { 'shadow' => %w[a a] }, bs], ['shadow nil', { 'shadow' => nil }, bs],
               ['shadow str', { 'shadow' => 'abc' }, bs], ['shadow int', { 'shadow' => 5 }, bs], ['shadow hash', { 'shadow' => {} }, bs],
               ['shadow empty elt', { 'shadow' => [''] }, bs], ['shadow int elt', { 'shadow' => [5] }, bs], ['shadow 128', { 'shadow' => [long.(128)] }, nil],
               ['shadow 129', { 'shadow' => [long.(129)] }, bs], ['shadow 17 dups', { 'shadow' => Array.new(17, 'a') }, bs])
    rows = table.map { |label, over, want| [label, AtlasPca.bundle_shape_error(C24.bbody(over)), want] }
    [nil, 5, 'x', [], [1], 'pca-policy-bundle'].each { |x| rows << ["non-object #{x.inspect}", AtlasPca.bundle_shape_error(x), np] }
    C24.ck(rows)
  end

  # ================================================================================================================ K3: verify_bundle
  t('c24 k3 verify_bundle: threshold, pinned signers, version gate, rollback and chain, exact verdicts (plain verify)') do
    next true if C24.skip?('k3.rb')

    C24.fast do
      c = C24
      vb = ->(bun, opts) { AtlasPca.verify_bundle(bun, opts) }
      body = c.bbody
      b = c.sb(body, %i[s1 s2])
      d1 = c.ref(body)
      pinned = [c.pub(:s1), c.pub(:s2), c.pub(:s3)]
      o = ->(over = {}) { c.mrg({ 'signers' => pinned, 'threshold' => 2, 'verifierVersion' => '1.2.0' }, over) }
      mal = ->(r) { { 'ok' => false, 'code' => 'malformed', 'reason' => r } }
      bad = ->(code, r) { { 'ok' => false, 'code' => code, 'reason' => r } }
      below = ->(n, need) { bad.('below_threshold', "#{n} valid pinned signature(s), need #{need}") }
      bs = 'bad sigs or threshold'
      s1 = b['sigs'][0]
      s2 = b['sigs'][1]
      body2 = c.bbody('revision' => 2, 'prev' => d1)
      b2 = c.sb(body2, %i[s1 s2])
      d2 = c.ref(body2)
      body3 = c.bbody('revision' => 3, 'prev' => 'unrelated')
      b3 = c.sb(body3, %i[s1 s2])
      okv = ->(bun, bod, signers) { { 'ok' => true, 'revision' => bod['revision'], 'digest' => c.ref(bod), 'signers' => signers.map { |l| c.pub(l) } } }
      rows = [
        ['ok', vb.(b, o.()), okv.(b, body, %i[s1 s2])],
        ['threshold 1 is enough with two good', vb.(b, o.('threshold' => 1)), okv.(b, body, %i[s1 s2])],
        ['threshold 3 not met', vb.(b, o.('threshold' => 3)), below.(2, 3)],
        ['shape error first', vb.(b.merge('v' => 2), o.()), mal.('not a policy bundle')],
        ['unpinned signers', vb.(b, o.('signers' => [c.pub(:s3)])), below.(0, 2)],
        ['signers nil', vb.(b, o.('signers' => nil)), below.(0, 2)],
        ['signers a string holding the keys', vb.(b, o.('signers' => c.pub(:s1) + c.pub(:s2), 'threshold' => 1)), below.(0, 1)],
        ['same signer twice counts once', vb.(b.merge('sigs' => [s1, s1]), o.()), below.(1, 2)],
        ['a signature on another signer', vb.(b.merge('sigs' => [{ 'signer' => c.pub(:s1), 'sig' => s2['sig'] }, s2]), o.()), below.(1, 2)],
        ['non-object sig entries skipped', vb.(b.merge('sigs' => [5, [], 'x', nil] + b['sigs']), o.()), okv.(b, body, %i[s1 s2])],
        ['sig entry without signer', vb.(b.merge('sigs' => [{ 'sig' => s1['sig'] }] + b['sigs']), o.()), okv.(b, body, %i[s1 s2])],
        ['sigs nil', vb.(b.merge('sigs' => nil), o.('threshold' => 1)), mal.(bs)], ['sigs hash', vb.(b.merge('sigs' => {}), o.('threshold' => 1)), mal.(bs)],
        ['sigs str', vb.(b.merge('sigs' => 'x'), o.('threshold' => 1)), mal.(bs)], ['sigs gone', vb.(b.reject { |k, _| k == 'sigs' }, o.('threshold' => 1)), mal.(bs)],
        ['64 sigs', vb.(b.merge('sigs' => Array.new(64, 1)), o.('threshold' => 1)), below.(0, 1)],
        ['65 sigs', vb.(b.merge('sigs' => Array.new(65, 1)), o.('threshold' => 1)), mal.(bs)],
        ['threshold 0', vb.(b, o.('threshold' => 0)), mal.(bs)], ['threshold -1', vb.(b, o.('threshold' => -1)), mal.(bs)],
        ['threshold 1.5', vb.(b, o.('threshold' => 1.5)), mal.(bs)], ['threshold str', vb.(b, o.('threshold' => '2')), mal.(bs)],
        ['threshold nil', vb.(b, o.('threshold' => nil)), mal.(bs)], ['threshold 2^53', vb.(b, o.('threshold' => 2**53)), mal.(bs)],
        ['threshold 1.0', vb.(b, o.('threshold' => 1.0)), mal.(bs)]
      ]
      too_old = bad.('verifier_too_old', 'needs verifier >= 1.2.0')
      [5, nil, '', 'abc', ['1.2.0'], '1.1.9', '0.9', '1.1.99999', "1.2.0\n", ' 1.2.0'].each { |v| rows << ["verifier #{v.inspect}", vb.(b, o.('verifierVersion' => v)), too_old] }
      ['1.2.0', '1.2', '1.10.0', '2', '1.2.0.1'].each { |v| rows << ["verifier #{v}", vb.(b, o.('verifierVersion' => v)), okv.(b, body, %i[s1 s2])] }
      rows.push(['verifier key gone', vb.(b, o.('verifierVersion' => :del)), too_old],
                ['chain ok', vb.(b2, o.('last' => { 'revision' => 1, 'digest' => d1 })), okv.(b2, body2, %i[s1 s2])],
                ['rollback', vb.(b, o.('last' => { 'revision' => 2, 'digest' => d2 })), bad.('rollback', 'revision 1 < accepted 2')],
                ['same revision same digest', vb.(b, o.('last' => { 'revision' => 1, 'digest' => d1 })), okv.(b, body, %i[s1 s2])],
                ['same revision other digest', vb.(b, o.('last' => { 'revision' => 1, 'digest' => 'other' })), bad.('broken_chain', 'same revision, different content')],
                ['next revision wrong prev', vb.(b2, o.('last' => { 'revision' => 1, 'digest' => 'other' })), bad.('broken_chain', 'prev does not chain to the accepted revision')],
                ['a later revision is not chain-checked', vb.(b3, o.('last' => { 'revision' => 1, 'digest' => d1 })), okv.(b3, body3, %i[s1 s2])],
                ['last a string is ignored', vb.(b, o.('last' => 'x')), okv.(b, body, %i[s1 s2])],
                ['last nil is ignored', vb.(b, o.('last' => nil)), okv.(b, body, %i[s1 s2])],
                ['options nil', vb.(b, nil), mal.('malformed bundle')])
      c.ck(rows)
    end
  end

  t('c24 k3 verify_bundle: a non-string signer is never offered to the signature check (spy)') do
    next true if C24.skip?('k3.rb')

    c = C24
    b = c.sb(c.bbody, %i[s1])
    calls = []
    r = Seam.with(AtlasPca, { k3_verify_body: ->(*a) { calls << a; false } }) do
      AtlasPca.verify_bundle(b.merge('sigs' => [{ 'signer' => 5, 'sig' => 'x' }, { 'signer' => nil, 'sig' => 'x' }, { 'signer' => ['k'], 'sig' => 'x' }]),
                             { 'signers' => [5, nil, ['k']], 'threshold' => 1, 'verifierVersion' => '9' })
    end
    c.ck([['no verify call', calls, []], ['verdict', r, { 'ok' => false, 'code' => 'below_threshold', 'reason' => '0 valid pinned signature(s), need 1' }]])
  end

  t('c24 k3 verify_bundle with the real strict verifier: valid, tampered, wrong key') do
    next true if C24.skip?('k3.rb')

    c = C24
    body = c.bbody
    b = c.sb(body, %i[s1 s2])
    o = { 'signers' => [c.pub(:s1), c.pub(:s2)], 'threshold' => 2, 'verifierVersion' => '1.2.0' }
    c.ck([['real ok', AtlasPca.verify_bundle(b, o), { 'ok' => true, 'revision' => 1, 'digest' => c.ref(body), 'signers' => [c.pub(:s1), c.pub(:s2)] }],
          ['real tampered', AtlasPca.verify_bundle(b.merge('grants' => ['g2']), o),
           { 'ok' => false, 'code' => 'below_threshold', 'reason' => '0 valid pinned signature(s), need 2' }]])
  end

  # ================================================================================================================ K3: decision log
  t('c24 k3 verify_log_head: every field of the head is required, signed bytes, signer pinned (plain verify)') do
    next true if C24.skip?('k3.rb')

    C24.fast do
      c = C24
      sg = c.pub(:log)
      vh = ->(h, s = sg) { AtlasPca.verify_log_head(h, s) }
      rows = [['valid', vh.(c.sh), true], ['empty root and last_commit', vh.(c.sh('root' => '', 'last_commit' => '')), true],
              ['size 0', vh.(c.sh('size' => 0)), true], ['other signer arg', vh.(c.sh, c.pub(:other)), false],
              ['tampered size', vh.(c.sh.merge('size' => 3)), false], ['signed by another key', vh.(c.sh({}, :other)), false],
              ['no sig', vh.(c.sh.reject { |k, _| k == 'sig' }), false], ['sig int', vh.(c.sh.merge('sig' => 5)), false],
              ['duck of a valid head', vh.(C24::Duck.new(c.sh)), false]]
      [nil, 5, 'x', []].each { |x| rows << ["non-object #{x.inspect}", vh.(x), false] }
      [{ 'v' => 2 }, { 'v' => '1' }, { 'signer' => c.pub(:other) }, { 'size' => -1 }, { 'size' => 1.5 }, { 'size' => '2' }, { 'issued_at' => -1 },
       { 'issued_at' => nil }, { 'root' => 5 }, { 'root' => nil }, { 'last_commit' => 5 }, { 'last_commit' => nil }, { 'size' => :del }, { 'root' => :del }].each do |over|
        rows << ["signed but #{over.inspect}", vh.(c.sh(over)), false]
      end
      raising = Seam.with(AtlasPca, { k3_verify_body: ->(*_a) { raise 'boom' } }) { vh.(c.sh) }
      rows << ['a fault is false', raising, false]
      c.ck(rows)
    end
  end

  t('c24 k3 verify_record_inclusion: record in the signed log, c nil, fault') do
    next true if C24.skip?('k3.rb')

    C24.fast do
      c = C24
      a = AtlasPca
      r0 = { 'v' => 1, 'seq' => 0, 'prev' => '', 'x' => 'a' }
      c0 = c.rc(r0)
      r1 = { 'v' => 1, 'seq' => 1, 'prev' => c0, 'x' => 'b' }
      c1 = c.rc(r1)
      head = c.sh('size' => 2, 'root' => a.merkle_root([c0, c1]), 'last_commit' => c1)
      p0 = { 'index' => 0, 'size' => 2, 'path' => [{ 'side' => 'R', 'hash' => a.b64e(a.leaf_hash(c1)) }] }
      p1 = { 'index' => 1, 'size' => 2, 'path' => [{ 'side' => 'L', 'hash' => a.b64e(a.leaf_hash(c0)) }] }
      sg = c.pub(:log)
      root_nil = a.merkle_root([nil])
      head_nil = c.sh('size' => 1, 'root' => root_nil, 'last_commit' => 'x')
      p_nil = { 'index' => 0, 'size' => 1, 'path' => [] }
      boom = Seam.with(a, { verify_log_head: ->(*_x) { true }, record_commit: ->(*_x) { raise 'boom' } }) { a.verify_record_inclusion(r0, p0, head, sg) }
      c.ck([['record 0', a.verify_record_inclusion(r0, p0, head, sg), true], ['record 1', a.verify_record_inclusion(r1, p1, head, sg), true],
            ['edited record', a.verify_record_inclusion(r0.merge('x' => 'z'), p0, head, sg), false],
            ['proof of another record', a.verify_record_inclusion(r0, p1, head, sg), false],
            ['head by another signer', a.verify_record_inclusion(r0, p0, c.sh({ 'size' => 2, 'root' => a.merkle_root([c0, c1]) }, :other), sg), false],
            ['unsigned head', a.verify_record_inclusion(r0, p0, { 'v' => 1 }, sg), false],
            ['a record with no commit is never included', a.verify_record_inclusion(Object.new, p_nil, head_nil, sg), false],
            ['a fault is false', boom, false]])
    end
  end

  t('c24 k3 verify_batch: contiguity, chain, head size and end, malformed (plain verify)') do
    next true if C24.skip?('k3.rb')

    C24.fast do
      c = C24
      sg = c.pub(:log)
      r0 = { 'v' => 1, 'seq' => 0, 'prev' => '', 'x' => 'a' }
      c0 = c.rc(r0)
      r1 = { 'v' => 1, 'seq' => 1, 'prev' => c0, 'x' => 'b' }
      c1 = c.rc(r1)
      r2 = { 'v' => 1, 'seq' => 2, 'prev' => c1, 'x' => 'c' }
      c2 = c.rc(r2)
      hd = ->(size, last, l = :log) { c.sh({ 'size' => size, 'last_commit' => last }, l) }
      st0 = { 'next' => 0, 'lastCommit' => '' }
      vbt = ->(bat, st) { AtlasPca.verify_batch(bat, st, sg) }
      fail_ = ->(r) { { 'ok' => false, 'reason' => r } }
      mal = fail_.('malformed batch')
      good = { 'from' => 0, 'records' => [r0, r1], 'head' => hd.(2, c1) }
      rows = [
        ['two records', vbt.(good, st0), { 'ok' => true, 'next' => 2, 'lastCommit' => c1 }],
        ['shorter than the head: end not compared', vbt.({ 'from' => 0, 'records' => [r0, r1], 'head' => hd.(3, 'zzz') }, st0), { 'ok' => true, 'next' => 2, 'lastCommit' => c1 }],
        ['longer than the head', vbt.({ 'from' => 0, 'records' => [r0, r1, r2], 'head' => hd.(2, c1) }, st0), fail_.('batch is longer than the signed head')],
        ['end differs', vbt.({ 'from' => 0, 'records' => [r0, r1], 'head' => hd.(2, 'zzz') }, st0), fail_.('batch end does not match the signed head')],
        ['wrong seq with the right prev', vbt.({ 'from' => 0, 'records' => [{ 'seq' => 1, 'prev' => '' }], 'head' => hd.(5, 'x') }, st0), fail_.('chain broken at seq 1')],
        ['wrong prev with the right seq', vbt.({ 'from' => 0, 'records' => [{ 'seq' => 0, 'prev' => 'bad' }], 'head' => hd.(5, 'x') }, st0), fail_.('chain broken at seq 0')],
        ['gap', vbt.({ 'from' => 1, 'records' => [r1], 'head' => hd.(2, c1) }, st0), fail_.('gap or replay: batch starts at 1, expected 0')],
        ['head by another signer', vbt.({ 'from' => 0, 'records' => [r0], 'head' => hd.(1, c0, :other) }, st0), fail_.('head not signed by the pinned log signer')],
        ['continues from the receiver state', vbt.({ 'from' => 1, 'records' => [r1, r2], 'head' => hd.(3, c2) }, { 'next' => 1, 'lastCommit' => c0 }),
         { 'ok' => true, 'next' => 3, 'lastCommit' => c2 }],
        ['empty batch at the head', vbt.({ 'from' => 2, 'records' => [], 'head' => hd.(2, c1) }, { 'next' => 2, 'lastCommit' => c1 }),
         { 'ok' => true, 'next' => 2, 'lastCommit' => c1 }],
        ['empty batch, head disagrees', vbt.({ 'from' => 2, 'records' => [], 'head' => hd.(2, 'zzz') }, { 'next' => 2, 'lastCommit' => c1 }),
         fail_.('batch end does not match the signed head')],
        ['records nil', vbt.(good.merge('records' => nil), st0), mal], ['record not an object', vbt.(good.merge('records' => [nil]), st0), mal],
        ['batch a string, state {}', vbt.('x', {}), mal], ['batch nil', vbt.(nil, st0), mal], ['state nil', vbt.(good, nil), mal],
        ['state a string', vbt.(good, 'x'), mal], ['state a duck', vbt.(good, C24::Duck.new(st0)), mal], ['batch a duck', vbt.(C24::Duck.new(good), st0), mal],
        ['batch a duck, state {}', vbt.(C24::Duck.new(good), {}), mal]
      ]
      c.ck(rows)
    end
  end

  # ================================================================================================================ K3: list receipts and cursors
  t('c24 k3 verify_list_receipt: every field required, objects check, optional objects, fault (plain verify)') do
    next true if C24.skip?('k3.rb')

    C24.fast do
      c = C24
      sg = c.pub(:ls)
      vr = ->(r, *rest) { AtlasPca.verify_list_receipt(r, sg, *rest) }
      rows = [['no objects given', vr.(c.sr), true], ['objects match', vr.(c.sr, %w[a b]), true], ['one object short', vr.(c.sr, %w[a]), false],
              ['other objects', vr.(c.sr, %w[a c]), false], ['objects nil explicitly', vr.(c.sr, nil), true],
              ['objects a string of the right length', vr.(c.sr('count' => 3, 'objects_digest' => c.od('abc')), 'abc'), false],
              ['objects empty, count 0', vr.(c.sr('count' => 0, 'objects_digest' => c.od([])), []), true],
              ['other signer arg', AtlasPca.verify_list_receipt(c.sr, c.pub(:other)), false], ['tampered', vr.(c.sr.merge('policy_digest' => 'q')), false],
              ['no sig', vr.(c.sr.reject { |k, _| k == 'sig' }), false], ['signed by another key', vr.(c.sr({}, :other)), false],
              ['subject 512', vr.(c.sr('subject' => 'x' * 512)), true], ['subject 513', vr.(c.sr('subject' => 'x' * 513)), false],
              ['duck of a valid receipt', vr.(C24::Duck.new(c.sr)), false]]
      [nil, 5, 'x', []].each { |x| rows << ["non-object #{x.inspect}", vr.(x), false] }
      [{ 'v' => 2 }, { 'signer' => c.pub(:other) }, { 'subject' => '' }, { 'subject' => 5 }, { 'subject' => nil }, { 'resource_type' => '' }, { 'resource_type' => 5 },
       { 'resource_type' => nil }, { 'count' => -1 }, { 'count' => 1.5 }, { 'count' => '2' }, { 'count' => nil }, { 'issued_at' => -1 }, { 'issued_at' => '7' },
       { 'issued_at' => nil }, { 'v' => :del }, { 'subject' => :del }, { 'count' => :del }].each do |over|
        rows << ["signed but #{over.inspect}", vr.(c.sr(over)), false]
      end
      raising = Seam.with(AtlasPca, { k3_verify_body: ->(*_a) { raise 'boom' } }) { vr.(c.sr) }
      rows << ['a fault is false', raising, false]
      c.ck(rows)
    end
  end

  t('c24 k3 list_bind: the exact binding digest, relation read only from an object, fault') do
    next true if C24.skip?('k3.rb')

    c = C24
    bi = { 'subject' => 's', 'resourceType' => 't', 'filterId' => 'f', 'policyDigest' => 'p', 'relation' => { 'relation' => 'viewer' }, 'limit' => 10 }
    want = ->(r) { AtlasPca.hash_canonical('s' => 's', 't' => 't', 'f' => 'f', 'p' => 'p', 'r' => r, 'l' => 10) }
    c.ck([['with relation', AtlasPca.list_bind(bi), want.('viewer')], ['no relation', AtlasPca.list_bind(bi.reject { |k, _| k == 'relation' }), want.(nil)],
          ['relation nil', AtlasPca.list_bind(bi.merge('relation' => nil)), want.(nil)],
          ['relation a string containing the word', AtlasPca.list_bind(bi.merge('relation' => 'xrelationx')), want.(nil)],
          ['relation a list', AtlasPca.list_bind(bi.merge('relation' => ['a'])), want.(nil)],
          ['relation without the key', AtlasPca.list_bind(bi.merge('relation' => {})), want.(nil)],
          ['nil input', AtlasPca.list_bind(nil), nil]])
  end

  t('c24 k3 verify_list_cursor: shape, split, signature, bind, optional bind and inner, U+FFFD scrub, fault (plain verify)') do
    next true if C24.skip?('k3.rb')

    C24.fast do
      c = C24
      sg = c.pub(:cur)
      vc2 = ->(t) { AtlasPca.verify_list_cursor(t, sg) }
      vc3 = ->(t, bnd) { AtlasPca.verify_list_cursor(t, sg, bnd) }
      mal = { 'ok' => false, 'reason' => 'malformed' }
      sig = { 'ok' => false, 'reason' => 'signature' }
      bi = { 'subject' => 's', 'resourceType' => 't', 'filterId' => 'f', 'policyDigest' => 'p', 'relation' => { 'relation' => 'viewer' }, 'limit' => 10 }
      bv = AtlasPca.hash_canonical('s' => 's', 't' => 't', 'f' => 'f', 'p' => 'p', 'r' => 'viewer', 'l' => 10)
      tok = c.cur
      p64, s64 = tok.split('.')
      splitter = Object.new
      splitter.define_singleton_method(:split) { |*_a| [p64, s64] }
      bad_json = "#{AtlasPca.b64e('not json'.b)}.#{s64}"
      raw = '{"bind":"B","inner":"'.b + "\xFF".b + "\",\"signer\":\"#{c.pub(:cur)}\",\"skip\":3,\"v\":1}".b
      scrub_body = { 'v' => 1, 'bind' => 'B', 'skip' => 3, 'signer' => c.pub(:cur), 'inner' => "\uFFFD" }
      scrub_tok = "#{AtlasPca.b64e(raw)}.#{c.sign(c::D_CUR, scrub_body, :cur)}"
      rows = [
        ['valid, no bind check', vc2.(tok), { 'ok' => true, 'skip' => 3 }],
        ['valid with inner', vc2.(c.cur('inner' => 'in')), { 'ok' => true, 'inner' => 'in', 'skip' => 3 }],
        ['skip 0', vc2.(c.cur('skip' => 0)), { 'ok' => true, 'skip' => 0 }],
        ['skip 2^53-1', vc2.(c.cur('skip' => (2**53) - 1)), { 'ok' => true, 'skip' => (2**53) - 1 }],
        ['bound and matching', vc3.(c.cur('bind' => bv), bi), { 'ok' => true, 'skip' => 3 }],
        ['bound, another limit', vc3.(c.cur('bind' => bv), bi.merge('limit' => 11)), { 'ok' => false, 'reason' => 'bind' }],
        ['bound, other relation', vc3.(c.cur('bind' => bv), bi.merge('relation' => { 'relation' => 'editor' })), { 'ok' => false, 'reason' => 'bind' }],
        ['garbage bind ignored without inputs', vc2.(c.cur('bind' => 'garbage')), { 'ok' => true, 'skip' => 3 }],
        ['trailing dot is a third part', vc2.(c.cur({}, :cur, '.')), mal], ['extra part', vc2.(c.cur({}, :cur, '.junk')), mal],
        ['no dot', vc2.(p64), mal], ['empty signature', vc2.("#{p64}."), mal], ['empty payload', vc2.(".#{s64}"), mal], ['empty token', vc2.(''), mal],
        ['payload not base64', vc2.("!!!.#{s64}"), mal], ['payload not json', vc2.(bad_json), mal],
        ['payload a json array', vc2.("#{AtlasPca.b64e('[1]'.b)}.#{s64}"), mal],
        ['payload null', vc2.("#{AtlasPca.b64e('null'.b)}.#{s64}"), mal],
        ['v 2', vc2.(c.cur('v' => 2)), mal], ['v str', vc2.(c.cur('v' => '1')), mal], ['v gone', vc2.(c.cur('v' => :del)), mal],
        ['bind int', vc2.(c.cur('bind' => 5)), mal], ['bind nil', vc2.(c.cur('bind' => nil)), mal], ['bind gone', vc2.(c.cur('bind' => :del)), mal],
        ['skip -1', vc2.(c.cur('skip' => -1)), mal], ['skip 1.5', vc2.(c.cur('skip' => 1.5)), mal], ['skip str', vc2.(c.cur('skip' => '3')), mal],
        ['skip nil', vc2.(c.cur('skip' => nil)), mal], ['skip gone', vc2.(c.cur('skip' => :del)), mal],
        ['inner int', vc2.(c.cur('inner' => 5)), mal], ['inner nil', vc2.(c.cur('inner' => nil)), mal], ['inner list', vc2.(c.cur('inner' => ['a'])), mal],
        ['signer field of another key', vc2.(c.cur('signer' => c.pub(:other))), sig], ['signed by another key', vc2.(c.cur({}, :other)), sig],
        ['signer field gone', vc2.(c.cur('signer' => :del)), sig], ['signature not base64', vc2.("#{p64}.zz!"), sig],
        ['signature of other bytes', vc2.("#{p64}.#{c.sign(c::D_CUR, { 'x' => 1 }, :cur)}"), sig],
        ['not a string: nil', vc2.(nil), mal], ['not a string: int', vc2.(5), mal], ['not a string: list', vc2.([p64, s64]), mal],
        ['a non-string that splits', vc2.(splitter), mal],
        ['invalid UTF-8 is replaced by U+FFFD before parsing', vc2.(scrub_tok), { 'ok' => true, 'inner' => "\uFFFD", 'skip' => 3 }]
      ]
      boom = Seam.with(AtlasPca, { k3_verify_body: ->(*_a) { raise 'boom' } }) { vc2.(tok) }
      rows << ['a fault is malformed', boom, mal]
      c.ck(rows)
    end
  end

  # ================================================================================================================ K3: authority
  t('c24 k3 authority_res_covers? / authority_res_subset?') do
    next true if C24.skip?('k3.rb')

    cv = ->(p, r) { AtlasPca.authority_res_covers?(p, r) }
    ss = ->(s, b) { AtlasPca.authority_res_subset?(s, b) }
    C24.ck([['prefix covers', cv.('a*', 'ab'), true], ['prefix itself', cv.('a*', 'a'), true], ['prefix misses', cv.('a*', 'b'), false],
            ['star covers all', cv.('*', 'x'), true], ['exact equal', cv.('a', 'a'), true], ['exact is not a prefix', cv.('a', 'ab'), false],
            ['exact vs star literal', cv.('a', 'a*'), false], ['longer prefix misses', cv.('ab*', 'ac'), false], ['longer prefix hits', cv.('ab*', 'abc'), true],
            ['subset exact', ss.(%w[a], %w[a]), true], ['subset star in star', ss.(%w[a*], %w[a*]), true], ['narrower star', ss.(%w[ab*], %w[a*]), true],
            ['wider star', ss.(%w[a*], %w[ab*]), false], ['star in exact', ss.(%w[a*], %w[a]), false], ['exact in star', ss.(%w[a], %w[a*]), true],
            ['empty small', ss.([], %w[x]), true], ['empty big', ss.(%w[a], []), false], ['disjoint', ss.(%w[a], %w[b]), false],
            ['every one must be covered', ss.(%w[a b], %w[a]), false]])
  end

  t('c24 k3 authority_le? / compare_authority: verbs, resources, ceilings, expiry, exact booleans and no fault on missing limits') do
    next true if C24.skip?('k3.rb')

    c = C24
    le = ->(x, y) { AtlasPca.authority_le?(x, y) }
    au = c.method(:au)
    rows = [
      ['equal', le.(au.(%w[x], %w[r]), au.(%w[x], %w[r])), true], ['more verbs', le.(au.(%w[x y], %w[r]), au.(%w[x], %w[r])), false],
      ['fewer verbs', le.(au.(%w[x], %w[r]), au.(%w[x y], %w[r])), true], ['other resource', le.(au.(%w[x], %w[r2]), au.(%w[x], %w[r])), false],
      ['resource in a star', le.(au.(%w[x], %w[doc/1]), au.(%w[x], %w[doc/*])), true],
      ['lower ceiling', le.(au.(%w[x], %w[r], { 'm' => 5 }), au.(%w[x], %w[r], { 'm' => 9 })), true],
      ['equal ceiling', le.(au.(%w[x], %w[r], { 'm' => 5 }), au.(%w[x], %w[r], { 'm' => 5 })), true],
      ['higher ceiling', le.(au.(%w[x], %w[r], { 'm' => 9 }), au.(%w[x], %w[r], { 'm' => 5 })), false],
      ['a bounded, b unbounded', le.(au.(%w[x], %w[r], { 'm' => 5 }), au.(%w[x], %w[r])), true],
      ['a unbounded, b bounded', le.(au.(%w[x], %w[r]), au.(%w[x], %w[r], { 'm' => 5 })), false],
      ['b bounds a key a lacks', le.(au.(%w[x], %w[r], { 'm' => 1 }), au.(%w[x], %w[r], { 'n' => 1 })), false],
      ['sooner expiry', le.(au.(%w[x], %w[r], nil, 5), au.(%w[x], %w[r], nil, 9)), true], ['later expiry', le.(au.(%w[x], %w[r], nil, 9), au.(%w[x], %w[r], nil, 5)), false],
      ['a never, b dated', le.(au.(%w[x], %w[r]), au.(%w[x], %w[r], nil, 9)), false], ['a dated, b never', le.(au.(%w[x], %w[r], nil, 9), au.(%w[x], %w[r])), true],
      ['same expiry', le.(au.(%w[x], %w[r], nil, 9), au.(%w[x], %w[r], nil, 9)), true]
    ]
    base = au.(%w[read write], %w[doc/*], { 'usd' => 100 }, 1000)
    cmp = ->(o, n) { AtlasPca.compare_authority(o, n) }
    rows.push(['cmp equal', cmp.(base, base), 'equal'], ['cmp narrower', cmp.(base, au.(%w[read], %w[doc/*], { 'usd' => 50 }, 500)), 'narrower'],
              ['cmp wider', cmp.(base, au.(%w[read write admin], %w[doc/*], { 'usd' => 100 }, 1000)), 'wider'],
              ['cmp incomparable', cmp.(base, au.(%w[read zzz], %w[doc/*], { 'usd' => 100 }, 1000)), 'incomparable'],
              ['cmp lower ceiling only', cmp.(base, au.(%w[read write], %w[doc/*], { 'usd' => 50 }, 1000)), 'narrower'],
              ['cmp dropped ceiling', cmp.(base, au.(%w[read write], %w[doc/*], nil, 1000)), 'wider'])
    c.ck(rows)
  end

  t('c24 k3 authority_digest: sorted by UTF-16 code units, exact digest, fault') do
    next true if C24.skip?('k3.rb')

    a = { 'verbs' => %w[z a m], 'resources' => %w[r2 r1 r10], 'limits' => { 'm' => 1 }, 'expires_at' => 9 }
    sorted = { 'verbs' => %w[a m z], 'resources' => %w[r1 r10 r2], 'limits' => { 'm' => 1 }, 'expires_at' => 9 }
    astral = { 'verbs' => ["\uffff", "\u{10000}"], 'resources' => ["\uffff", "\u{10000}"] }
    astral_sorted = { 'verbs' => ["\u{10000}", "\uffff"], 'resources' => ["\u{10000}", "\uffff"] }
    dg = ->(x) { AtlasPca.hash_canonical('d' => 'atlas-pca/authority/v1', 'a' => x) }
    C24.ck([['digest', AtlasPca.authority_digest(a), dg.(sorted)], ['already sorted', AtlasPca.authority_digest(sorted), dg.(sorted)],
            ['utf-16 order', AtlasPca.authority_digest(astral), dg.(astral_sorted)], ['nil', AtlasPca.authority_digest(nil), nil],
            ['no verbs', AtlasPca.authority_digest({ 'resources' => [] }), nil]])
  end

  t('c24 k3 merge_authority: union, ceilings only raised, expiry only raised, empty parts omitted') do
    next true if C24.skip?('k3.rb')

    c = C24
    mg = ->(x, y) { AtlasPca.merge_authority(x, y) }
    rows = [
      ['plain union', mg.(c.au(%w[x], %w[r]), c.au(%w[x y], %w[r2])), { 'verbs' => %w[x y], 'resources' => %w[r r2] }],
      ['delta has limits a lacks', mg.(c.au(%w[x], %w[r]), c.au(%w[y], %w[r2], { 'm' => 3 }, 99)), { 'verbs' => %w[x y], 'resources' => %w[r r2] }],
      ['ceiling raised, omitted kept, new key ignored', mg.(c.au(%w[x], %w[r], { 'm' => 5, 'n' => 7 }), c.au(%w[x], %w[r], { 'm' => 9, 'q' => 1 })),
       { 'verbs' => %w[x], 'resources' => %w[r], 'limits' => { 'm' => 9, 'n' => 7 } }],
      ['ceiling not lowered', mg.(c.au(%w[x], %w[r], { 'm' => 5 }), c.au(%w[x], %w[r], { 'm' => 3 })), { 'verbs' => %w[x], 'resources' => %w[r], 'limits' => { 'm' => 5 } }],
      ['delta without limits keeps them', mg.(c.au(%w[x], %w[r], { 'm' => 5 }), c.au(%w[y], %w[r])),
       { 'verbs' => %w[x y], 'resources' => %w[r], 'limits' => { 'm' => 5 } }],
      ['expiry raised', mg.(c.au(%w[x], %w[r], nil, 10), c.au(%w[x], %w[r], nil, 20)), { 'verbs' => %w[x], 'resources' => %w[r], 'expires_at' => 20 }],
      ['expiry not lowered', mg.(c.au(%w[x], %w[r], nil, 10), c.au(%w[x], %w[r], nil, 5)), { 'verbs' => %w[x], 'resources' => %w[r], 'expires_at' => 10 }],
      ['expiry kept when delta has none', mg.(c.au(%w[x], %w[r], nil, 10), c.au(%w[x], %w[r])), { 'verbs' => %w[x], 'resources' => %w[r], 'expires_at' => 10 }],
      ['a never expires stays so', mg.(c.au(%w[x], %w[r]), c.au(%w[x], %w[r], nil, 99)), { 'verbs' => %w[x], 'resources' => %w[r] }]
    ]
    C24.ck(rows)
  end

  t('c24 k3 authority_ok?: shape, counts and lengths on both sides of each cap, ceilings, expiry') do
    next true if C24.skip?('k3.rb')

    ok = ->(over) { AtlasPca.authority_ok?(C24.mrg({ 'verbs' => ['v'], 'resources' => ['r'] }, over)) }
    long = ->(n) { 'x' * n }
    table = [
      ['base', {}, true], ['empty lists', { 'verbs' => [], 'resources' => [] }, true], ['256 verbs', { 'verbs' => Array.new(256, 'v') }, true],
      ['257 verbs', { 'verbs' => Array.new(257, 'v') }, false], ['verb 128', { 'verbs' => [long.(128)] }, true], ['verb 129', { 'verbs' => [long.(129)] }, false],
      ['verb empty', { 'verbs' => [''] }, false], ['verb int', { 'verbs' => [5] }, false], ['verbs nil', { 'verbs' => nil }, false],
      ['verbs hash', { 'verbs' => {} }, false], ['verbs str', { 'verbs' => 'abc' }, false], ['verbs gone', { 'verbs' => :del }, false],
      ['1024 resources', { 'resources' => Array.new(1024, 'r') }, true], ['1025 resources', { 'resources' => Array.new(1025, 'r') }, false],
      ['resource 512', { 'resources' => [long.(512)] }, true], ['resource 513', { 'resources' => [long.(513)] }, false],
      ['resource empty', { 'resources' => [''] }, false], ['resource int', { 'resources' => [5] }, false], ['resources nil', { 'resources' => nil }, false],
      ['resources hash', { 'resources' => {} }, false], ['resources str', { 'resources' => 'abc' }, false], ['resources gone', { 'resources' => :del }, false],
      ['limits empty', { 'limits' => {} }, true], ['limit 0', { 'limits' => { 'm' => 0 } }, true], ['limit 0.5', { 'limits' => { 'm' => 0.5 } }, true],
      ['limit 3', { 'limits' => { 'm' => 3 } }, true], ['limit -1', { 'limits' => { 'm' => -1 } }, false], ['limit -0.5', { 'limits' => { 'm' => -0.5 } }, false],
      ['limit str', { 'limits' => { 'm' => 'x' } }, false], ['limit nil', { 'limits' => { 'm' => nil } }, false], ['limit true', { 'limits' => { 'm' => true } }, false],
      ['limit infinity', { 'limits' => { 'm' => Float::INFINITY } }, false], ['limit nan', { 'limits' => { 'm' => Float::NAN } }, false],
      ['limits nil', { 'limits' => nil }, false], ['limits list', { 'limits' => [] }, false], ['limits int', { 'limits' => 5 }, false],
      ['one bad limit among good', { 'limits' => { 'a' => 1, 'b' => -1 } }, false],
      ['expiry 0', { 'expires_at' => 0 }, true], ['expiry 2^53-1', { 'expires_at' => (2**53) - 1 }, true], ['expiry 2^53', { 'expires_at' => 2**53 }, false],
      ['expiry -1', { 'expires_at' => -1 }, false], ['expiry 1.5', { 'expires_at' => 1.5 }, false], ['expiry str', { 'expires_at' => '5' }, false],
      ['expiry nil', { 'expires_at' => nil }, false]
    ]
    rows = table.map { |label, over, want| [label, ok.(over), want] }
    [nil, 5, 'x', []].each { |x| rows << ["non-object #{x.inspect}", AtlasPca.authority_ok?(x), false] }
    C24.ck(rows)
  end

  # ================================================================================================================ K3: grant management
  t('c24 k3 verify_amendment: check order, classification, who signs, step-up, exact results (plain verify)') do
    next true if C24.skip?('k3.rb')

    C24.fast do
      c = C24
      auth = c.au(%w[read write], %w[doc/*], { 'usd' => 100 }, 1000)
      cur = { 'id' => 'g1', 'rev' => 3, 'principal' => c.pub(:pr), 'agent' => c.pub(:ag), 'status' => 'active', 'authority' => auth }
      amsg = ->(cu, action, a) { { 'grant' => cu['id'], 'rev' => cu['rev'], 'action' => action, 'authority' => c.adig(a) } }
      rq = lambda do |action, a, who, cu = cur, label = nil|
        { 'action' => action, 'authority' => a, 'signed_by' => who, 'sig' => c.sign(c::D_AMEND, amsg.(cu, action, a), label || (who == 'principal' ? :pr : :ag)) }
      end
      va = ->(cu, req, step) { AtlasPca.verify_amendment(cu, req, step) }
      err = ->(code) { { 'ok' => false, 'code' => code } }
      narrower = c.au(%w[read], %w[doc/*], { 'usd' => 50 }, 500)
      wider = c.au(%w[read write admin], %w[doc/*], { 'usd' => 100 }, 1000)
      incomp = c.au(%w[read zzz], %w[doc/*], { 'usd' => 100 }, 1000)
      delta = c.au(%w[admin], %w[x/*])
      merged = { 'verbs' => %w[read write admin], 'resources' => %w[doc/* x/*], 'limits' => { 'usd' => 100 }, 'expires_at' => 1000 }
      unsigned = rq.('narrow', narrower, 'holder').reject { |k, _| k == 'sig' }
      stranger = rq.('narrow', narrower, 'holder').merge('signed_by' => 'x')
      old_cur = cur.merge('rev' => 2)
      rows = [
        ['narrow by the holder', va.(cur, rq.('narrow', narrower, 'holder'), false), { 'ok' => true, 'widens' => false, 'next' => narrower }],
        ['narrow by the principal', va.(cur, rq.('narrow', narrower, 'principal'), false), { 'ok' => true, 'widens' => false, 'next' => narrower }],
        ['narrow that changes nothing', va.(cur, rq.('narrow', auth, 'holder'), true), err.('not_narrower')],
        ['narrow that widens', va.(cur, rq.('narrow', wider, 'principal'), true), err.('not_narrower')],
        ['narrow that is incomparable', va.(cur, rq.('narrow', incomp, 'principal'), true), err.('not_narrower')],
        ['replace with the same authority is in place', va.(cur, rq.('replace', auth, 'holder'), false), { 'ok' => true, 'widens' => false, 'next' => auth }],
        ['replace narrower by the holder', va.(cur, rq.('replace', narrower, 'holder'), false), { 'ok' => true, 'widens' => false, 'next' => narrower }],
        ['widening by the holder', va.(cur, rq.('replace', wider, 'holder'), true), err.('signature_required')],
        ['widening by the principal, no step-up', va.(cur, rq.('replace', wider, 'principal'), false), err.('step_up_required')],
        ['widening by the principal with step-up', va.(cur, rq.('replace', wider, 'principal'), true), { 'ok' => true, 'widens' => true, 'next' => wider }],
        ['incomparable is widening', va.(cur, rq.('replace', incomp, 'principal'), true), { 'ok' => true, 'widens' => true, 'next' => incomp }],
        ['principal claim signed by the agent key', va.(cur, rq.('replace', wider, 'principal', cur, :ag), true), err.('bad_signature')],
        ['holder claim signed by the principal key', va.(cur, rq.('narrow', narrower, 'holder', cur, :pr), true), err.('bad_signature')],
        ['merge unions and widens', va.(cur, rq.('merge', delta, 'principal'), true), { 'ok' => true, 'widens' => true, 'next' => merged }],
        ['merge needs step-up', va.(cur, rq.('merge', delta, 'principal'), false), err.('step_up_required')],
        ['merge by the holder', va.(cur, rq.('merge', delta, 'holder'), true), err.('signature_required')],
        ['merge of nothing new is in place', va.(cur, rq.('merge', c.au(%w[read], %w[doc/*]), 'holder'), false),
         { 'ok' => true, 'widens' => false, 'next' => auth }],
        ['unsigned', va.(cur, unsigned, true), err.('signature_required')],
        ['signature not a string', va.(cur, rq.('narrow', narrower, 'holder').merge('sig' => 5), true), err.('signature_required')],
        ['signed_by a stranger label', va.(cur, stranger, true), err.('signature_required')],
        ['signed_by nil', va.(cur, rq.('narrow', narrower, 'holder').merge('signed_by' => nil), true), err.('signature_required')],
        ['signed_by gone', va.(cur, rq.('narrow', narrower, 'holder').reject { |k, _| k == 'signed_by' }, true), err.('signature_required')],
        ['a signature for the previous revision', va.(cur, rq.('narrow', narrower, 'holder', old_cur), true), err.('bad_signature')],
        ['a signature for another action', va.(cur, rq.('replace', narrower, 'holder').merge('action' => 'narrow'), true), err.('bad_signature')],
        ['not active', va.(cur.merge('status' => 'revoked'), rq.('narrow', narrower, 'holder'), true), err.('not_active')],
        ['bad authority beats not active', va.(cur.merge('status' => 'revoked'), { 'action' => 'narrow', 'authority' => nil }, true), err.('bad_request')],
        ['negative ceiling beats not active', va.(cur.merge('status' => 'revoked'), { 'action' => 'narrow', 'authority' => c.au(%w[a], %w[b], { 'm' => -1 }) }, true),
         err.('bad_request')],
        ['unknown action', va.(cur, rq.('narrow', narrower, 'holder').merge('action' => 'bogus'), true), err.('bad_request')],
        ['request nil', va.(cur, nil, true), err.('bad_request')], ['request a list', va.(cur, [], true), err.('bad_request')],
        ['request a string', va.(cur, 'narrow', true), err.('bad_request')], ['authority nil', va.(cur, { 'action' => 'narrow', 'authority' => nil }, true), err.('bad_request')],
        ['authority without resources', va.(cur, { 'action' => 'narrow', 'authority' => { 'verbs' => ['a'] } }, true), err.('bad_request')],
        ['grant nil is a bad request', va.(nil, rq.('narrow', narrower, 'holder'), true), err.('bad_request')]
      ]
      c.ck(rows)
    end
  end

  t('c24 k3 verify_revoke_signature: scope list, principal signature over (grant, scope), fault (plain verify)') do
    next true if C24.skip?('k3.rb')

    C24.fast do
      c = C24
      root = { 'id' => 'g1', 'principal' => c.pub(:pr) }
      rs = ->(scope, l = :pr, id = 'g1') { c.sign(c::D_REVOKE, { 'grant' => id, 'scope' => scope }, l) }
      vr = ->(rt, scope, sig) { AtlasPca.verify_revoke_signature(rt, scope, sig) }
      err = ->(code) { { 'ok' => false, 'code' => code } }
      rows = %w[grant agent subtree].map { |s| ["scope #{s}", vr.(root, s, rs.(s)), { 'ok' => true, 'scope' => s }] }
      rows.push(['a grant-scope signature does not cover subtree', vr.(root, 'subtree', rs.('grant')), err.('bad_signature')],
                ['a stranger', vr.(root, 'grant', rs.('grant', :other)), err.('bad_signature')],
                ['another grant id', vr.(root, 'grant', rs.('grant', :pr, 'g2')), err.('bad_signature')],
                ['unknown scope', vr.(root, 'bogus', rs.('grant')), err.('bad_request')], ['scope nil', vr.(root, nil, rs.('grant')), err.('bad_request')],
                ['no signature', vr.(root, 'grant', nil), err.('bad_signature')], ['signature int', vr.(root, 'grant', 5), err.('bad_signature')],
                ['root nil is a bad signature', vr.(nil, 'grant', rs.('grant')), err.('bad_signature')])
      c.ck(rows)
    end
  end

  t('c24 k3 verify_need_approval: signature first, count, same target, lowered only, adjustable, step-up, merged authority (plain verify)') do
    next true if C24.skip?('k3.rb')

    C24.fast do
      c = C24
      gauth = { 'verbs' => ['read'], 'resources' => ['doc/*'], 'limits' => { 'usd' => 10 } }
      g = { 'rev' => 2, 'principal' => c.pub(:pr), 'authority' => gauth }
      need = { 'verb' => 'pay', 'resource' => 'acct/1', 'limits' => { 'usd' => 50 }, 'adjustable' => true }
      nr = { 'id' => 'n1', 'grant_id' => 'g1', 'status' => 'pending', 'needs' => [need] }
      nsig = ->(n, approved, rev = 2, l = :pr) { c.sign(c::D_NEED, { 'need' => n['id'], 'grant' => n['grant_id'], 'rev' => rev, 'approved' => approved }, l) }
      vn = lambda do |n, gr, approved, step = true, sig = :auto|
        AtlasPca.verify_need_approval(n, gr, approved, sig == :auto ? nsig.(n, approved, gr['rev']) : sig, step)
      end
      err = ->(code) { { 'ok' => false, 'code' => code } }
      a1 = [{ 'verb' => 'pay', 'resource' => 'acct/1', 'limits' => { 'usd' => 50 } }]
      a_low = [{ 'verb' => 'pay', 'resource' => 'acct/1', 'limits' => { 'usd' => 20 } }]
      nr_na = nr.merge('needs' => [need.merge('adjustable' => false)])
      nr_nl = nr.merge('needs' => [{ 'verb' => 'pay', 'resource' => 'acct/1' }])
      nr2 = nr.merge('needs' => [{ 'verb' => 'pay', 'resource' => 'a', 'limits' => { 'usd' => 10 } }, { 'verb' => 'pay', 'resource' => 'b', 'limits' => { 'usd' => 5 } }])
      a2 = [{ 'verb' => 'pay', 'resource' => 'a', 'limits' => { 'usd' => 10 } }, { 'verb' => 'pay', 'resource' => 'b', 'limits' => { 'usd' => 5 } }]
      g0 = g.merge('authority' => { 'verbs' => ['read'], 'resources' => ['doc/*'], 'limits' => { 'usd' => 0 } })
      nr3 = nr.merge('needs' => [{ 'verb' => 'pay', 'resource' => 'a', 'limits' => { 'usd' => 0 } }])
      a3 = [{ 'verb' => 'pay', 'resource' => 'a', 'limits' => { 'usd' => 0 } }]
      nr_empty = nr.merge('needs' => [])
      rows = [
        ['approve as asked', vn.(nr, g, a1), { 'ok' => true, 'authority' => { 'verbs' => %w[read pay], 'resources' => %w[doc/* acct/1], 'limits' => { 'usd' => 50 } } }],
        ['approve lowered, adjustable', vn.(nr, g, a_low), { 'ok' => true, 'authority' => { 'verbs' => %w[read pay], 'resources' => %w[doc/* acct/1], 'limits' => { 'usd' => 20 } } }],
        ['lowered, not adjustable', vn.(nr_na, g, a_low), err.('need_not_adjustable')],
        ['as asked, not adjustable', vn.(nr_na, g, a1),
         { 'ok' => true, 'authority' => { 'verbs' => %w[read pay], 'resources' => %w[doc/* acct/1], 'limits' => { 'usd' => 50 } } }],
        ['raised amount', vn.(nr, g, [{ 'verb' => 'pay', 'resource' => 'acct/1', 'limits' => { 'usd' => 60 } }]), err.('need_not_lowered_only')],
        ['a limit that was not asked for', vn.(nr, g, [{ 'verb' => 'pay', 'resource' => 'acct/1', 'limits' => { 'usd' => 50, 'eur' => 1 } }]), err.('need_not_lowered_only')],
        ['the need names no limits, approval adds one', vn.(nr_nl, g, a1), err.('need_not_lowered_only')],
        ['the need names no limits, approval adds none',
         vn.(nr_nl, g, [{ 'verb' => 'pay', 'resource' => 'acct/1' }]),
         { 'ok' => true, 'authority' => { 'verbs' => %w[read pay], 'resources' => %w[doc/* acct/1], 'limits' => { 'usd' => 10 } } }],
        ['changed verb', vn.(nr, g, [{ 'verb' => 'refund', 'resource' => 'acct/1', 'limits' => { 'usd' => 50 } }]), err.('need_not_lowered_only')],
        ['changed resource', vn.(nr, g, [{ 'verb' => 'pay', 'resource' => 'acct/2', 'limits' => { 'usd' => 50 } }]), err.('need_not_lowered_only')],
        ['fewer approved', vn.(nr, g, []), err.('need_not_lowered_only')], ['more approved', vn.(nr, g, a1 + a1), err.('need_not_lowered_only')],
        ['approved an object, no needs', vn.(nr_empty, g, {}), err.('need_not_lowered_only')],
        ['approved empty list, no needs', vn.(nr_empty, g, []), { 'ok' => true, 'authority' => gauth }],
        ['no step-up', vn.(nr, g, a1, false), err.('step_up_required')],
        ['already approved', vn.(nr.merge('status' => 'approved'), g, a1), err.('conflict')],
        ['signed by a stranger', vn.(nr, g, a1, true, nsig.(nr, a1, 2, :other)), err.('bad_signature')],
        ['signed for another revision', vn.(nr, g, a1, true, nsig.(nr, a1, 1)), err.('bad_signature')],
        ['signature over other approved', vn.(nr, g, a1, true, nsig.(nr, a_low)), err.('bad_signature')], ['no signature', vn.(nr, g, a1, true, nil), err.('bad_signature')],
        ['same ceiling twice keeps the larger', vn.(nr2, g0, a2),
         { 'ok' => true, 'authority' => { 'verbs' => %w[read pay], 'resources' => %w[doc/* a b], 'limits' => { 'usd' => 10 } } }],
        ['a ceiling of zero stays zero', vn.(nr3, g0, a3),
         { 'ok' => true, 'authority' => { 'verbs' => %w[read pay], 'resources' => %w[doc/* a], 'limits' => { 'usd' => 0 } } }],
        ['needs nil is a fault', vn.(nr.merge('needs' => nil), g, a1), err.('need_not_lowered_only')],
        ['an approved entry that is not an object', vn.(nr, g, [nil]), err.('need_not_lowered_only')]
      ]
      c.ck(rows)
    end
  end

  # ================================================================================================================ K3: shared vectors
  t('c24 k3 shared vectors (k3-vectors.json) reproduce their expect exactly (plain verify)') do
    next true if C24.skip?('k3.rb')

    raise 'k3-vectors.json missing' if C24_VEC3.nil?

    C24.fast do
      a = AtlasPca
      run = lambda do |kind, i|
        case kind
        when 'bundle_digest' then { 'digest' => a.bundle_digest(i['bundle']) }
        when 'bundle_verify' then a.verify_bundle(i['bundle'], i['options'])
        when 'log_commit' then { 'commit' => a.record_commit(i['record']) }
        when 'log_head_verify' then { 'valid' => a.verify_log_head(i['head'], i['signer']) }
        when 'log_inclusion' then { 'valid' => a.verify_record_inclusion(i['record'], i['proof'], i['head'], i['signer']) }
        when 'log_batch_verify' then a.verify_batch(i['batch'], i['state'], i['signer'])
        when 'list_objects_digest' then { 'digest' => a.objects_digest(i['objects']) }
        when 'list_receipt_verify' then { 'valid' => a.verify_list_receipt(i['receipt'], i['signer'], i['objects']) }
        when 'list_bind' then { 'digest' => a.list_bind(i['bind']) }
        when 'list_cursor_verify' then a.verify_list_cursor(i['cursor'], i['signer'], i['bind'])
        when 'authority_digest' then { 'digest' => a.authority_digest(i['authority']) }
        when 'authority_compare' then { 'order' => a.compare_authority(i['old'], i['new']) }
        when 'amend_verify'
          r = a.verify_amendment(i['grant'], i['request'], i['step_up_ok'])
          r['ok'] ? { 'ok' => true, 'widens' => r['widens'], 'next_digest' => a.authority_digest(r['next']) } : r
        when 'revoke_verify' then a.verify_revoke_signature(i['root'], i['scope'], i['sig'])
        when 'need_approve_verify'
          r = a.verify_need_approval(i['need_request'], i['grant'], i['approved'], i['sig'], i['step_up_ok'])
          r['ok'] ? { 'ok' => true, 'authority_digest' => a.authority_digest(r['authority']) } : r
        end
      end
      bad = []
      C24_VEC3['primitives'].each do |kind, entries|
        next if kind.start_with?('fresh_at')

        entries.each do |e|
          got = run.(kind, e['input'])
          bad << "#{kind}/#{e['name']}: got #{got.inspect[0, 120]}" if got != e['expect']
        end
      end
      raise "k3 vectors: #{bad.first(4).join(' | ')}" unless bad.empty?

      true
    end
  end

  # ================================================================================================================ K4: helpers
  t('c24 k4 k4_int? / k4_lower') do
    next true if C24.skip?('k4.rb')

    a = AtlasPca
    m = (2**53) - 1
    C24.ck([['5', a.k4_int?(5), true], ['0', a.k4_int?(0), true], ['-5', a.k4_int?(-5), true], ['max', a.k4_int?(m), true], ['max+1', a.k4_int?(m + 1), false],
            ['-max', a.k4_int?(-m), true], ['-(max+1)', a.k4_int?(-(m + 1)), false], ['1.5', a.k4_int?(1.5), false], ['1.0', a.k4_int?(1.0), false],
            ['nil', a.k4_int?(nil), false], ['str', a.k4_int?('5'), false],
            ['lower str', a.k4_lower('AbC'), 'abc'], ['lower nil', a.k4_lower(nil), "\0"], ['lower int', a.k4_lower(5), "\0"], ['lower empty', a.k4_lower(''), ''],
            ['lower list', a.k4_lower(['A']), "\0"]])
  end

  t('c24 k4 k4_luhn? / looks_like_pan? / token_ref_error: digit arithmetic, 13..19 digit runs, reference alphabet and length') do
    next true if C24.skip?('k4.rb')

    a = AtlasPca
    valid = %w[4111111111111111 4222222222222 477777777772 18 59 5500000000000004 6011111111111117 378282246310005 4777777777771]
    invalid = %w[4111111111111112 55 5500000000000005 1234567812345678]
    rows = valid.map { |d| ["luhn #{d}", a.k4_luhn?(d), true] } + invalid.map { |d| ["luhn #{d}", a.k4_luhn?(d), false] }
    pan = a.method(:looks_like_pan?)
    rows.push(['pan 16', pan.('4111111111111111'), true], ['pan 13', pan.('4222222222222'), true], ['pan 19', pan.('4777777777777777775'), true],
              ['pan 12 valid is not', pan.('477777777772'), false], ['pan 20 valid is not', pan.('47777777777777777774'), false],
              ['pan 18 valid', pan.('477777777777777776'), true], ['pan 14 valid', pan.('47777777777770'), true],
              ['16 invalid is not', pan.('4111111111111112'), false], ['spaces joined', pan.('4111 1111 1111 1111'), true], ['hyphens joined', pan.('4111-1111-1111-1111'), true],
              ['tabs joined', pan.("4111\t1111\t1111\t1111"), true], ['letters split the run', pan.('41111111x11111111'), false],
              ['embedded in text', pan.('ref4111111111111111end'), true], ['no digits', pan.('abcdef'), false], ['empty', pan.(''), false])
    ter = a.method(:token_ref_error)
    mal = 'token_ref_malformed'
    rows.push(['ref ok', ter.('tok_abcdef12'), nil], ['ref 8', ter.('abcdefgh'), nil], ['ref 7', ter.('abcdefg'), mal], ['ref 128', ter.('a' * 128), nil],
              ['ref 129', ter.('a' * 129), mal], ['ref alphabet', ter.('a_b.c:d-e1'), nil], ['ref space', ter.('abcd efgh'), mal], ['ref slash', ter.('abcd/efgh'), mal],
              ['ref newline end', ter.("abcdefgh\n"), mal], ['ref nil', ter.(nil), mal], ['ref int', ter.(12_345_678), mal], ['ref list', ter.(['abcdefgh']), mal],
              ['ref pan', ter.('4111111111111111'), 'token_ref_looks_like_pan'], ['ref pan in text', ter.('tok-4111111111111111'), 'token_ref_looks_like_pan'],
              ['ref luhn-invalid digits', ter.('4111111111111112'), nil], ['ref 12 valid digits', ter.('477777777772'), nil])
    C24.ck(rows)
  end

  t('c24 k4 k4_sig: undecodable key or signature is nil (not false), guards observable with a decoder that accepts anything') do
    next true if C24.skip?('k4.rb')

    c = C24
    a = AtlasPca
    real = c.k4sign('k', { 'x' => 1 }, :pr)
    rows = [['valid', c.fast { a.k4_sig(c.pub(:pr), 'k', { 'x' => 1, 'sig' => real }) }, true],
            ['body without sig only', c.fast { a.k4_sig(c.pub(:pr), 'k', { 'x' => 2, 'sig' => real }) }, false],
            ['other kind', c.fast { a.k4_sig(c.pub(:pr), 'j', { 'x' => 1, 'sig' => real }) }, false],
            ['key not base64', a.k4_sig('!!', 'k', { 'x' => 1, 'sig' => real }), nil], ['sig not base64', a.k4_sig(c.pub(:pr), 'k', { 'x' => 1, 'sig' => '!!' }), nil],
            ['key nil', a.k4_sig(nil, 'k', { 'sig' => real }), nil], ['sig nil', a.k4_sig(c.pub(:pr), 'k', { 'sig' => nil }), nil],
            ['key int', a.k4_sig(5, 'k', { 'sig' => real }), nil], ['sig int', a.k4_sig(c.pub(:pr), 'k', { 'sig' => 5 }), nil]]
    seen = []
    Seam.with(a, { b64d: ->(*_x) { 'x' } }) do
      rows << ['decoder accepts all: key int', a.k4_sig(5, 'k', { 'sig' => 'x' }), nil]
      rows << ['decoder accepts all: sig int', a.k4_sig('x', 'k', { 'sig' => 5 }), nil]
      rows << ['decoder accepts all: key nil', a.k4_sig(nil, 'k', { 'sig' => 'x' }), nil]
      rows << ['decoder accepts all: sig nil', a.k4_sig('x', 'k', { 'sig' => nil }), nil]
      rows << ['decoder accepts all: key list', a.k4_sig(['x'], 'k', { 'sig' => 'x' }), nil]
      rows << ['decoder accepts all: both strings go on to the verify', a.k4_sig('x', 'k', { 'sig' => 'x' }), false]
      seen << :done
    end
    c.ck(rows + [['seam ran', seen, [:done]]])
  end

  # ================================================================================================================ K4: pricing config and decisions
  t('c24 k4 pricing_config_error: shape, amounts, cost cap, step range, signature (plain verify)') do
    next true if C24.skip?('k4.rb')

    C24.fast do
      c = C24
      pe = ->(x) { AtlasPca.pricing_config_error(x) }
      mal = 'config_malformed'
      rows = [
        ['valid', pe.(c.sc), nil], ['cost equals the max', pe.(c.sc('interruptionCost' => 500)), nil], ['cost 0', pe.(c.sc('interruptionCost' => 0)), nil],
        ['cost above max', pe.(c.sc('interruptionCost' => 501)), 'config_cost_above_max'],
        ['step 0', pe.(c.sc('tightenStepPpm' => 0)), nil], ['step at the cap', pe.(c.sc('tightenStepPpm' => 100_000_000)), nil],
        ['step above the cap', pe.(c.sc('tightenStepPpm' => 100_000_001)), 'config_step_invalid'], ['step -1', pe.(c.sc('tightenStepPpm' => -1)), 'config_step_invalid'],
        ['step 0.5', pe.(c.sc('tightenStepPpm' => 0.5)), 'config_step_invalid'], ['step str', pe.(c.sc('tightenStepPpm' => '5')), 'config_step_invalid'],
        ['step nil', pe.(c.sc('tightenStepPpm' => nil)), 'config_step_invalid'], ['step gone', pe.(c.sc('tightenStepPpm' => :del)), 'config_step_invalid'],
        ['step 2^53', pe.(c.sc('tightenStepPpm' => 2**53)), 'config_step_invalid'],
        ['signed by another key', pe.(c.sc({}, :other)), 'config_signature_invalid'], ['tampered', pe.(c.sc.merge('interruptionCost' => 101)), 'config_signature_invalid'],
        ['principal not base64', pe.(c.sc('principal' => 'zz!')), mal], ['sig not base64', pe.(c.sc.merge('sig' => 'zz!')), mal], ['sig int', pe.(c.sc.merge('sig' => 5)), mal],
        ['sig gone', pe.(c.sc.reject { |k, _| k == 'sig' }), mal], ['principal int', pe.(c.sc('principal' => 5)), mal],
        ['currency int, signed', pe.(c.sc('currency' => 5)), mal], ['currency nil, signed', pe.(c.sc('currency' => nil)), mal], ['currency gone', pe.(c.sc('currency' => :del)), mal],
        ['v 2', pe.(c.sc('v' => 2)), mal], ['v str', pe.(c.sc('v' => '1')), mal], ['v gone', pe.(c.sc('v' => :del)), mal],
        ['nil', pe.(nil), mal], ['list', pe.([]), mal], ['string', pe.('x'), mal], ['empty object', pe.({}), mal], ['duck of a valid config', pe.(C24::Duck.new(c.sc)), mal]
      ]
      %w[interruptionCost maxInterruptionCost hardCeilingLoss epoch].each do |k|
        [-1, 1.5, '1', nil].each { |v| rows << ["#{k}=#{v.inspect}", pe.(c.sc(k => v)), 'config_amounts_invalid'] }
        rows << ["#{k} gone", pe.(c.sc(k => :del)), 'config_amounts_invalid']
      end
      boom = Seam.with(AtlasPca, { k4_sig: ->(*_x) { raise 'boom' } }) { pe.(c.sc) }
      rows << ['a fault is malformed', boom, mal]
      c.ck(rows)
    end
  end

  t('c24 k4 decide_escalation: invalid config asks with its reason, input checks, calibration, ceiling (plain verify)') do
    next true if C24.skip?('k4.rb')

    C24.fast do
      c = C24
      de = ->(cfg, cal, a) { AtlasPca.decide_escalation(cfg, cal, a) }
      ask = ->(r) { { 'ask' => true, 'reason' => r } }
      cfg = c.sc
      cal = { 'multiplierPpm' => 1_000_000, 'seen' => [] }
      risk = { 'currency' => 'USD', 'loss' => 1, 'pBadUpperPpm' => 0 }
      within = { 'ask' => false, 'reason' => 'expected_loss_within_interruption_cost' }
      rows = [
        ['allowed', de.(cfg, cal, risk), within], ['bad signature asks with its reason', de.(c.sc({}, :other), cal, risk), ask.('config_signature_invalid')],
        ['nil config asks', de.(nil, cal, risk), ask.('config_malformed')], ['cost above max asks', de.(c.sc('interruptionCost' => 501), cal, risk), ask.('config_cost_above_max')],
        ['config error beats currency', de.(c.sc({}, :other), cal, risk.merge('currency' => 'EUR')), ask.('config_signature_invalid')],
        ['risk nil', de.(cfg, cal, nil), ask.('currency_mismatch')], ['risk a string', de.(cfg, cal, 'USD'), ask.('currency_mismatch')],
        ['risk a list', de.(cfg, cal, []), ask.('currency_mismatch')], ['other currency', de.(cfg, cal, risk.merge('currency' => 'EUR')), ask.('currency_mismatch')],
        ['loss 1.5', de.(cfg, cal, risk.merge('loss' => 1.5)), ask.('risk_input_invalid')], ['loss -1', de.(cfg, cal, risk.merge('loss' => -1)), ask.('risk_input_invalid')],
        ['loss nil', de.(cfg, cal, risk.merge('loss' => nil)), ask.('risk_input_invalid')], ['loss gone', de.(cfg, cal, risk.reject { |k, _| k == 'loss' }), ask.('risk_input_invalid')],
        ['p 0.5', de.(cfg, cal, risk.merge('pBadUpperPpm' => 0.5)), ask.('risk_input_invalid')], ['p str', de.(cfg, cal, risk.merge('pBadUpperPpm' => 'x')), ask.('risk_input_invalid')],
        ['p -1', de.(cfg, cal, risk.merge('pBadUpperPpm' => -1)), ask.('risk_input_invalid')],
        ['p above one', de.(cfg, cal, risk.merge('pBadUpperPpm' => 1_000_001)), ask.('risk_input_invalid')], ['p nil', de.(cfg, cal, risk.merge('pBadUpperPpm' => nil)), ask.('risk_input_invalid')],
        ['calibration nil', de.(cfg, nil, risk), ask.('calibration_invalid')], ['calibration a list', de.(cfg, [], risk), ask.('calibration_invalid')],
        ['calibration a string', de.(cfg, 'x', risk), ask.('calibration_invalid')], ['calibration empty', de.(cfg, {}, risk), ask.('calibration_invalid')],
        ['multiplier below one', de.(cfg, { 'multiplierPpm' => 999_999 }, risk), ask.('calibration_invalid')],
        ['multiplier above 100', de.(cfg, { 'multiplierPpm' => 100_000_001 }, risk), ask.('calibration_invalid')],
        ['multiplier float', de.(cfg, { 'multiplierPpm' => 1_500_000.0 }, risk), ask.('calibration_invalid')],
        ['multiplier at one', de.(cfg, { 'multiplierPpm' => 1_000_000 }, risk), within],
        ['multiplier at 100', de.(cfg, { 'multiplierPpm' => 100_000_000 }, risk), within],
        ['above the hard ceiling', de.(cfg, cal, risk.merge('loss' => 100_001)), ask.('above_hard_ceiling')],
        ['at the hard ceiling, p 0', de.(cfg, cal, risk.merge('loss' => 100_000)), within],
        ['expected loss at the cost: not asked', de.(cfg, cal, risk.merge('loss' => 1000, 'pBadUpperPpm' => 100_000)), within],
        ['expected loss over the cost: asked', de.(cfg, cal, risk.merge('loss' => 1001, 'pBadUpperPpm' => 100_000)), ask.('expected_loss_exceeds_interruption_cost')],
        ['multiplier tips it over', de.(cfg, { 'multiplierPpm' => 1_500_000 }, risk.merge('loss' => 1000, 'pBadUpperPpm' => 100_000)),
         ask.('expected_loss_exceeds_interruption_cost')]
      ]
      c.ck(rows)
    end
  end

  t('c24 k4 k4_answer_ok? / update_calibration: nonce length in UTF-16 units, strict fields, replay, unknown actions, no mutation of the input (plain verify)') do
    next true if C24.skip?('k4.rb')

    C24.fast do
      c = C24
      a = AtlasPca
      pr = c.pub(:pr)
      ok = ->(x) { a.k4_answer_ok?(x, pr) }
      rows = [
        ['valid', ok.(c.ans), true], ['nonce 7', ok.(c.ans('nonce' => 'nonce-1')), false], ['nonce 8', ok.(c.ans('nonce' => 'nonce-01')), true],
        ['nonce 4 astral = 8 units', ok.(c.ans('nonce' => "\u{1F600}" * 4)), true], ['nonce 3 astral = 6 units', ok.(c.ans('nonce' => "\u{1F600}" * 3)), false],
        ['nonce int', ok.(c.ans('nonce' => 12_345_678)), false], ['nonce nil', ok.(c.ans('nonce' => nil)), false],
        ['other principal', ok.(c.ans({ 'principal' => c.pub(:other) }, :other)), false], ['signed by another key', ok.(c.ans({}, :other)), false],
        ['v 2', ok.(c.ans('v' => 2)), false], ['answer maybe', ok.(c.ans('answer' => 'maybe')), false], ['answer nil', ok.(c.ans('answer' => nil)), false],
        ['approve', ok.(c.ans('answer' => 'approve')), true], ['action_digest int', ok.(c.ans('action_digest' => 5)), false],
        ['action_digest nil', ok.(c.ans('action_digest' => nil)), false], ['tampered', ok.(c.ans.merge('answer' => 'approve')), false],
        ['no sig', ok.(c.ans.reject { |k, _| k == 'sig' }), false], ['nil', ok.(nil), false], ['list', ok.([]), false], ['duck of a valid answer', ok.(C24::Duck.new(c.ans)), false]
      ]
      boom = Seam.with(a, { k4_sig: ->(*_x) { raise 'boom' } }) { ok.(c.ans) }
      rows << ['a fault is false', boom, false]
      wide = Seam.with(a, { utf16_len: ->(_s) { 100 } }) do
        [ok.(c.ans('nonce' => 12_345_678)), ok.(c.ans('nonce' => nil)), ok.(c.ans('nonce' => ['nonce-001'])), ok.(c.ans('nonce' => 'x'))]
      end
      rows << ['a non-string nonce is refused before its length is read', wide, [false, false, false, true]]

      cfg = c.sc
      cal0 = { 'multiplierPpm' => 1_000_000, 'seen' => [] }
      risks = { 'd1' => { 'currency' => 'USD', 'loss' => 1000, 'pBadUpperPpm' => 100_000 }, 'd2' => { 'currency' => 'USD', 'loss' => 100_000, 'pBadUpperPpm' => 1_000_000 },
                'd3' => { 'currency' => 'USD', 'loss' => 500, 'pBadUpperPpm' => 100_000 }, 'd4' => { 'currency' => 'USD', 'loss' => 1, 'pBadUpperPpm' => 0 } }
      uc = ->(config, cal, answers, rk = risks) { a.update_calibration(config, cal, answers, rk) }
      start = { 'multiplierPpm' => 1_000_000, 'seen' => [] }
      after = uc.(cfg, start, [c.ans])
      calls = []
      unknown = Seam.with(a, { decide_escalation: ->(*x) { calls << x; { 'ask' => true, 'reason' => 'spy' } } }) do
        uc.(cfg, { 'multiplierPpm' => 1_000_000, 'seen' => [] }, [c.ans('action_digest' => 'dX')])
      end
      rows.push(
        ['deny of an auto-approved action tightens', after, { 'multiplierPpm' => 1_500_000, 'seen' => ['nonce-001'] }],
        ['the input calibration is not modified', start, { 'multiplierPpm' => 1_000_000, 'seen' => [] }],
        ['invalid config returns the very same calibration (nil)', uc.(nil, cal0, [c.ans]).equal?(cal0), true],
        ['invalid config returns the very same calibration (bad signature)', uc.(c.sc({}, :other), cal0, [c.ans]).equal?(cal0), true],
        ['approve changes nothing but is recorded', uc.(cfg, cal0, [c.ans('answer' => 'approve')]), { 'multiplierPpm' => 1_000_000, 'seen' => ['nonce-001'] }],
        ['deny of an unknown action: recorded, nothing decided', unknown, { 'multiplierPpm' => 1_000_000, 'seen' => ['nonce-001'] }],
        ['the escalation decision is never consulted for an unknown action', calls, []],
        ['deny of an already-asked action changes nothing', uc.(cfg, cal0, [c.ans('action_digest' => 'd2')]), { 'multiplierPpm' => 1_000_000, 'seen' => ['nonce-001'] }],
        ['replayed nonce counts once', uc.(cfg, cal0, [c.ans, c.ans]), { 'multiplierPpm' => 1_500_000, 'seen' => ['nonce-001'] }],
        ['a seen nonce is not counted again', uc.(cfg, { 'multiplierPpm' => 1_000_000, 'seen' => ['nonce-001'] }, [c.ans]), { 'multiplierPpm' => 1_000_000, 'seen' => ['nonce-001'] }],
        ['two distinct denies step twice', uc.(cfg, cal0, [c.ans, c.ans('nonce' => 'nonce-002', 'action_digest' => 'd3')]), { 'multiplierPpm' => 2_000_000, 'seen' => %w[nonce-001 nonce-002] }],
        ['short nonce ignored', uc.(cfg, cal0, [c.ans('nonce' => 'nonce-1')]), cal0],
        ['forged answer ignored', uc.(cfg, cal0, [c.ans({}, :other)]), cal0],
        ['answer for another principal ignored', uc.(cfg, cal0, [c.ans({ 'principal' => c.pub(:other) }, :other)]), cal0],
        ['non-string action digest ignored', uc.(cfg, cal0, [c.ans('action_digest' => 5)]), cal0],
        ['unknown answer ignored', uc.(cfg, cal0, [c.ans('answer' => 'maybe')]), cal0],
        ['multiplier cap', uc.(cfg, { 'multiplierPpm' => 99_800_000, 'seen' => [] }, [c.ans('action_digest' => 'd4')]), { 'multiplierPpm' => 100_000_000, 'seen' => ['nonce-001'] }]
      )
      c.ck(rows)
    end
  end

  # ================================================================================================================ K4: network token binding
  t('c24 k4 verify_network_token_binding: shape, token_ref, provider, equality checks, base64, proof, fault (plain verify)') do
    next true if C24.skip?('k4.rb')

    C24.fast do
      c = C24
      a = AtlasPca
      grant = { 'g' => 1 }
      holder = c.pub(:wallet)
      nonce = 'n-123456789'
      body = ->(over = {}) do
        c.mrg({ 'kind' => 'pca.network_token_binding', 'v' => 1, 'provider' => 'visa', 'token_ref' => 'tok_abcdef12', 'grant_digest' => a.hash_canonical(grant),
                'issuer_nonce' => nonce, 'holder' => holder }, over)
      end
      bind = lambda do |over = {}|
        bd = body.(over)
        bd.merge('binding_proof' => a.b64e(c.key(:wallet).sign(nil, a.hash_canonical(bd).b)))
      end
      vb = ->(b, h = holder, g = grant, n = nonce, p = nil) { a.verify_network_token_binding(b, g, h, n, p) }
      rows = [
        ['valid', vb.(bind.()), nil], ['valid, provider asked', vb.(bind.(), holder, grant, nonce, 'visa'), nil],
        ['wrong provider', vb.(bind.(), holder, grant, nonce, 'mc'), 'provider_mismatch'],
        ['provider nil', vb.(bind.('provider' => nil)), 'provider_mismatch'], ['provider int', vb.(bind.('provider' => 5)), 'provider_mismatch'],
        ['provider empty', vb.(bind.('provider' => '')), 'provider_mismatch'], ['provider gone', vb.(bind.('provider' => :del)), 'provider_mismatch'],
        ['other grant', vb.(bind.(), holder, { 'g' => 2 }), 'grant_digest_mismatch'], ['other holder', vb.(bind.(), c.pub(:other)), 'holder_mismatch'],
        ['other nonce', vb.(bind.(), holder, grant, 'zzz'), 'issuer_nonce_mismatch'],
        ['proof flipped', vb.(bind.().merge('binding_proof' => c.sign('x', { 'y' => 1 }, :wallet))), 'binding_proof_invalid'],
        ['token_ref changed after signing', vb.(bind.().merge('token_ref' => 'tok_zzzzzz99')), 'binding_proof_invalid'],
        ['wrong kind', vb.(bind.('kind' => 'x')), 'binding_malformed'], ['kind gone', vb.(bind.('kind' => :del)), 'binding_malformed'],
        ['nil', vb.(nil), 'binding_malformed'], ['list', vb.([]), 'binding_malformed'], ['string', vb.('pca.network_token_binding'), 'binding_malformed'],
        ['duck of a valid binding', vb.(C24::Duck.new(bind.())), 'binding_malformed'],
        ['token_ref nil', vb.(bind.('token_ref' => nil)), 'token_ref_malformed'], ['token_ref int', vb.(bind.('token_ref' => 12_345_678)), 'token_ref_malformed'],
        ['token_ref short', vb.(bind.('token_ref' => 'abc')), 'token_ref_malformed'], ['token_ref a PAN', vb.(bind.('token_ref' => '4111111111111111')), 'token_ref_looks_like_pan'],
        ['token_ref Luhn-invalid digits', vb.(bind.('token_ref' => '4111111111111112')), nil],
        ['holder not base64', vb.(bind.('holder' => 'zz!'), 'zz!'), 'binding_malformed'],
        ['proof not base64', vb.(bind.().merge('binding_proof' => 'zz!')), 'binding_malformed'],
        ['proof gone', vb.(bind.().reject { |k, _| k == 'binding_proof' }), 'binding_proof_invalid'],
        ['holder nil on both sides: decoded as empty, then the proof fails', vb.(bind.('holder' => nil), nil), 'binding_proof_invalid'],
        ['grant that cannot be hashed', vb.(bind.(), holder, Object.new), 'binding_malformed']
      ]
      seen = []
      Seam.with(a, { verify_b64u: ->(_p, m, _s) { seen << m; true } }) { vb.(bind.()) }
      want_msg = a.hash_canonical(body.())
      rows << ['the signed message is the BINARY digest string', seen.map { |m| [m.encoding, m.bytes] }, [[Encoding::BINARY, want_msg.bytes]]]
      c.ck(rows)
    end
  end

  # ================================================================================================================ K4: ERC-7715
  t('c24 k4 verify_granted_permission: every refusal reason, case-insensitive compares, expiry rules, faults') do
    next true if C24.skip?('k4.rb')

    c = C24
    a = AtlasPca
    g = { 'grantDigest' => 'gd1', 'expiresAtSec' => 1800 }
    mgr = "0x#{'ab' * 20}"
    sent0 = { 'chainId' => '0x2105', 'to' => "0x#{'11' * 20}", 'permission' => { 'type' => 'erc20-token-allowance', 'isAdjustmentAllowed' => true,
                                                                                     'data' => { 'tokenAddress' => "0x#{'2a' * 20}", 'allowance' => '0x989680' } },
              'rules' => [{ 'type' => 'expiry', 'data' => { 'timestamp' => 1800 } }] }
    got0 = sent0.merge('context' => '0xabc123', 'dependencies' => [], 'delegationManager' => mgr)
    owner = ->(k) { { '0xabc123' => 'gd1' }[k] }
    run = lambda do |sent: nil, got: nil, got_obj: :none, allowed: [mgr], own: owner, five: true, grant: g|
      s = c.deep(sent0)
      r = got_obj == :none ? c.deep(got0) : got_obj
      sent&.call(s)
      got&.call(r) if got_obj == :none
      five ? a.verify_granted_permission(grant, s, r, allowed, own) : a.verify_granted_permission(grant, s, r, allowed)
    end
    rows = [
      ['as requested', run.(), nil], ['no context_owner argument', run.(five: false), nil], ['context owner unknown', run.(own: ->(_k) { nil }), nil],
      ['context bound to another grant', run.(own: ->(_k) { 'gd9' }), 'context_bound_to_other_grant'],
      ['response nil', run.(got_obj: nil), 'response_malformed'], ['response a list', run.(got_obj: []), 'response_malformed'],
      ['response a duck of a valid one', run.(got_obj: C24::Duck.new(c.deep(got0))), 'response_malformed'],
      ['permission nil', run.(got: ->(r) { r['permission'] = nil }), 'response_malformed'],
      ['permission a string', run.(got: ->(r) { r['permission'] = 'abc' }), 'response_malformed'],
      ['permission a list', run.(got: ->(r) { r['permission'] = [] }), 'response_malformed'],
      ['permission a duck', run.(got: ->(r) { r['permission'] = C24::Duck.new(r['permission']) }), 'response_malformed'],
      ['context nil', run.(got: ->(r) { r['context'] = nil }), 'context_malformed'], ['context int', run.(got: ->(r) { r['context'] = 5 }), 'context_malformed'],
      ['context not hex', run.(got: ->(r) { r['context'] = 'abc' }), 'context_malformed'], ['context 0x only', run.(got: ->(r) { r['context'] = '0x' }), 'context_malformed'],
      ['context uppercase hex', run.(got: ->(r) { r['context'] = '0xABC123' }, own: ->(_k) { nil }), nil],
      ['manager nil', run.(got: ->(r) { r['delegationManager'] = nil }), 'delegation_manager_not_allowed'],
      ['manager int', run.(got: ->(r) { r['delegationManager'] = 5 }), 'delegation_manager_not_allowed'],
      ['manager not an address but listed', run.(got: ->(r) { r['delegationManager'] = 'zzz' }, allowed: ['zzz']), 'delegation_manager_not_allowed'],
      ['manager one nibble short but listed', run.(got: ->(r) { r['delegationManager'] = mgr[0...-1] }, allowed: [mgr[0...-1]]), 'delegation_manager_not_allowed'],
      ['manager not listed', run.(allowed: ["0x#{'cd' * 20}"]), 'delegation_manager_not_allowed'], ['no managers', run.(allowed: []), 'delegation_manager_not_allowed'],
      ['listed in uppercase', run.(allowed: ["0x#{'AB' * 20}"]), nil], ['returned in uppercase', run.(got: ->(r) { r['delegationManager'] = "0x#{'AB' * 20}" }), nil],
      ['chain upper-case X', run.(got: ->(r) { r['chainId'] = '0X2105' }), nil], ['chain other', run.(got: ->(r) { r['chainId'] = '0x1' }), 'chain_mismatch'],
      ['chain missing in the response', run.(got: ->(r) { r.delete('chainId') }), 'chain_mismatch'],
      ['chain missing on both sides', run.(sent: ->(s) { s.delete('chainId') }, got: ->(r) { r.delete('chainId') }), nil],
      ['recipient other', run.(got: ->(r) { r['to'] = "0x#{'12' * 20}" }), 'recipient_mismatch'],
      ['recipient in uppercase', run.(sent: ->(s) { s['to'] = "0x#{'1a' * 20}" }, got: ->(r) { r['to'] = "0x#{'1A' * 20}" }), nil],
      ['from requested and equal in another case', run.(sent: ->(s) { s['from'] = "0x#{'aa' * 20}" }, got: ->(r) { r['from'] = "0x#{'AA' * 20}" }), nil],
      ['from requested and different', run.(sent: ->(s) { s['from'] = "0x#{'aa' * 20}" }, got: ->(r) { r['from'] = "0x#{'bb' * 20}" }), 'from_mismatch'],
      ['from requested and missing', run.(sent: ->(s) { s['from'] = "0x#{'aa' * 20}" }), 'from_mismatch'],
      ['from not requested, response names one', run.(got: ->(r) { r['from'] = "0x#{'bb' * 20}" }), nil],
      ['type changed', run.(got: ->(r) { r['permission']['type'] = 'native-token-allowance' }), 'permission_type_mismatch'],
      ['type not allowed on both sides', run.(sent: ->(s) { s['permission']['type'] = 'foo' }, got: ->(r) { r['permission']['type'] = 'foo' }), 'permission_type_mismatch'],
      ['native on both sides', run.(sent: ->(s) { s['permission']['type'] = 'native-token-allowance' }, got: ->(r) { r['permission']['type'] = 'native-token-allowance' }), nil],
      ['data nil', run.(got: ->(r) { r['permission']['data'] = nil }), 'response_malformed'], ['data a string', run.(got: ->(r) { r['permission']['data'] = 'abc' }), 'response_malformed'],
      ['data a list', run.(got: ->(r) { r['permission']['data'] = [] }), 'response_malformed'],
      ['token in uppercase', run.(got: ->(r) { r['permission']['data']['tokenAddress'] = "0x#{'2A' * 20}" }), nil],
      ['sent token in uppercase', run.(sent: ->(s) { s['permission']['data']['tokenAddress'] = "0x#{'2A' * 20}" }), nil],
      ['token other', run.(got: ->(r) { r['permission']['data']['tokenAddress'] = "0x#{'33' * 20}" }), 'token_mismatch'],
      ['token an int in the response', run.(got: ->(r) { r['permission']['data']['tokenAddress'] = 5 }), 'token_mismatch'],
      ['token an int on both sides', run.(sent: ->(s) { s['permission']['data']['tokenAddress'] = 5 }, got: ->(r) { r['permission']['data']['tokenAddress'] = 5 }), nil],
      ['token absent on both sides', run.(sent: ->(s) { s['permission']['data'].delete('tokenAddress') }, got: ->(r) { r['permission']['data'].delete('tokenAddress') }), nil],
      ['allowance nil', run.(got: ->(r) { r['permission']['data']['allowance'] = nil }), 'amount_malformed'],
      ['allowance int', run.(got: ->(r) { r['permission']['data']['allowance'] = 5 }), 'amount_malformed'],
      ['allowance 0x only', run.(got: ->(r) { r['permission']['data']['allowance'] = '0x' }), 'amount_malformed'],
      ['allowance leading zero', run.(got: ->(r) { r['permission']['data']['allowance'] = '0x01' }), 'amount_malformed'],
      ['allowance upper X', run.(got: ->(r) { r['permission']['data']['allowance'] = '0X10' }), 'amount_malformed'],
      ['allowance not hex', run.(got: ->(r) { r['permission']['data']['allowance'] = '10' }), 'amount_malformed'],
      ['allowance zero', run.(got: ->(r) { r['permission']['data']['allowance'] = '0x0' }), nil],
      ['allowance lowered', run.(got: ->(r) { r['permission']['data']['allowance'] = '0x1' }), nil],
      ['allowance one over', run.(got: ->(r) { r['permission']['data']['allowance'] = '0x989681' }), 'amount_widened'],
      ['allowance in uppercase digits, equal', run.(sent: ->(s) { s['permission']['data']['allowance'] = '0xFF' }, got: ->(r) { r['permission']['data']['allowance'] = '0xff' }), nil],
      ['sent allowance missing is a fault', run.(sent: ->(s) { s['permission']['data'].delete('allowance') }), 'response_malformed'],
      ['adjustment turned on', run.(sent: ->(s) { s['permission']['isAdjustmentAllowed'] = false }), 'adjustment_widened'],
      ['adjustment turned on from absent', run.(sent: ->(s) { s['permission'].delete('isAdjustmentAllowed') }), 'adjustment_widened'],
      ['adjustment turned off', run.(got: ->(r) { r['permission']['isAdjustmentAllowed'] = false }), nil],
      ['rules nil', run.(got: ->(r) { r['rules'] = nil }), 'expiry_missing'], ['rules an object with entries', run.(got: ->(r) { r['rules'] = { 'a' => 1 } }), 'expiry_missing'],
      ['rules a string', run.(got: ->(r) { r['rules'] = 'x' }), 'expiry_missing'], ['rules empty', run.(got: ->(r) { r['rules'] = [] }), 'expiry_missing'],
      ['rule nil', run.(got: ->(r) { r['rules'] = [nil] }), 'unknown_rule_type'], ['rule int', run.(got: ->(r) { r['rules'] = [5] }), 'unknown_rule_type'],
      ['rule other type', run.(got: ->(r) { r['rules'] = [{ 'type' => 'x' }] }), 'unknown_rule_type'],
      ['rule a string', run.(got: ->(r) { r['rules'] = ['expiry'] }), 'unknown_rule_type'],
      ['rule a duck', run.(got: ->(r) { r['rules'] = [C24::Duck.new({ 'type' => 'expiry', 'data' => { 'timestamp' => 1 } })] }), 'unknown_rule_type'],
      ['two expiries', run.(got: ->(r) { r['rules'] = [r['rules'][0], r['rules'][0]] }), 'duplicate_expiry'],
      ['expiry data int', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => 5 }] }), 'expiry_malformed'],
      ['expiry data nil', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => nil }] }), 'expiry_malformed'],
      ['expiry data a list', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => [] }] }), 'expiry_malformed'],
      ['expiry data empty', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => {} }] }), 'expiry_malformed'],
      ['expiry a string', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => { 'timestamp' => '5' } }] }), 'expiry_malformed'],
      ['expiry a float', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => { 'timestamp' => 1.5 } }] }), 'expiry_malformed'],
      ['expiry nil', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => { 'timestamp' => nil } }] }), 'expiry_malformed'],
      ['expiry earlier', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => { 'timestamp' => 1799 } }] }), nil],
      ['expiry negative', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => { 'timestamp' => -1 } }] }), nil],
      ['expiry one later', run.(got: ->(r) { r['rules'] = [{ 'type' => 'expiry', 'data' => { 'timestamp' => 1801 } }] }), 'expiry_extended']
    ]
    c.ck(rows)
  end

  # ================================================================================================================ K4: shared vectors
  t('c24 k4 shared vectors (k4-vectors.json) reproduce their expect exactly (plain verify)') do
    next true if C24.skip?('k4.rb')

    raise 'k4-vectors.json missing' if C24_VEC4.nil?

    C24.fast do
      a = AtlasPca
      doc = C24_VEC4
      bad = []
      chk = ->(label, want, got) { bad << "#{label}: got #{got.inspect[0, 100]}" unless want == got }
      doc['escalation']['config_cases'].each { |cs| chk.(cs['name'], cs['expect'], a.pricing_config_error(cs['config'])) }
      doc['escalation']['decisions'].each { |cs| chk.(cs['risk'].to_s, cs['expect'], a.decide_escalation(doc['escalation']['config'], cs['calibration'], cs['risk'])) }
      doc['escalation']['calibration'].each { |cs| chk.(cs['name'], cs['expect'], a.update_calibration(cs['config'], cs['start'], cs['answers'], cs['risks'])) }
      doc['network_binding']['cases'].each do |cs|
        e = cs['expect_in']
        chk.(cs['name'], cs['expect'], a.verify_network_token_binding(cs['binding'], e['grant'], e['holder'], e['issuer_nonce'], e['provider']))
      end
      doc['erc7715']['cases'].each do |cs|
        ctx = cs['opts']['contexts'] || {}
        chk.(cs['name'], cs['expect'], a.verify_granted_permission(cs['envelope'], cs['sent'], cs['got'], cs['opts']['allowedManagers'], ->(k) { ctx[k] }))
      end
      raise "k4 vectors: #{bad.first(4).join(' | ')}" unless bad.empty?

      true
    end
  end
end
