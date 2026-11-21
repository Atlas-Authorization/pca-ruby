# frozen_string_literal: true

# Exact-outcome kill tests for lib/atlas_pca/attest/amd.rb (AMD SEV-SNP report verifier) and lib/atlas_pca/attest/azure.rb (Microsoft Azure
# Attestation JWT verifier). Reference: packages/pca/src/attest-amd-snp.ts, hardware-sevsnp.ts and attest-azure-maa.ts; the shared rows of
# packages/pca/conformance/attestation-evidence-vectors.json drive the end-to-end cases (exact internal result hashes, not only the verifier
# verdict), seams (kill/bi_seams.rb) pin the checks no honest input reaches. AtlasPca is dropped and re-evaluated for every mutant, so every
# module is resolved at CALL time and nothing from the library is captured at load.
require 'timeout'
require 'tmpdir'
require 'fileutils'
require 'json'
require 'base64'
require 'digest'
require 'openssl'
require 'rbconfig'
require 'atlas_pca/attest'

module MutationKill
  module C09
    LIB = File.expand_path('../../lib', __dir__)
    CONF = File.expand_path('../../conformance', __dir__)
    NOW = 1_700_000_000_000
    NOW_SEC = 1_700_000_000
    BIND = { 'holderPub' => 'h', 'grantRef' => 'g', 'epoch' => 1, 'nonce' => 'n' }.freeze

    module_function

    def att = AtlasPca::Attest
    def amd = AtlasPca::Attest::Amd
    def az = AtlasPca::Attest::Azure
    def cm = AtlasPca::Attest::Common
    def der = AtlasPca::Attest::Der

    # the oracle exports MUT_FILE (basename of the mutated file); run_kill.rb leaves it unset
    def skip?(*names) = (f = ENV['MUT_FILE']) && !f.empty? && !names.include?(f)
    def mutating? = (f = ENV['MUT_FILE']) && !f.empty?

    def err
      yield
      nil
    rescue Exception => e # rubocop:disable Lint/RescueException
      [e.class, e.message]
    end

    def tm(&) = Timeout.timeout(5, &)

    def same?(got, want)
      case want
      when Hash then got.is_a?(Hash) && got.size == want.size && want.all? { |k, v| got.key?(k) && same?(got[k], v) }
      when Array then got.is_a?(Array) && got.size == want.size && got.zip(want).all? { |g, w| same?(g, w) }
      else got.class == want.class && got == want
      end
    end

    # rows: [label, got, want]
    def chk(rows)
      bad = rows.reject { |_l, got, want| same?(got, want) }
      return true if bad.empty?

      raise "mismatch: #{bad.first(4).map { |l, g, w| "#{l}: got #{g.inspect[0, 300]} want #{w.inspect[0, 300]}" }.join(' | ')}"
    end

    def msg_err = Class.new(StandardError) { def message = 'MSG'; def to_s = 'TOS' }
    def msg_js = Class.new(AtlasPca::Attest::JsTypeError) { def message = 'JM'; def to_s = 'JT' }
    def msg_der = Class.new(AtlasPca::Attest::DerError) { def message = 'DM'; def to_s = 'DT' }

    def b64u(s) = Base64.urlsafe_encode64(s, padding: false)
    def hex(s) = s.unpack1('H*')

    # ---- a fresh Ruby that loads the library with only the file under mutation replaced
    def source(rel)
      path = File.join(LIB, rel)
      if defined?(::Oracle) && (tgt = ::Oracle.instance_variable_get(:@target)) && File.expand_path(tgt) == path
        ::Oracle.instance_variable_get(:@text)
      else
        File.read(path)
      end
    end

    def header_changed?(rel, nlines) = source(rel).lines.first(nlines) != File.read(File.join(LIB, rel)).lines.first(nlines)

    def fresh(rel, code)
      Dir.mktmpdir('c09fresh') do |d|
        FileUtils.cp_r(LIB, d)
        File.write(File.join(d, 'lib', rel), source(rel))
        gems = Gem.loaded_specs.values.flat_map(&:full_require_paths).flat_map { |g| ['-I', g] }
        out = IO.popen([RbConfig.ruby, '--disable-gems', '-I', File.join(d, 'lib'), *gems, '-e', code], 'r', err: File::NULL, &:read)
        [out, $?.success?]
      end
    end

    # ---- the shared vector rows
    def doc
      @doc ||= JSON.parse(File.read(File.join(ENV['PCA_CONFORMANCE_DIR'] || CONF, 'attestation-evidence-vectors.json'), encoding: 'UTF-8'))
    end

    def hydrate(x, b)
      case x
      when Array then x.map { |e| hydrate(e, b) }
      when Hash then x.keys == ['$blob'] ? b.fetch(x['$blob']) : x.to_h { |k, v| [k, hydrate(v, b)] }
      else x
      end
    end

    def rows(vendor)
      @rows ||= {}
      @rows[vendor] ||= doc['attestation_vectors'].select { |r| r['vendor'] == vendor }.map { |r| hydrate(r, doc['blobs']) }
    end

    def row(vendor, id) = rows(vendor).find { |r| r['id'] == id }

    # the unwrapped AmdSnpVerifier of a row (with the conformance ARK override applied, as run_attestation_vector does) and its evidence
    def amd_ctx(r)
      ev = att.evidence_for('amd-sev-snp', r['evidence'])
      v = att.verifier_from_config('amd-sev-snp', r['config'], ->(_d) { r['evidence'] })
      inner = v.is_a?(att::WithIdentity) ? v.instance_variable_get(:@inner) : v
      pin = r['config']['trustAnchorArkSpkiSha384']
      inner.instance_variable_set(:@pin, pin) unless pin.nil?
      { ev: ev, pin: inner.instance_variable_get(:@pin), skew: inner.instance_variable_get(:@skew), policy: inner.instance_variable_get(:@policy),
        direct: inner.instance_variable_get(:@binding) == 'report-data', expected: r['expected_binding'], now: r['now'] }
    end

    AZ_BIND_REASONS = ['report_data is not 64 bytes', 'report_data[32:64] is not zero (not an Azure runtime-data hash)',
                       'sha256(runtime data) does not equal the quote report_data', 'runtime data is not valid JSON', 'runtime data is not a JSON object',
                       'runtime data carries no 64-byte hex user-data',
                       'runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)'].freeze

    # one row per distinct reason (the first), so the walk stays a few dozen verifications
    def amd_curated
      @amd_curated ||= begin
        seen = {}
        rows('amd-sev-snp').select do |r|
          e = r['expect']
          next false if e['construct_error']

          key = e['ok'] ? "ok-#{r['config']['binding']}" : (e['reason'] || '')[0, 70]
          next false if seen[key]

          seen[key] = true
        end
      end
    end

    # key for 'want' of a stored reason: [prefix?, text]
    def want_reason(e, strip)
      return [true, e['reason_prefix'].delete_prefix(strip)] if e['reason_match'] == 'prefix'

      [false, e['reason'].delete_prefix(strip)]
    end

    def hash_fail?(got, want)
      pre, text = want
      got.is_a?(Hash) && got.keys.sort == %w[ok reason] && got['ok'].equal?(false) && got['reason'].is_a?(String) &&
        (pre ? got['reason'].start_with?(text) : got['reason'] == text)
    end

    # ---- generated X.509 (data only: no library constant is captured)
    def pki_key(name)
      @keys ||= {}
      @keys[name] ||= OpenSSL::PKey::EC.generate('prime256v1')
    end

    def pki_cert(cn, key, issuer: nil, issuer_key: nil)
      c = OpenSSL::X509::Certificate.new
      c.version = 2
      c.serial = 1
      c.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
      c.issuer = issuer ? issuer.subject : c.subject
      c.public_key = key
      c.not_before = Time.at(1_600_000_000)
      c.not_after = Time.at(2_000_000_000)
      c.sign(issuer_key || key, OpenSSL::Digest.new('SHA256'))
      c
    end

    def pki
      @pki ||= begin
        root = pki_cert('root', pki_key('root'))
        mid = pki_cert('mid', pki_key('mid'), issuer: root, issuer_key: pki_key('root'))
        leaf = pki_cert('leaf', pki_key('leaf'), issuer: mid, issuer_key: pki_key('mid'))
        leaf_bad = pki_cert('leaf', pki_key('leaf'), issuer: mid, issuer_key: pki_key('rogue'))
        mid_bad = pki_cert('mid', pki_key('mid'), issuer: root, issuer_key: pki_key('rogue'))
        root2 = pki_cert('root2', pki_key('root2'))
        top = pki_cert('top', pki_key('top'), issuer: root2, issuer_key: pki_key('root2'))
        { top: top, root: root, mid: mid, leaf: leaf, leaf_bad: leaf_bad, mid_bad: mid_bad, root2: root2 }
      end
    end

    def x5c(*names) = names.map { |n| [pki.fetch(n).to_der].pack('m0') }
    def spki(name) = OpenSSL::Digest.new('SHA256').hexdigest(OpenSSL::X509::Certificate.new(pki.fetch(name).to_der).public_key.public_to_der)
  end

  # ============================================================================================================ loading
  t('amd.rb / azure.rb require what they use: cert (and so common, der) is loaded by each alone (fresh ruby over the mutated text)') do
    next true if C09.skip?('amd.rb', 'azure.rb')

    [['atlas_pca/attest/amd.rb', 'amd'], ['atlas_pca/attest/azure.rb', 'azure']].all? do |rel, name|
      next true if C09.mutating? && !C09.header_changed?(rel, 12)

      out, ok = C09.fresh(rel, "require 'atlas_pca/attest/#{name}'; puts $LOADED_FEATURES.filter_map { |f| f[%r{/lib/(atlas_pca/.*)}, 1] }")
      want = %w[common der cert].map { |n| "atlas_pca/attest/#{n}.rb" } + ["atlas_pca/attest/#{name}.rb"]
      ok && out == "#{want.join("\n")}\n"
    end
  end

  # ============================================================================================================ AMD constants
  t('amd: suite, pins, layout offsets and OIDs are exactly the reference values') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    pins = a::ARK_SPKI_SHA384
    C09.chk([
      ['suite', a::SUITE, 'amd-sev-snp-ecdsa-p384'],
      ['pins keys', pins.keys, %w[milan genoa turin]],
      ['pins frozen', pins.frozen?, true],
      ['pins shape', pins.values.all? { |v| v.is_a?(String) && v.match?(/\A[0-9a-f]{96}\z/) }, true],
      ['milan', pins['milan'], '1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e'],
      ['n', a::P384_N, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973],
      ['debug bit', a::POLICY_DEBUG_BIT, 524_288],
      ['offsets', [a::VERSION, a::GUEST_SVN, a::POLICY, a::VMPL, a::SIGNATURE_ALGO, a::CURRENT_TCB, a::REPORT_DATA, a::MEASUREMENT, a::HOST_DATA,
                   a::REPORTED_TCB, a::CHIP_ID, a::COMMITTED_TCB, a::LAUNCH_TCB, a::SIGNED_END, a::SIG_R, a::SIG_S, a::REPORT_LEN],
       [0, 4, 8, 48, 52, 56, 80, 144, 192, 384, 416, 480, 496, 672, 672, 744, 1184]],
      ['oids', [a::OID_HWID, a::OID_BL_SPL, a::OID_TEE_SPL, a::OID_SNP_SPL, a::OID_UCODE_SPL, a::HWID_LEN],
       ['1.3.6.1.4.1.3704.1.4', '1.3.6.1.4.1.3704.1.3.1', '1.3.6.1.4.1.3704.1.3.2', '1.3.6.1.4.1.3704.1.3.3', '1.3.6.1.4.1.3704.1.3.8', 64]]
    ])
  end

  # ============================================================================================================ AMD parse
  t('amd parse_sev_snp_report: every field at its offset, binary slices, the exact minimum length') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    buf = Array.new(1184) { |i| ((i * 31) + 7) & 0xFF }.pack('C*')
    want = { 'version' => buf[0, 4].unpack1('V'), 'guest_svn' => buf[4, 4].unpack1('V'), 'policy' => buf[8, 8].unpack1('Q<'),
             'vmpl' => buf[48, 4].unpack1('V'), 'signature_algo' => buf[52, 4].unpack1('V'), 'current_tcb' => buf[56, 8].unpack1('Q<'),
             'report_data' => buf[80, 64], 'measurement' => buf[144, 48], 'host_data' => buf[192, 32], 'reported_tcb' => buf[384, 8].unpack1('Q<'),
             'chip_id' => buf[416, 64], 'committed_tcb' => buf[480, 8].unpack1('Q<'), 'launch_tcb' => buf[496, 8].unpack1('Q<'),
             'sig_r' => buf[672, 72], 'sig_s' => buf[744, 72], 'signed' => buf[0, 672] }
    utf = buf.dup.force_encoding('UTF-8')
    got = a.parse_sev_snp_report(utf)
    short = buf[0, 816]
    C09.chk([
      ['full', got, want],
      ['binary', got.select { |_k, v| v.is_a?(String) }.values.map(&:encoding).uniq, [Encoding::BINARY]],
      ['input untouched', utf.encoding, Encoding::UTF_8],
      ['816 parses', a.parse_sev_snp_report(short)['sig_s'], buf[744, 72]],
      ['815 refused', C09.err { a.parse_sev_snp_report(buf[0, 815]) }, [ArgumentError, 'parseSevSnpReport: report too short (815 < 816)']],
      ['0 refused', C09.err { a.parse_sev_snp_report(''.b) }, [ArgumentError, 'parseSevSnpReport: report too short (0 < 816)']],
      ['u32', a.u32("\x01\x02\x03\x04\x05".b, 1), 0x05040302],
      ['u64', a.u64("\x00\x01\x02\x03\x04\x05\x06\x07\x08".b, 1), 0x0807060504030201],
      ['le_int', [a.le_int("\x01\x02".b), a.le_int("\x00".b * 3)], [0x0201, 0]]
    ])
  end

  # ============================================================================================================ AMD signature
  t('amd verify_sev_snp_report_signature: r and s must be in [1, n-1] (the verifier is called only for those), never raises') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    cm = C09.cm
    n = a::P384_N
    le = ->(v) { [v.to_s(16).rjust(144, '0')].pack('H*').reverse }
    rep = ->(r, s) { { 'sig_r' => le.call(r), 'sig_s' => le.call(s), 'signed' => 'SIGNED'.b } }
    calls = []
    spy = ->(key, der, data, h) { calls << [key, der, data, h]; true }
    rows = []
    MutationKill::Seam.with(cm, { ecdsa_verify_der: spy }) do
      [[1, 1, true], [n - 1, n - 1, true], [2, n - 1, true], [0, 1, false], [1, 0, false], [n, 1, false], [1, n, false], [n + 1, 1, false],
       [1, n + 1, false], [0, 0, false], [n, n, false]].each do |r, s, want|
        rows << ["r=#{r} s=#{s}", a.verify_sev_snp_report_signature(rep.call(r, s), :key), want]
      end
    end
    seq = ->(r, s) { OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der }
    rows << ['only accepted pairs reach the verifier', calls.map { |c| c[1] }, [seq.call(1, 1), seq.call(n - 1, n - 1), seq.call(2, n - 1)]]
    rows << ['verifier args', calls[0], [:key, seq.call(1, 1), 'SIGNED'.b, 'sha384']]
    MutationKill::Seam.with(cm, { ecdsa_verify_der: ->(*) { raise 'boom' } }) do
      rows << ['a fault is false', a.verify_sev_snp_report_signature(rep.call(1, 1), :key), false]
    end
    MutationKill::Seam.with(cm, { ecdsa_verify_der: ->(*) { false } }) do
      rows << ['verifier false', a.verify_sev_snp_report_signature(rep.call(1, 1), :key), false]
    end
    rows << ['malformed report', a.verify_sev_snp_report_signature({}, :key), false]
    C09.chk(rows)
  end

  # ============================================================================================================ AMD decode_spl
  t('amd decode_spl: one minimally encoded DER INTEGER 0..255, each failure its own text') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    d = ->(s) { a.decode_spl(s.b) }
    C09.chk([
      ['empty', d.call(''), 'is not a DER INTEGER'],
      ['two bytes', d.call("\x02\x01"), 'is not a DER INTEGER'],
      ['wrong tag', d.call("\x03\x01\x05"), 'is not a DER INTEGER'],
      ['len 0', d.call("\x02\x00\x05"), 'has a wrong-length INTEGER'],
      ['len 3', d.call("\x02\x03\x00\x00\x01"), 'has a wrong-length INTEGER'],
      ['len 3 negative lead', d.call("\x02\x03\xAA\xBB\xCC"), 'has a wrong-length INTEGER'],
      ['len mismatch', d.call("\x02\x01\x05\x06"), 'has a wrong-length INTEGER'],
      ['len 2 short', d.call("\x02\x02\x05"), 'has a wrong-length INTEGER'],
      ['negative', d.call("\x02\x01\x80"), 'is negative'],
      ['negative 2', d.call("\x02\x02\x80\x01"), 'is negative'],
      ['out of range', d.call("\x02\x02\x01\x80"), 'is out of range (> 255)'],
      ['non minimal', d.call("\x02\x02\x00\x7f"), 'is a non-minimal INTEGER'],
      ['non minimal 0', d.call("\x02\x02\x00\x00"), 'is a non-minimal INTEGER'],
      ['128', d.call("\x02\x02\x00\x80"), 128],
      ['255', d.call("\x02\x02\x00\xff"), 255],
      ['0', d.call("\x02\x01\x00"), 0],
      ['127', d.call("\x02\x01\x7f"), 127]
    ])
  end

  # ============================================================================================================ AMD VCEK binding
  t('amd check_vcek_report_binding: hwID and the four SPL extensions, each failure its own text') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    ce = ->(crit, val) { C09.der::CertExtension.new(crit, val.b) }
    chip = (0...64).to_a.pack('C*')
    t_val = 3 | (5 << 8) | (7 << 48) | (11 << 56)
    report = { 'chip_id' => chip, 'reported_tcb' => t_val }
    spl = ->(v) { "\x02\x01#{v.chr}" }
    good = { a::OID_HWID => ce.call(false, chip), a::OID_BL_SPL => ce.call(false, spl.call(3)), a::OID_TEE_SPL => ce.call(false, spl.call(5)),
             a::OID_SNP_SPL => ce.call(false, spl.call(7)), a::OID_UCODE_SPL => ce.call(false, spl.call(11)) }
    run = lambda do |exts|
      MutationKill::Seam.with(C09.der, { parse_tbs_extensions: ->(_t) { exts } }) { a.check_vcek_report_binding('tbs'.b, report) }
    end
    names = { a::OID_BL_SPL => 'bootloader', a::OID_TEE_SPL => 'tee', a::OID_SNP_SPL => 'snp', a::OID_UCODE_SPL => 'microcode' }
    rows = [['good', run.call(good), nil],
            ['no hwid', run.call(good.reject { |k, _| k == a::OID_HWID }), 'VCEK certificate has no CHIP_ID (hwID) extension'],
            ['hwid critical', run.call(good.merge(a::OID_HWID => ce.call(true, chip))),
             'VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)'],
            ['hwid 63', run.call(good.merge(a::OID_HWID => ce.call(false, chip[0, 63]))), 'VCEK CHIP_ID (hwID) extension is 63 bytes, expected 64'],
            ['hwid 65', run.call(good.merge(a::OID_HWID => ce.call(false, chip + "\x00"))), 'VCEK CHIP_ID (hwID) extension is 65 bytes, expected 64'],
            ['hwid differs', run.call(good.merge(a::OID_HWID => ce.call(false, chip.sub("\x00".b, "\x01".b)))),
             'VCEK CHIP_ID does not match report chip_id']]
    names.each do |oid, name|
      want = { a::OID_BL_SPL => 3, a::OID_TEE_SPL => 5, a::OID_SNP_SPL => 7, a::OID_UCODE_SPL => 11 }[oid]
      rows << ["#{name} missing", run.call(good.reject { |k, _| k == oid }), "VCEK certificate has no #{name} SPL extension"]
      rows << ["#{name} critical", run.call(good.merge(oid => ce.call(true, spl.call(want)))),
               "VCEK #{name} SPL extension is marked critical (the AMD profile is non-critical)"]
      rows << ["#{name} malformed", run.call(good.merge(oid => ce.call(false, "\x03\x01\x03"))), "VCEK #{name} SPL extension is not a DER INTEGER"]
      rows << ["#{name} negative", run.call(good.merge(oid => ce.call(false, "\x02\x01\x80"))), "VCEK #{name} SPL extension is negative"]
      rows << ["#{name} mismatch", run.call(good.merge(oid => ce.call(false, spl.call(want + 1)))),
               "VCEK #{name} SPL #{want + 1} does not match report reported_tcb (#{want}) — TCB downgrade?"]
    end
    de = C09.msg_der
    MutationKill::Seam.with(C09.der, { parse_tbs_extensions: ->(_t) { raise de, 'x' } }) do
      rows << ['der fault', a.check_vcek_report_binding('tbs'.b, report), 'VCEK extensions malformed: DM']
    end
    C09.chk(rows)
  end

  # ============================================================================================================ AMD policy
  t('amd check_sev_snp_policy: every gate, its boundary and its text; malformed gates are not gates') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    big = ->(v) { AtlasPca::Attest::BigU64.new(v) }
    base = { 'signature_algo' => 1, 'policy' => 0, 'guest_svn' => 5, 'reported_tcb' => 10, 'committed_tcb' => 20, 'launch_tcb' => 30, 'vmpl' => 0,
             'measurement' => ("\xAA".b * 48), 'host_data' => ("\xBB".b * 32), 'chip_id' => ("\xCC".b * 64) }
    always = Class.new do
      def ==(other) = other.is_a?(Integer)
      def to_s = 'ALWAYS'
    end.new
    sig = 'unexpected signature_algo 2'
    dbg = 'guest policy has the DEBUG bit set (host can inspect the guest)'
    cases = [
      [{}, {}, nil], [{ 'signature_algo' => 2 }, {}, sig], [{ 'signature_algo' => 2 }, { 'requireEcdsaP384' => false }, nil],
      [{ 'signature_algo' => 2 }, { 'requireEcdsaP384' => true }, sig], [{ 'signature_algo' => 2 }, { 'requireEcdsaP384' => nil }, sig],
      [{ 'policy' => 1 << 19 }, {}, dbg], [{ 'policy' => (1 << 19) | 5 }, { 'allowDebug' => true }, nil], [{ 'policy' => 1 << 19 }, { 'allowDebug' => 'yes' }, dbg],
      [{ 'policy' => (1 << 19) - 1 }, {}, nil], [{ 'policy' => 1 << 20 }, {}, nil],
      [{}, { 'minGuestSvn' => 6 }, 'guest_svn 5 below minimum 6'], [{}, { 'minGuestSvn' => 5 }, nil], [{}, { 'minGuestSvn' => 4 }, nil],
      [{}, { 'minGuestSvn' => 6.0 }, 'guest_svn 5 below minimum 6'], [{}, { 'minGuestSvn' => '6' }, nil], [{}, { 'minGuestSvn' => true }, nil],
      [{}, { 'minReportedTcb' => big.call(11) }, 'reported_tcb below minimum (rollback?)'], [{}, { 'minReportedTcb' => big.call(10) }, nil],
      [{}, { 'minReportedTcb' => 11 }, nil],
      [{}, { 'minCommittedTcb' => big.call(21) }, 'committed_tcb below minimum (rollback?)'], [{}, { 'minCommittedTcb' => big.call(20) }, nil],
      [{}, { 'minCommittedTcb' => big.call(19) }, nil], [{}, { 'minCommittedTcb' => 21 }, nil],
      [{}, { 'minLaunchTcb' => big.call(31) }, 'launch_tcb below minimum'], [{}, { 'minLaunchTcb' => big.call(30) }, nil], [{}, { 'minLaunchTcb' => 31 }, nil],
      [{ 'vmpl' => 1 }, {}, 'vmpl 1 is not the required 0'], [{ 'vmpl' => 3 }, { 'requireVmpl' => 'any' }, nil],
      [{}, { 'requireVmpl' => 1 }, 'vmpl 0 is not the required 1'], [{ 'vmpl' => 1 }, { 'requireVmpl' => 1.0 }, nil],
      [{}, { 'requireVmpl' => 2.0 }, 'vmpl 0 is not the required 2'], [{}, { 'requireVmpl' => '0' }, 'vmpl 0 is not the required 0'],
      [{}, { 'requireVmpl' => always }, 'vmpl 0 is not the required ALWAYS'],
      [{}, { 'measurements' => ['bb' * 48] }, 'measurement not in policy allowlist'], [{}, { 'measurements' => ['AA' * 48] }, nil],
      [{}, { 'measurements' => ['x', 'aa' * 48] }, nil], [{}, { 'measurements' => [] }, nil], [{}, { 'measurements' => 'aa' }, nil],
      [{}, { 'hostData' => ['aa' * 32] }, 'host_data not in policy allowlist'], [{}, { 'hostData' => ['BB' * 32] }, nil],
      [{}, { 'hostData' => [] }, nil], [{}, { 'hostData' => 'aa' }, nil],
      [{}, { 'chipIds' => ['aa' * 64] }, 'chip_id not in policy allowlist'], [{}, { 'chipIds' => ['CC' * 64] }, nil],
      [{}, { 'chipIds' => [] }, nil], [{}, { 'chipIds' => 'aa' }, nil]
    ]
    rows = cases.map { |over, pol, want| ["#{over.inspect} #{pol.inspect}", a.check_sev_snp_policy(base.merge(over), pol), want] }
    rows << ['fmt_num', [a.fmt_num(6.0), a.fmt_num(5), a.fmt_num('x'), a.fmt_num(nil)], %w[6 5 x undefined]]
    C09.chk(rows)
  end

  # ============================================================================================================ AMD chain (direct, real evidence)
  t('amd verify_amd_cert_chain: the clock gate, the chain shape, defaults and the exact failure hashes (real SEV-SNP evidence)') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    r = C09.row('amd-sev-snp', 'snp-real-positive')
    c = C09.amd_ctx(r)
    ev = c[:ev]
    pems = C09.cm.pem_blocks(ev['askArkPem'])
    ok = a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], c[:now], nil)
    fail_h = ->(reason) { { 'ok' => false, 'reason' => reason } }
    pin_bad = a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], nil, c[:now])
    boom = Object.new
    boom.define_singleton_method(:b) { raise C09.msg_err, 'x' }
    rows = [
      ['ok shape', ok.keys.sort, %w[ok vcek vcekTbs]],
      ['ok', ok['ok'], true],
      ['vcek key', [ok['vcek'].is_a?(OpenSSL::PKey::EC), ok['vcek'].group.curve_name], [true, 'secp384r1']],
      ['tbs', ok['vcekTbs'], C09.der.tbs_of_certificate(ev['vcekDer'])],
      ['skew omitted', a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], c[:now])['ok'], true],
      ['skew 0', a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], c[:now], 0)['ok'], true],
      ['pin upcase', a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin].upcase, c[:now])['ok'], true],
      ['default pin is milan, not genoa', pin_bad, fail_h.call('ARK does not match the pinned AMD trust anchor')],
      ['utf8 tagged vcek', a.verify_amd_cert_chain(ev['vcekDer'].dup.force_encoding('UTF-8'), ev['askArkPem'], c[:pin], c[:now])['ok'], true],
      ['now nil', a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], nil),
       fail_h.call('nowMs (verifier clock) is required for the AMD chain validity check')],
      ['now string', a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], '5'),
       fail_h.call('nowMs (verifier clock) is required for the AMD chain validity check')],
      ['now true', a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], true),
       fail_h.call('nowMs (verifier clock) is required for the AMD chain validity check')],
      ['skew negative', a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], c[:now], -1),
       fail_h.call('clockSkewMs must be a non-negative number')],
      ['skew string', a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], c[:now], 'x'),
       fail_h.call('clockSkewMs must be a non-negative number')],
      ['skew nan', a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], c[:now], Float::NAN),
       fail_h.call('clockSkewMs must be a non-negative number')],
      ['one pem', a.verify_amd_cert_chain(ev['vcekDer'], pems[0], c[:pin], c[:now]),
       fail_h.call('ASK+ARK chain must contain exactly two certificates (ASK then ARK)')],
      ['three pems', a.verify_amd_cert_chain(ev['vcekDer'], "#{pems[0]}\n#{pems[1]}\n#{pems[1]}", c[:pin], c[:now]),
       fail_h.call('ASK+ARK chain must contain exactly two certificates (ASK then ARK)')],
      ['reversed', a.verify_amd_cert_chain(ev['vcekDer'], "#{pems[1]}\n#{pems[0]}", c[:pin], c[:now]),
       fail_h.call('second certificate of the chain is not a self-signed ARK (chain out of order?)')],
      ['ark twice', a.verify_amd_cert_chain(ev['vcekDer'], "#{pems[1]}\n#{pems[1]}", c[:pin], c[:now]),
       fail_h.call('first certificate of the chain is self-signed, not an ASK (chain out of order?)')]
    ]
    got = a.verify_amd_cert_chain(boom, ev['askArkPem'], c[:pin], c[:now])
    rows << ['fault text', got, fail_h.call('AMD chain verification error: MSG')]
    C09.chk(rows)
  end

  t('amd verify_amd_cert_chain: validity gates, BasicConstraints, curve and role gates through seams over the real chain') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    cm = C09.cm
    dr = C09.der
    r = C09.row('amd-sev-snp', 'snp-real-positive')
    c = C09.amd_ctx(r)
    ev = c[:ev]
    fail_h = ->(reason) { { 'ok' => false, 'reason' => reason } }
    run = ->(now = c[:now], skew = c[:skew]) { a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], now, skew) }
    orig_validity = dr.method(:der_validity_ms)
    orig_exts = dr.method(:parse_cert_extensions)
    orig_kt = cm.method(:key_type)
    rows = []
    vseam = ->(pair) { { der_validity_ms: ->(_d) { pair } } }
    MutationKill::Seam.with(dr, vseam.call([nil, 5])) { rows << ['lo nil', run.call(1000, 0), fail_h.call('VCEK certificate validity is unparseable')] }
    MutationKill::Seam.with(dr, vseam.call([5, nil])) { rows << ['hi nil', run.call(1000, 0), fail_h.call('VCEK certificate validity is unparseable')] }
    MutationKill::Seam.with(dr, vseam.call([0, 1000])) do
      rows << ['inside the skew window', run.call(1500, 1000)['ok'], true]
      rows << ['expired beyond the skew', run.call(2500, 1000), fail_h.call('VCEK certificate has expired')]
      rows << ['expired no skew', run.call(1001, 0), fail_h.call('VCEK certificate has expired')]
      rows << ['not yet valid', run.call(-1, 0), fail_h.call('VCEK certificate is not yet valid')]
      rows << ['at the end', run.call(1000, 0)['ok'], true]
    end
    calls = 0
    MutationKill::Seam.with(dr, { parse_cert_extensions: ->(d) { calls += 1; calls == 2 ? {} : orig_exts.call(d) } }) do
      rows << ['ASK without BasicConstraints', run.call, fail_h.call('ASK certificate BasicConstraints is not marked critical')]
    end
    calls = 0
    MutationKill::Seam.with(dr, { parse_cert_extensions: ->(d) { calls += 1; calls == 3 ? {} : orig_exts.call(d) } }) do
      rows << ['ARK without BasicConstraints', run.call, fail_h.call('ARK certificate BasicConstraints is not marked critical')]
    end
    calls = 0
    MutationKill::Seam.with(dr, { parse_cert_extensions: ->(d) { calls += 1; calls == 1 ? {} : orig_exts.call(d) } }) do
      rows << ['VCEK needs no BasicConstraints', run.call['ok'], true]
    end
    MutationKill::Seam.with(dr, { check_chain_roles: ->(_c) { 'RE' } }) do
      rows << ['role text', run.call, fail_h.call('AMD chain role check failed: RE')]
    end
    # the last validity read is the ARK's: flip the key gate after it
    flip = lambda do |kt, nc|
      n = 0
      seams = { der_validity_ms: ->(d) { n += 1; orig_validity.call(d) } }
      seams[:key_type] = ->(k) { n >= 3 && kt ? kt : orig_kt.call(k) }
      seams[:node_curve] = ->(k) { n >= 3 ? nc : (orig_kt.call(k) == 'ec' ? k.group.curve_name : nil) }
      MutationKill::Seam.with(dr, { der_validity_ms: seams[:der_validity_ms] }) do
        MutationKill::Seam.with(cm, { key_type: seams[:key_type], node_curve: seams[:node_curve] }) { run.call }
      end
    end
    rows << ['curve p256', flip.call(nil, 'prime256v1'), fail_h.call('AMD chain verification error: VCEK is not EC secp384r1 (got ec/prime256v1)')]
    rows << ['curve undefined', flip.call(nil, nil), fail_h.call('AMD chain verification error: VCEK is not EC secp384r1 (got ec/undefined)')]
    rows << ['type rsa', flip.call('rsa', 'secp384r1'), fail_h.call('AMD chain verification error: VCEK is not EC secp384r1 (got rsa/secp384r1)')]
    C09.chk(rows)
  end

  # ============================================================================================================ AMD genuine report
  t('amd verify_genuine_sev_snp_report: each stage, its exact hash, defaults and the reserved signature bytes (seams)') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    good = Array.new(1184) { |i| ((i * 13) + 5) & 0xFF }
    (720...744).each { |i| good[i] = 0 }
    (792...816).each { |i| good[i] = 0 }
    (816...1184).each { |i| good[i] = 0 }
    gb = good.pack('C*')
    flip = ->(i) { b = gb.dup; b.setbyte(i, 1); b }
    key = :vcek
    chain_ok = { 'ok' => true, 'vcek' => key, 'vcekTbs' => 'TBS'.b }
    f = ->(reason) { { 'ok' => false, 'reason' => reason } }
    seams = { verify_amd_cert_chain: ->(*) { chain_ok }, verify_sev_snp_report_signature: ->(*) { true }, check_vcek_report_binding: ->(*) { nil } }
    run = lambda do |report = gb, **kw|
      args = [report, 'v'.b, 'p', 'pin', 1, 2, kw.fetch(:expected, nil), kw.fetch(:policy, nil)]
      a.verify_genuine_sev_snp_report(*args)
    end
    rep = a.parse_sev_snp_report(gb)
    rows = []
    MutationKill::Seam.with(a, seams) do
      rows << ['ok', run.call, { 'ok' => true, 'report' => rep, 'measured' => { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false,
                                                                                   'runtime_measurement' => rep['measurement'].unpack1('H*'),
                                                                                   'operator' => rep['chip_id'].unpack1('H*') } }]
      rows << ['too short', run.call(gb[0, 815]), f.call('report parse failed: parseSevSnpReport: report too short (815 < 816)')]
      rows << ['1185', run.call(gb + "\x00"), f.call('report length 1185 is not the canonical 1184')]
      rows << ['1183', run.call(gb[0, 1183]), f.call('report length 1183 is not the canonical 1184')]
      zero = f.call('report signature block has non-zero reserved bytes')
      [816, 1183, 720, 743, 792, 815].each { |i| rows << ["reserved byte #{i}", run.call(flip.call(i)), zero] }
      [719, 744, 791].each { |i| rows << ["signature byte #{i} is data", run.call(flip.call(i))['ok'], true] }
      # nil expected / policy are the defaults: nothing is checked
      rows << ['default expected, policy', a.verify_genuine_sev_snp_report(gb, 'v'.b, 'p', 'pin', 1)['ok'], true]
      rows << ['expected binding', run.call(expected: { 'holderPub' => 'h', 'grantRef' => 'g', 'epoch' => 1, 'nonce' => 'n' }),
               f.call('report_data does not bind holder/grant/epoch/nonce')]
      rows << ['policy refusal', run.call(policy: { 'allowDebug' => true, 'requireEcdsaP384' => false, 'minGuestSvn' => 2**40 }),
               f.call("guest_svn #{rep['guest_svn']} below minimum #{2**40}")]
    end
    seen = nil
    spies = { verify_amd_cert_chain: ->(*args) { seen = args; chain_ok }, verify_sev_snp_report_signature: ->(*) { true }, check_vcek_report_binding: ->(*) { nil } }
    MutationKill::Seam.with(a, spies) do
      a.verify_genuine_sev_snp_report(gb, 'V'.b, 'P', 'PIN', 7)
      rows << ['chain args, skew defaults to nil', seen, ['V'.b, 'P', 'PIN', 7, nil]]
      a.verify_genuine_sev_snp_report(gb, 'V'.b, 'P', 'PIN', 7, 9)
      rows << ['chain args, skew', seen, ['V'.b, 'P', 'PIN', 7, 9]]
    end
    MutationKill::Seam.with(a, seams.merge(verify_amd_cert_chain: ->(*) { { 'ok' => false, 'reason' => 'R' } })) do
      rows << ['chain refused', run.call, f.call('cert chain invalid: R')]
    end
    MutationKill::Seam.with(a, seams.merge(verify_amd_cert_chain: ->(*) { { 'ok' => false } })) do
      rows << ['chain refused, no reason', run.call, f.call('cert chain invalid: undefined')]
    end
    MutationKill::Seam.with(a, seams.merge(verify_amd_cert_chain: ->(*) { { 'ok' => true } })) do
      rows << ['chain ok but no key', run.call, f.call('cert chain invalid: undefined')]
    end
    MutationKill::Seam.with(a, seams.merge(verify_amd_cert_chain: ->(*) { { 'ok' => false, 'vcek' => key, 'reason' => 'Q' } })) do
      rows << ['chain not ok but a key', run.call, f.call('cert chain invalid: Q')]
    end
    sig_args = nil
    MutationKill::Seam.with(a, seams.merge(verify_sev_snp_report_signature: ->(*args) { sig_args = args; false })) do
      rows << ['signature', run.call, f.call('report signature does not verify under VCEK')]
      rows << ['signature args', sig_args, [rep, key]]
    end
    bind_args = nil
    MutationKill::Seam.with(a, seams.merge(check_vcek_report_binding: ->(*args) { bind_args = args; 'BIND' })) do
      rows << ['binding', run.call, f.call('BIND')]
      rows << ['binding args', bind_args, ['TBS'.b, rep]]
    end
    MutationKill::Seam.with(a, seams.merge(check_sev_snp_policy: ->(*) { 'POL' })) do
      rows << ['policy', run.call(policy: {}), f.call('POL')]
      rows << ['no policy, no check', run.call['ok'], true]
    end
    pe = Class.new(ArgumentError) { def message = 'PM' }
    MutationKill::Seam.with(a, seams.merge(parse_sev_snp_report: ->(_r) { raise pe, 'x' })) do
      rows << ['parse fault text', run.call, f.call('report parse failed: PM')]
    end
    me = C09.msg_err
    MutationKill::Seam.with(a, seams.merge(verify_amd_cert_chain: ->(*) { raise me, 'x' })) do
      rows << ['fault', run.call, f.call('genuine verification error (fail closed): MSG')]
    end
    C09.chk(rows)
  end

  # ============================================================================================================ Azure runtime-data binding
  t('amd check_azure_runtime_data_binding: size, zero half, hash, JSON, object, user-data and binding, each its own text') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    cm = C09.cm
    want = cm.attestation_binding(C09::BIND)
    ud = want.unpack1('H*')
    mk = lambda do |runtime|
      rd = Digest::SHA256.digest(runtime) + ("\x00" * 32)
      [rd.b, runtime]
    end
    run = ->(runtime) { rd, rt = mk.call(runtime); a.check_azure_runtime_data_binding(rd, rt, C09::BIND) }
    json = ->(h) { JSON.generate(h).b }
    rows = [
      ['ok', run.call(json.call('user-data' => ud)), nil], ['ok upper', run.call(json.call('user-data' => ud.upcase)), nil],
      ['63', a.check_azure_runtime_data_binding("\x00".b * 63, 'x'.b, C09::BIND), 'report_data is not 64 bytes'],
      ['65', a.check_azure_runtime_data_binding("\x00".b * 65, 'x'.b, C09::BIND), 'report_data is not 64 bytes'],
      ['not JSON', run.call('nope'.b), 'runtime data is not valid JSON'], ['array', run.call('[1]'.b), 'runtime data is not a JSON object'],
      ['no user-data', run.call('{}'.b), 'runtime data carries no 64-byte hex user-data'],
      ['number user-data', run.call(json.call('user-data' => 5)), 'runtime data carries no 64-byte hex user-data'],
      ['127', run.call(json.call('user-data' => ud[0, 126] + 'a')), 'runtime data carries no 64-byte hex user-data'],
      ['129', run.call(json.call('user-data' => ud + 'a')), 'runtime data carries no 64-byte hex user-data'],
      ['non hex', run.call(json.call('user-data' => 'zz' * 64)), 'runtime data carries no 64-byte hex user-data'],
      ['other binding', run.call(json.call('user-data' => '00' * 64)), 'runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)']
    ]
    [0, 31].each { |i| b = ("\x00".b * 64); b.setbyte(32 + i, 1); rows << ["tail byte #{i}", a.check_azure_runtime_data_binding(b, 'x'.b, C09::BIND), 'report_data[32:64] is not zero (not an Azure runtime-data hash)'] }
    rd, = mk.call('{}'.b)
    rows << ['hash mismatch', a.check_azure_runtime_data_binding(rd, '{ }'.b, C09::BIND), 'sha256(runtime data) does not equal the quote report_data']
    bad = ("\x01".b * 32) + ("\x00".b * 32)
    rows << ['hash first half', a.check_azure_runtime_data_binding(bad, 'x'.b, C09::BIND), 'sha256(runtime data) does not equal the quote report_data']
    # an invalid UTF-8 byte becomes U+FFFD, it is not dropped: this key is not "user-data"
    rows << ['scrub keeps the key distinct', run.call("{\"user-\xFFdata\":\"#{ud}\"}".b), 'runtime data carries no 64-byte hex user-data']
    rows << ['invalid UTF-8 elsewhere is scrubbed, the JSON still parses', run.call("{\"user-data\":\"#{ud}\",\"x\":\"\xFF\"}".b), nil]
    rt = json.call('user-data' => ud)
    rd2, = mk.call(rt)
    a.check_azure_runtime_data_binding(rd2, rt, C09::BIND)
    rows << ['runtime data not re-tagged', rt.encoding, Encoding::BINARY]
    mj = C09.msg_js
    MutationKill::Seam.with(cm, { attestation_binding: ->(_e) { raise mj, 'x' } }) do
      rows << ['binding fault', run.call(json.call('user-data' => ud)), 'binding not constructible: JM']
    end
    C09.chk(rows)
  end

  # ============================================================================================================ AMD rows (exact internal hashes)
  t('amd: verify_genuine / chain / runtime-data results equal the reference reasons for one row per distinct outcome') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    rows = []
    C09.amd_curated.each do |r|
      e = r['expect']
      begin
        c = C09.amd_ctx(r)
      rescue StandardError
        next
      end
      ev = c[:ev]
      next unless ev['report'].is_a?(String) && ev['vcekDer'].is_a?(String) && ev['askArkPem'].is_a?(String)

      reason = e['reason'] || e['reason_prefix']
      got = a.verify_genuine_sev_snp_report(ev['report'], ev['vcekDer'], ev['askArkPem'], c[:pin], c[:now], c[:skew], c[:direct] ? c[:expected] : nil, c[:policy])
      strip = 'SEV-SNP report invalid: '
      if reason&.start_with?(strip)
        want = C09.want_reason(e, strip)
        rows << ["#{r['id']} genuine", C09.hash_fail?(got, want), true]
        if want[1].start_with?('cert chain invalid: ')
          cw = [want[0], want[1].delete_prefix('cert chain invalid: ')]
          ch = a.verify_amd_cert_chain(ev['vcekDer'], ev['askArkPem'], c[:pin], c[:now], c[:skew])
          rows << ["#{r['id']} chain", C09.hash_fail?(ch, cw), true]
        end
      elsif e['ok'] || C09::AZ_BIND_REASONS.include?(reason) || reason&.start_with?('binding not constructible: ')
        rows << ["#{r['id']} genuine ok", [got['ok'], got.keys.sort], [true, %w[measured ok report]]]
        next if c[:direct] || ev['runtimeData'].nil?

        why = a.check_azure_runtime_data_binding(got['report']['report_data'], ev['runtimeData'], c[:expected])
        rows << ["#{r['id']} binding", why, e['ok'] ? nil : reason]
      end
    end
    C09.chk(rows)
  end

  # ============================================================================================================ AmdSnpVerifier
  t('AmdSnpVerifier.new: family, binding and the non-empty measurement allowlist are required; policy is copied, never aliased') do
    next true if C09.skip?('amd.rb')

    k = C09.att::AmdSnpVerifier
    construct = C09.att::AttestConstructError
    base = ->(over = {}) { { 'family' => 'genoa', 'binding' => 'report-data', 'policy' => { 'measurements' => ['aa'] } }.merge(over) }
    fam = [construct, "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'"]
    bnd = [construct, "createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'"]
    mea = [construct, 'createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)']
    rows = [
      ['family nil', C09.err { k.new(base.call('family' => nil)) }, fam], ['family 5', C09.err { k.new(base.call('family' => 5)) }, fam],
      ['family other', C09.err { k.new(base.call('family' => 'rome')) }, fam], ['family empty', C09.err { k.new(base.call('family' => '')) }, fam],
      ['binding nil', C09.err { k.new(base.call('binding' => nil)) }, bnd], ['binding other', C09.err { k.new(base.call('binding' => 'x')) }, bnd],
      ['policy nil', C09.err { k.new(base.call('policy' => nil)) }, mea], ['policy string', C09.err { k.new(base.call('policy' => 'str')) }, mea],
      ['policy array', C09.err { k.new(base.call('policy' => [1])) }, mea],
      ['measurements missing', C09.err { k.new(base.call('policy' => {})) }, mea],
      ['measurements empty', C09.err { k.new(base.call('policy' => { 'measurements' => [] })) }, mea],
      ['measurements string', C09.err { k.new(base.call('policy' => { 'measurements' => 'aa' })) }, mea],
      ['measurements hash', C09.err { k.new(base.call('policy' => { 'measurements' => { 'a' => 1 } })) }, mea]
    ]
    %w[milan genoa turin].each do |f|
      %w[report-data azure-runtime-data].each do |b|
        v = k.new(base.call('family' => f, 'binding' => b))
        rows << ["#{f}/#{b}", [v.instance_variable_get(:@pin), v.instance_variable_get(:@family), v.instance_variable_get(:@binding)], [C09.amd::ARK_SPKI_SHA384[f], f, b]]
      end
    end
    meas = ['aa']
    pol = { 'measurements' => meas, 'minReportedTcb' => '5', 'minCommittedTcb' => 6, 'minLaunchTcb' => '7', 'allowDebug' => true }
    resolver = ->(_d) { nil }
    v = k.new(base.call('policy' => pol, 'clockSkewMs' => 5, 'resolve_evidence' => resolver))
    p2 = v.instance_variable_get(:@policy)
    meas.clear
    rows << ['policy copied', p2.equal?(pol), false]
    rows << ['caller policy untouched', pol, { 'measurements' => [], 'minReportedTcb' => '5', 'minCommittedTcb' => 6, 'minLaunchTcb' => '7', 'allowDebug' => true }]
    rows << ['measurements copied', [p2['measurements'], p2['measurements'].equal?(meas)], [['aa'], false]]
    rows << ['tcb floors', %w[minReportedTcb minCommittedTcb minLaunchTcb].map { |n| [p2[n].class == C09.att::BigU64, p2[n].v] }, [[true, 5], [true, 6], [true, 7]]]
    rows << ['other keys', p2['allowDebug'], true]
    rows << ['skew, resolver', [v.instance_variable_get(:@skew), v.instance_variable_get(:@resolve).equal?(resolver)], [5, true]]
    C09.chk(rows)
  end

  t('AmdSnpVerifier#verify: resolver, evidence shape, expected binding, direct vs azure binding and the exact success hash (seams)') do
    next true if C09.skip?('amd.rb')

    a = C09.amd
    k = C09.att::AmdSnpVerifier
    mk = lambda do |binding, ev, over = {}|
      opts = { 'family' => 'genoa', 'binding' => binding, 'policy' => { 'measurements' => ['aa'] }, 'clockSkewMs' => 77 }.merge(over)
      opts['resolve_evidence'] = ->(_d) { ev } unless over.key?('no_resolver')
      opts.delete('no_resolver')
      k.new(opts)
    end
    f = ->(reason) { { 'ok' => false, 'reason' => reason } }
    evid = { 'report' => 'R', 'vcekDer' => 'V', 'askArkPem' => 'P' }
    exp = { 'holderPub' => 'h' }
    rows = [
      ['no resolver', mk.call('report-data', evid, 'no_resolver' => true).verify({}, exp, 1),
       f.call('no AMD SEV-SNP evidence resolver configured (fail closed)')]
    ]
    none = f.call('no AMD SEV-SNP evidence for this action')
    [nil, [], 'x', 5, evid.merge('report' => 5), evid.merge('report' => nil), evid.merge('vcekDer' => 5), evid.merge('vcekDer' => nil),
     evid.merge('askArkPem' => 5), evid.merge('askArkPem' => nil), evid.reject { |kk, _| kk == 'askArkPem' }].each_with_index do |ev, i|
      rows << ["evidence #{i}", mk.call('report-data', ev).verify({}, exp, 1), none]
    end
    rows << ['expected nil', mk.call('report-data', evid).verify({}, nil, 1), f.call('no expected attestation binding supplied')]
    rep = { 'report_data' => 'RD', 'measurement' => "\x12\x34".b }
    measured = { 'model_id' => 'm' }
    okr = { 'ok' => true, 'report' => rep, 'measured' => measured }
    seen = nil
    gen = ->(res) { ->(*args) { seen = args; res } }
    MutationKill::Seam.with(a, { verify_genuine_sev_snp_report: gen.call(okr) }) do
      v = mk.call('report-data', evid)
      rows << ['direct ok', v.verify({}, exp, 5), { 'ok' => true, 'bound' => true, 'measured' => measured,
                                                      'hostAsserted' => { 'attestation_type' => 'amd-sev-snp', 'family' => 'genoa', 'measurement' => '1234' } }]
      rows << ['direct args', seen, ['R', 'V', 'P', C09.amd::ARK_SPKI_SHA384['genoa'], 5, 77, exp, v.instance_variable_get(:@policy)]]
    end
    MutationKill::Seam.with(a, { verify_genuine_sev_snp_report: gen.call(okr), check_azure_runtime_data_binding: ->(*args) { seen = args; nil } }) do
      v = mk.call('azure-runtime-data', evid.merge('runtimeData' => 'RT'))
      rows << ['azure ok', v.verify({}, exp, 5)['ok'], true]
      rows << ['azure binding args', seen, ['RD', 'RT', exp]]
      [nil, 5].each { |rt| rows << ["azure runtime #{rt.inspect}", mk.call('azure-runtime-data', evid.merge('runtimeData' => rt)).verify({}, exp, 5), f.call('azure-runtime-data binding needs the runtime-data JSON bytes')] }
    end
    gseen = nil
    MutationKill::Seam.with(a, { verify_genuine_sev_snp_report: ->(*args) { gseen = args; okr }, check_azure_runtime_data_binding: ->(*) { 'WHY' } }) do
      v = mk.call('azure-runtime-data', evid.merge('runtimeData' => 'RT'))
      rows << ['azure refusal', v.verify({}, exp, 5), f.call('WHY')]
      rows << ['azure: genuine gets no expected', gseen[6], nil]
    end
    [[{ 'ok' => false, 'reason' => 'X' }, 'SEV-SNP report invalid: X'], [{ 'ok' => false }, 'SEV-SNP report invalid: unknown'],
     [{ 'ok' => true, 'measured' => measured }, 'SEV-SNP report invalid: unknown'], [{ 'ok' => true, 'report' => rep }, 'SEV-SNP report invalid: unknown'],
     [{ 'ok' => false, 'report' => rep, 'measured' => measured }, 'SEV-SNP report invalid: unknown']].each_with_index do |(res, why), i|
      MutationKill::Seam.with(a, { verify_genuine_sev_snp_report: gen.call(res) }) do
        rows << ["genuine result #{i}", mk.call('report-data', evid).verify({}, exp, 5), f.call(why)]
      end
    end
    me = C09.msg_err
    MutationKill::Seam.with(a, { verify_genuine_sev_snp_report: ->(*) { raise me, 'x' } }) do
      rows << ['fault', mk.call('report-data', evid).verify({}, exp, 5), f.call('amd-snp verification error (fail closed): MSG')]
    end
    C09.chk(rows)
  end

  # ============================================================================================================ Azure constants, keys, JWS
  t('azure: suite, claim-key lists (frozen) and the TCB claim table') do
    next true if C09.skip?('azure.rb')

    z = C09.az
    C09.chk([
      ['suite', z::SUITE, 'azure-maa-jwt'],
      ['keys', [z::SEVSNP_MEASUREMENT_KEYS, z::SEVSNP_REPORTDATA_KEYS, z::SEVSNP_HOSTDATA_KEYS, z::SEVSNP_DEBUG_KEY],
       [['x-ms-sevsnpvm-launchmeasurement'], ['x-ms-sevsnpvm-reportdata'], ['x-ms-sevsnpvm-hostdata'], 'x-ms-sevsnpvm-is-debuggable']],
      ['tcb', z::SEVSNP_TCB_CLAIMS, [%w[bootloader x-ms-sevsnpvm-bootloader-svn bootloader_svn], %w[snp x-ms-sevsnpvm-snpfw-svn snpfw_svn],
                                     %w[microcode x-ms-sevsnpvm-microcode-svn microcode_svn], %w[tee x-ms-sevsnpvm-tee-svn tee_svn]]],
      ['tdx', [z::TDX_MRTD_KEYS, z::TDX_REPORTDATA_KEYS, z::TDX_RTMR0_KEYS],
       [%w[tdx_mrtd x-ms-tdx-mrtd], %w[tdx_report_data x-ms-tdx-report-data x-ms-tdx-reportdata], %w[tdx_rtmr0 x-ms-tdx-rtmr0]]],
      ['frozen', [z::SEVSNP_MEASUREMENT_KEYS, z::SEVSNP_REPORTDATA_KEYS, z::SEVSNP_HOSTDATA_KEYS, z::SEVSNP_TCB_CLAIMS, z::TDX_MRTD_KEYS,
                  z::TDX_REPORTDATA_KEYS, z::TDX_RTMR0_KEYS].map(&:frozen?), [true] * 7]
    ])
  end

  t('azure kty / kty_crv / lower / verify_jws_signature: key kind gates, signature length, both algorithms, exact texts') do
    next true if C09.skip?('azure.rb')

    z = C09.az
    cm = C09.cm
    load_pub = ->(k) { cm.load_public_key(k.public_to_der) }
    ec256 = load_pub.call(C09.pki_key('jws'))
    ec384 = load_pub.call(OpenSSL::PKey::EC.generate('secp384r1'))
    rsa_k = OpenSSL::PKey::RSA.generate(2048)
    rsa = load_pub.call(rsa_k)
    leaf = ->(k) { Struct.new(:public_key).new(k) }
    msg = 'jws.signing.input'.b
    raw = lambda do |key, data|
      OpenSSL::ASN1.decode(key.sign(OpenSSL::Digest.new('SHA256'), data)).value.map { |i| i.value.to_s(2).rjust(32, "\x00".b) }.join
    end
    sig = raw.call(C09.pki_key('jws'), msg)
    es = ->(k, s = sig, d = msg) { z.verify_jws_signature({ 'header' => { 'alg' => 'ES256' }, 'signature' => s, 'signingInput' => d }, leaf.call(k)) }
    rs = lambda do |k, s, alg = 'RS256'|
      z.verify_jws_signature({ 'header' => { 'alg' => alg }, 'signature' => s, 'signingInput' => msg }, leaf.call(k))
    end
    rsig = rsa_k.sign(OpenSSL::Digest.new('SHA256'), msg)
    flipped = sig.dup
    flipped.setbyte(5, flipped.getbyte(5) ^ 1)
    rows = [
      ['kty', [z.kty(ec256), z.kty(rsa)], %w[EC RSA]], ['kty ed', z.kty(cm.load_public_key(OpenSSL::PKey.generate_key('ED25519').public_to_der)), 'ed25519'],
      ['crv', [z.kty_crv(ec256), z.kty_crv(ec384), z.kty_crv(rsa)], ['EC/P-256', 'EC/P-384', 'RSA/undefined']],
      ['lower', z.lower(%w[AbC D e]), %w[abc d e]],
      ['es ok', es.call(ec256), nil], ['es bad', es.call(ec256, flipped), 'JWS ES256 signature does not verify under the MAA signing key'],
      ['es wrong data', es.call(ec256, sig, 'other'.b), 'JWS ES256 signature does not verify under the MAA signing key'],
      ['es 63', es.call(ec256, sig[0, 63]), 'ES256 signature is 63 bytes (expected 64: r‖s)'],
      ['es 65', es.call(ec256, sig + "\x00"), 'ES256 signature is 65 bytes (expected 64: r‖s)'],
      ['es on p384', es.call(ec384), 'ES256 token but signing key is EC/P-384 (not EC P-256)'],
      ['es on rsa', es.call(rsa), 'ES256 token but signing key is RSA/undefined (not EC P-256)'],
      ['rs ok', rs.call(rsa, rsig), nil], ['rs bad', rs.call(rsa, rsig.reverse), 'JWS RS256 signature does not verify under the MAA signing key'],
      ['rs on ec', rs.call(ec256, rsig), 'RS256 token but signing key is EC (not RSA)'],
      ['ps256', rs.call(rsa, rsig, 'PS256'), "unsupported JWS alg 'PS256' (MAA uses ES256 / RS256)"],
      ['es256 lower', rs.call(rsa, rsig, 'es256'), "unsupported JWS alg 'es256' (MAA uses ES256 / RS256)"],
      ['alg none', rs.call(rsa, rsig, 'none'), "unsupported JWS alg 'none' (MAA uses ES256 / RS256)"]
    ]
    # the EC-key kind gate stands on its own: an RSA key that claims P-256 is still refused
    MutationKill::Seam.with(cm, { jwk_curve: ->(_k) { 'P-256' } }) do
      rows << ['rsa claiming p-256', es.call(rsa), 'ES256 token but signing key is RSA/P-256 (not EC P-256)']
    end
    C09.chk(rows)
  end

  t('azure resolve_signing_x5c: kid selection, the single-key shortcut, header fallback, every refusal verbatim') do
    next true if C09.skip?('azure.rb')

    z = C09.az
    k1 = { 'kid' => 'a', 'x5c' => ['X1'] }
    k2 = { 'kid' => 'b', 'x5c' => ['X2'] }
    r = ->(h, j) { z.resolve_signing_x5c(h, j) }
    noh = { 'reason' => 'no signing x5c available (no JWKS and no header x5c)' }
    rows = [
      ['kid match', r.call({ 'kid' => 'b' }, { 'keys' => [k1, k2] }), { 'x5c' => ['X2'] }],
      ['kid match skips non-objects', r.call({ 'kid' => 'a' }, { 'keys' => [5, 'a', k1] }), { 'x5c' => ['X1'] }],
      ['kid unknown', r.call({ 'kid' => 'z' }, { 'keys' => [k1] }), { 'reason' => "no JWKS key matches the token kid 'z' (untrusted signer)" }],
      ['kid, key without x5c', r.call({ 'kid' => 'a' }, { 'keys' => [{ 'kid' => 'a' }] }), { 'reason' => "JWKS key 'a' carries no x5c chain" }],
      ['kid, empty x5c', r.call({ 'kid' => 'a' }, { 'keys' => [{ 'kid' => 'a', 'x5c' => [] }] }), { 'reason' => "JWKS key 'a' carries no x5c chain" }],
      ['kid, string x5c', r.call({ 'kid' => 'a' }, { 'keys' => [{ 'kid' => 'a', 'x5c' => 'abc' }] }), { 'reason' => "JWKS key 'a' carries no x5c chain" }],
      ['no kid, one key', r.call({}, { 'keys' => [k1] }), { 'x5c' => ['X1'] }],
      ['empty kid, one key', r.call({ 'kid' => '' }, { 'keys' => [k1] }), { 'x5c' => ['X1'] }],
      ['non-string kid, one key', r.call({ 'kid' => 5 }, { 'keys' => [k1] }), { 'x5c' => ['X1'] }],
      ['no kid, two keys', r.call({}, { 'keys' => [k1, k2] }), { 'reason' => 'token has no kid and the JWKS publishes multiple keys (ambiguous)' }],
      ['no kid, key without x5c', r.call({}, { 'keys' => [{ 'kid' => 'a' }] }), { 'reason' => 'JWKS key carries no x5c chain' }],
      ['no kid, empty x5c', r.call({}, { 'keys' => [{ 'x5c' => [] }] }), { 'reason' => 'JWKS key carries no x5c chain' }],
      ['no kid, string x5c', r.call({}, { 'keys' => [{ 'x5c' => 'abc' }] }), { 'reason' => 'JWKS key carries no x5c chain' }],
      ['no kid, key not an object', r.call({}, { 'keys' => [5] }), { 'reason' => 'JWKS key carries no x5c chain' }],
      ['header x5c, no jwks', r.call({ 'x5c' => ['H'] }, nil), { 'x5c' => ['H'] }],
      ['header x5c, empty keys', r.call({ 'x5c' => ['H'] }, { 'keys' => [] }), { 'x5c' => ['H'] }],
      ['header x5c, keys not an array', r.call({ 'x5c' => ['H'] }, { 'keys' => 'abc' }), { 'x5c' => ['H'] }],
      ['header x5c, jwks a string', r.call({ 'x5c' => ['H'] }, 'abc'), { 'x5c' => ['H'] }],
      ['nothing', r.call({}, nil), noh], ['empty header x5c', r.call({ 'x5c' => [] }, nil), noh], ['empty keys, no header', r.call({}, { 'keys' => [] }), noh]
    ]
    rows << ['jwks an array', C09.err { r.call({ 'x5c' => ['H'] }, [1]) }, nil]
    C09.chk(rows)
  end

  # ============================================================================================================ x5c chain
  t('azure verify_x5c_chain: shape, entry and validity gates, anchored-in-chain and external-root paths, exact hashes') do
    next true if C09.skip?('azure.rb')

    z = C09.az
    dr = C09.der
    cm = C09.cm
    p = C09.pki
    f = ->(reason) { { 'ok' => false, 'reason' => reason } }
    valid_calls = []
    prof_calls = []
    profile = nil
    seams = { x509_valid_at?: ->(raw, now, skew) { valid_calls << [raw, now, skew]; true },
              strict_chain_error: ->(ders) { prof_calls << ders; profile } }
    run = ->(x5c, anchors, now = 5, *skew) { z.verify_x5c_chain(x5c, anchors, now, *skew) }
    der_of = ->(n) { p.fetch(n).to_der }
    sp = ->(n) { { 'rootSpkiSha256' => [C09.spki(n)] } }
    pem = ->(n) { { 'rootCertsPem' => [p.fetch(n).to_pem] } }
    rows = []
    MutationKill::Seam.with(dr, seams) do
      ['x', nil, [], {}, 5].each { |bad| rows << ["x5c #{bad.inspect}", run.call(bad, sp.call(:root)), f.call('empty x5c certificate chain')] }
      leaf64 = C09.x5c(:leaf)[0]
      ['', 5, nil].each { |bad| rows << ["entry #{bad.inspect}", run.call([leaf64, bad], sp.call(:root)), f.call('empty x5c entry at index 1')] }
      rows << ['entry 0 empty', run.call([''], sp.call(:root)), f.call('empty x5c entry at index 0')]
      mal = run.call(%w[AAAA], sp.call(:root))
      rows << ['malformed', [mal['ok'], mal['reason'].start_with?('malformed x5c certificate at index 0: ')], [false, true]]
      me = C09.msg_err
      MutationKill::Seam.with(cm, { node_b64decode: ->(_s) { raise me, 'x' } }) do
        rows << ['malformed text', run.call([leaf64], sp.call(:root)), f.call('malformed x5c certificate at index 0: MSG')]
      end
      # clock: the skew is a non-negative number, default 0
      valid_calls.clear
      run.call(C09.x5c(:leaf), sp.call(:leaf), 77)
      run.call(C09.x5c(:leaf), sp.call(:leaf), 77, 9)
      run.call(C09.x5c(:leaf), sp.call(:leaf), 77, -9)
      run.call(C09.x5c(:leaf), sp.call(:leaf), 77, 0)
      run.call(C09.x5c(:leaf), sp.call(:leaf), 77, nil)
      run.call(C09.x5c(:leaf), sp.call(:leaf), 77, 'x')
      rows << ['skews', valid_calls.map { |c| c[2] }, [0, 9, 0, 0, 0, 0]]
      rows << ['clock args', valid_calls[1], [der_of.call(:leaf), 77, 9]]
      rows << ['anchored at the leaf', run.call(C09.x5c(:leaf), sp.call(:leaf)).then { |r| [r['ok'], r['leaf'].raw] }, [true, der_of.call(:leaf)]]
    end
    MutationKill::Seam.with(dr, { x509_valid_at?: ->(raw, _n, _s) { raw != der_of.call(:mid) }, strict_chain_error: seams[:strict_chain_error] }) do
      rows << ['outside validity', run.call(C09.x5c(:leaf, :mid), sp.call(:root)), f.call('x5c certificate at index 1 is outside its validity window')]
    end
    MutationKill::Seam.with(dr, seams) do
      # no anchors at all
      [nil, {}, 'x', { 'rootSpkiSha256' => [], 'rootCertsPem' => [] }, { 'rootSpkiSha256' => ['', 5, nil] }].each do |anc|
        rows << ["anchors #{anc.inspect}", run.call(C09.x5c(:leaf), anc), f.call('no MAA trust anchor configured (fail closed)')]
      end
      rows << ['anchors an array', C09.err { run.call(C09.x5c(:leaf), [1]) }.nil?, true]
      # anchored inside the chain
      prof_calls.clear
      r = run.call(C09.x5c(:leaf, :mid, :root), sp.call(:root))
      rows << ['anchored at root', [r['ok'], r['leaf'].raw, prof_calls.last], [true, der_of.call(:leaf), [der_of.call(:leaf), der_of.call(:mid), der_of.call(:root)]]]
      r = run.call(C09.x5c(:leaf, :mid, :root), sp.call(:mid))
      rows << ['anchored at the middle', [r['ok'], prof_calls.last], [true, [der_of.call(:leaf), der_of.call(:mid)]]]
      rows << ['anchored, upcase pin', run.call(C09.x5c(:leaf, :mid), { 'rootSpkiSha256' => [C09.spki(:mid).upcase] })['ok'], true]
      rows << ['anchored, pem is the middle', run.call(C09.x5c(:leaf, :mid), pem.call(:mid))['ok'], true]
      rows << ['anchored: link 0', run.call(C09.x5c(:leaf_bad, :mid, :root), sp.call(:root)), f.call('x5c link 0 is not signed by the certificate above it')]
      rows << ['anchored: link 1', run.call(C09.x5c(:leaf, :mid_bad, :root), sp.call(:root)), f.call('x5c link 1 is not signed by the certificate above it')]
      profile = 'PROFILE'
      rows << ['anchored: profile', run.call(C09.x5c(:leaf, :mid), sp.call(:mid)), f.call('x5c chain profile: PROFILE')]
      rows << ['external: profile', run.call(C09.x5c(:leaf, :mid), pem.call(:root)), f.call('x5c chain profile: PROFILE')]
      profile = nil
      # external root
      prof_calls.clear
      r = run.call(C09.x5c(:leaf, :mid), pem.call(:root))
      rows << ['external ok', [r['ok'], r['leaf'].raw, prof_calls.last], [true, der_of.call(:leaf), [der_of.call(:leaf), der_of.call(:mid)]]]
      rows << ['external: wrong root', run.call(C09.x5c(:leaf, :mid), pem.call(:root2)), f.call('x5c chain does not anchor in a configured MAA trust root')]
      rows << ['external: link 0 (two certs)', run.call(C09.x5c(:leaf_bad, :mid), pem.call(:root)), f.call('x5c link 0 is not signed by the certificate above it')]
      rows << ['external: link 1', run.call(C09.x5c(:leaf, :mid_bad, :top), pem.call(:root2)), f.call('x5c link 1 is not signed by the certificate above it')]
      rows << ['external: three certs ok', run.call(C09.x5c(:leaf, :mid, :root), pem.call(:root2))['reason'],
               'x5c chain does not anchor in a configured MAA trust root']
      rows << ['external: single cert signed by the root', run.call(C09.x5c(:mid), pem.call(:root))['ok'], true]
    end
    boom = C09.msg_err
    MutationKill::Seam.with(dr, seams.merge(strict_chain_error: ->(_d) { raise boom, 'x' })) do
      rows << ['fault', run.call(C09.x5c(:leaf, :mid), pem.call(:root)), f.call('x5c chain verification error (fail closed): MSG')]
    end
    C09.chk(rows)
  end

  # ============================================================================================================ AzureMaaVerifier.new
  t('AzureMaaVerifier.new: issuers, anchors, policy allowlists and the TCB floors are validated; inputs are copied') do
    next true if C09.skip?('azure.rb')

    k = C09.att::AzureMaaVerifier
    ce = C09.att::AttestConstructError
    base = lambda do |over = {}|
      { 'trustedIssuers' => ['https://i'], 'trustAnchors' => { 'rootSpkiSha256' => ['aa'] }, 'policy' => { 'sevSnpMeasurements' => ['ab'] } }.merge(over)
    end
    pre = 'createAzureMaaVerifier: '
    iss1 = [ce, "#{pre}trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs"]
    iss2 = [ce, "#{pre}every trusted issuer must be a non-empty URL string"]
    anc = [ce, "#{pre}trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted"]
    pol = [ce, "#{pre}policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)"]
    pw = ->(h) { base.call('policy' => h) }
    tcb = ->(m) { pw.call('sevSnpMeasurements' => ['ab'], 'sevSnpMinTcb' => m) }
    rows = [
      ['issuers nil', C09.err { k.new(base.call('trustedIssuers' => nil)) }, iss1], ['issuers empty', C09.err { k.new(base.call('trustedIssuers' => [])) }, iss1],
      ['issuers string', C09.err { k.new(base.call('trustedIssuers' => 'https://i')) }, iss1],
      ['issuer empty', C09.err { k.new(base.call('trustedIssuers' => ['https://i', ''])) }, iss2],
      ['issuer number', C09.err { k.new(base.call('trustedIssuers' => [5])) }, iss2],
      ['anchors nil', C09.err { k.new(base.call('trustAnchors' => nil)) }, anc], ['anchors empty', C09.err { k.new(base.call('trustAnchors' => {})) }, anc],
      ['anchors lists empty', C09.err { k.new(base.call('trustAnchors' => { 'rootCertsPem' => [], 'rootSpkiSha256' => [] })) }, anc],
      ['anchors array', C09.err { k.new(base.call('trustAnchors' => [])) }, anc],
      ['policy nil', C09.err { k.new(base.call('policy' => nil)) }, pol], ['policy array', C09.err { k.new(base.call('policy' => [])) }, pol],
      ['policy string', C09.err { k.new(base.call('policy' => 'x')) }, pol], ['policy empty', C09.err { k.new(pw.call({})) }, pol],
      ['sev empty', C09.err { k.new(pw.call('sevSnpMeasurements' => [])) }, pol], ['sev string', C09.err { k.new(pw.call('sevSnpMeasurements' => 'x')) }, pol],
      ['tdx empty', C09.err { k.new(pw.call('tdxMrtds' => [])) }, pol], ['tdx string', C09.err { k.new(pw.call('tdxMrtds' => 'x')) }, pol],
      ['sev empty tdx empty', C09.err { k.new(pw.call('sevSnpMeasurements' => [], 'tdxMrtds' => [])) }, pol],
      ['min tcb nil', C09.err { k.new(tcb.call(nil)) }, [ce, "#{pre}policy.sevSnpMinTcb must be an object"]],
      ['min tcb array', C09.err { k.new(tcb.call([])) }, [ce, "#{pre}policy.sevSnpMinTcb must be an object"]],
      ['min tcb string', C09.err { k.new(tcb.call('x')) }, [ce, "#{pre}policy.sevSnpMinTcb must be an object"]],
      ['min tcb unknown', C09.err { k.new(tcb.call('firmware' => 1)) }, [ce, "#{pre}policy.sevSnpMinTcb.firmware is not a known field (bootloader | snp | microcode | tee)"]]
    ]
    [-1, 1.5, '1', nil, true, Float::NAN].each do |bad|
      rows << ["min tcb #{bad.inspect}", C09.err { k.new(tcb.call('snp' => bad)) }, [ce, "#{pre}policy.sevSnpMinTcb.snp must be a non-negative integer"]]
    end
    [0, 5, 2.0].each { |good| rows << ["min tcb #{good}", C09.err { k.new(tcb.call('tee' => good)) }, nil] }
    rows << ['anchors: one and one', C09.err { k.new(base.call('trustAnchors' => { 'rootCertsPem' => ['p'], 'rootSpkiSha256' => ['aa'] })) }, nil]
    rows << ['anchors: certs only', C09.err { k.new(base.call('trustAnchors' => { 'rootCertsPem' => ['p'] })) }, nil]
    ti = ['https://i']
    policy = { 'sevSnpMeasurements' => ['ab'], 'tdxMrtds' => ['cd'] }
    v = k.new(base.call('trustedIssuers' => ti, 'policy' => policy, 'clockSkewMs' => 1500))
    ivar = ->(n) { v.instance_variable_get(n) }
    rows << ['copies', [ivar.call(:@policy).equal?(policy), ivar.call(:@policy), ivar.call(:@issuers).equal?(ti), ivar.call(:@issuers)], [false, policy, false, ti]]
    rows << ['flags', [ivar.call(:@has_sev), ivar.call(:@has_tdx), ivar.call(:@skew)], [true, true, 1500]]
    tdx_only = k.new(base.call('policy' => { 'tdxMrtds' => ['cd'] }))
    rows << ['tdx only', [tdx_only.instance_variable_get(:@has_sev), tdx_only.instance_variable_get(:@has_tdx)], [false, true]]
    sev_only = k.new(base.call)
    rows << ['sev only', [sev_only.instance_variable_get(:@has_sev), sev_only.instance_variable_get(:@has_tdx)], [true, false]]
    [[nil, 0], [-5, 0], [0, 0], ['x', 0], [250, 250], [2.5, 2.5]].each do |inp, want|
      rows << ["skew #{inp.inspect}", k.new(base.call('clockSkewMs' => inp)).instance_variable_get(:@skew), want]
    end
    C09.chk(rows)
  end

  # ============================================================================================================ AzureMaaVerifier#verify
  module C09
    module_function

    def az_base_payload(extra = {})
      { 'iss' => 'https://i', 'exp' => NOW_SEC + 100, 'x-ms-attestation-type' => 'sevsnpvm',
        'x-ms-sevsnpvm-reportdata' => hex(cm.attestation_binding(BIND)), 'x-ms-sevsnpvm-launchmeasurement' => 'ab' }.merge(extra)
    end

    def az_token(payload, header = { 'alg' => 'ES256' }) = "#{b64u(JSON.generate(header))}.#{b64u(JSON.generate(payload))}.#{b64u('sig')}"

    def az_run(payload, header: { 'alg' => 'ES256' }, policy: nil, expected: BIND, now: NOW, evidence: :default, opts: {}, seams: {})
      ev = evidence == :default ? { 'token' => az_token(payload, header), 'jwks' => nil } : evidence
      pol = policy || { 'sevSnpMeasurements' => ['ab'], 'tdxMrtds' => ['cd'] }
      o = { 'trustedIssuers' => ['https://i'], 'trustAnchors' => { 'rootSpkiSha256' => ['aa'] }, 'policy' => pol, 'resolve_evidence' => ->(_d) { ev } }.merge(opts)
      v = att::AzureMaaVerifier.new(o)
      d = { resolve_signing_x5c: ->(*) { { 'x5c' => ['X'] } }, verify_x5c_chain: ->(*) { { 'ok' => true, 'leaf' => :leaf } },
            verify_jws_signature: ->(*) {} }.merge(seams)
      MutationKill::Seam.with(az, d) { v.verify({}, expected, now) }
    end

    SEV_OK = { 'ok' => true, 'bound' => true,
               'measured' => { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => 'ab', 'operator' => '' },
               'hostAsserted' => { 'attestation_type' => 'sevsnpvm' } }.freeze

    def fail_h(reason) = { 'ok' => false, 'reason' => reason }
  end

  t('AzureMaaVerifier#verify: resolver, token shape, algorithm, signer resolution, chain and signature stages (seams over the stages)') do
    next true if C09.skip?('azure.rb')

    run = C09.method(:az_run)
    f = C09.method(:fail_h)
    pay = C09.az_base_payload
    rows = [['ok', run.call(pay), C09::SEV_OK]]
    v = C09.att::AzureMaaVerifier.new('trustedIssuers' => ['https://i'], 'trustAnchors' => { 'rootSpkiSha256' => ['aa'] },
                                      'policy' => { 'sevSnpMeasurements' => ['ab'] })
    rows << ['no resolver', v.verify({}, C09::BIND, C09::NOW), f.call('no Azure MAA evidence resolver configured (fail closed)')]
    none = f.call('no Azure MAA token for this action')
    [nil, [], { 'token' => nil }, { 'token' => 5 }, { 'token' => '' }, {}].each_with_index do |ev, i|
      rows << ["evidence #{i}", run.call(pay, evidence: ev), none]
    end
    rows << ['parse failure', run.call(pay, evidence: { 'token' => 'a.b' }),
             f.call('MAA token parse failed: parseMaaJwt: a compact JWS has exactly three dot-separated parts')]
    mj = C09.msg_js
    MutationKill::Seam.with(C09.cm, { parse_jws: ->(*) { raise mj, 'x' } }) do
      rows << ['parse failure text', run.call(pay), f.call('MAA token parse failed: JM')]
    end
    %w[none HS256 PS256 es256 RS512].each do |alg|
      rows << ["alg #{alg}", run.call(pay, header: { 'alg' => alg }), f.call("unsupported JWS alg '#{alg}' (MAA uses ES256 / RS256)")]
    end
    rows << ['RS256 accepted', run.call(pay, header: { 'alg' => 'RS256' }), C09::SEV_OK]
    seen = nil
    rows << ['signer: reason', run.call(pay, seams: { resolve_signing_x5c: ->(*) { { 'reason' => 'SR' } } }), f.call('SR')]
    rows << ['signer: neither', run.call(pay, seams: { resolve_signing_x5c: ->(*) { {} } }), f.call('no signing x5c available')]
    rows << ['signer: reason beats nothing', run.call(pay, seams: { resolve_signing_x5c: ->(*) { { 'reason' => 'SR', 'x' => 1 } } }), f.call('SR')]
    jwks = { 'keys' => [] }
    run.call(pay, header: { 'alg' => 'ES256' }, evidence: { 'token' => C09.az_token(pay, { 'alg' => 'ES256', 'kid' => 'k' }), 'jwks' => jwks },
             seams: { resolve_signing_x5c: ->(*args) { seen = args; { 'x5c' => ['X'] } } })
    rows << ['signer args', seen, [{ 'alg' => 'ES256', 'kid' => 'k' }, jwks]]
    chain_args = nil
    chain = ->(res) { { verify_x5c_chain: ->(*args) { chain_args = args; res } } }
    rows << ['chain: reason', run.call(pay, seams: chain.call({ 'ok' => false, 'reason' => 'CR' })), f.call('MAA signing chain invalid: CR')]
    rows << ['chain: no reason', run.call(pay, seams: chain.call({ 'ok' => false })), f.call('MAA signing chain invalid: untrusted')]
    rows << ['chain: ok without leaf', run.call(pay, seams: chain.call({ 'ok' => true })), f.call('MAA signing chain invalid: untrusted')]
    rows << ['chain: leaf but not ok', run.call(pay, seams: chain.call({ 'ok' => false, 'leaf' => :l })), f.call('MAA signing chain invalid: untrusted')]
    anchors = { 'rootSpkiSha256' => ['aa'] }
    run.call(pay, opts: { 'trustAnchors' => anchors, 'clockSkewMs' => 1500 }, seams: chain.call({ 'ok' => true, 'leaf' => :leaf }))
    rows << ['chain args', chain_args, [['X'], anchors, C09::NOW, 1500]]
    sig_args = nil
    sig = ->(res) { { verify_jws_signature: ->(*args) { sig_args = args; res } } }
    rows << ['signature refusal', run.call(pay, seams: sig.call('SIGERR')), f.call('SIGERR')]
    run.call(pay, seams: sig.call(nil))
    rows << ['signature args', [sig_args[0]['header'], sig_args[0]['payload'], sig_args[1]], [{ 'alg' => 'ES256' }, pay, :leaf]]
    me = C09.msg_err
    rows << ['fault', run.call(pay, seams: { resolve_signing_x5c: ->(*) { raise me, 'x' } }), f.call('azure-maa verification error (fail closed): MSG')]
    C09.chk(rows)
  end

  t('AzureMaaVerifier#verify: issuer, exp / nbf / iat windows at their boundaries, isolation-tee and attestation type') do
    next true if C09.skip?('azure.rb')

    run = C09.method(:az_run)
    f = C09.method(:fail_h)
    s = C09::NOW_SEC
    pay = C09.az_base_payload
    rows = []
    iss_msg = ->(i) { f.call("token iss '#{i}' is not a configured trusted MAA instance") }
    rows << ['iss missing', run.call(pay.reject { |k, _| k == 'iss' }), iss_msg.call('undefined')]
    rows << ['iss number', run.call(pay.merge('iss' => 5)), iss_msg.call('undefined')]
    rows << ['iss other', run.call(pay.merge('iss' => 'https://x')), iss_msg.call('https://x')]
    rows << ['iss empty', run.call(pay.merge('iss' => '')), iss_msg.call('')]
    rows << ['iss trailing slash', run.call(pay.merge('iss' => 'https://i/')), iss_msg.call('https://i/')]
    # an issuer list that (against the constructor) holds '' or nil must not make those pass
    odd = lambda do |payload|
      ev = { 'token' => C09.az_token(payload), 'jwks' => nil }
      v = C09.att::AzureMaaVerifier.new('trustedIssuers' => ['https://i'], 'trustAnchors' => { 'rootSpkiSha256' => ['aa'] },
                                        'policy' => { 'sevSnpMeasurements' => ['ab'] }, 'resolve_evidence' => ->(_d) { ev })
      v.instance_variable_set(:@issuers, ['', nil, 'https://i'])
      MutationKill::Seam.with(C09.az, { resolve_signing_x5c: ->(*) { { 'x5c' => ['X'] } }, verify_x5c_chain: ->(*) { { 'ok' => true, 'leaf' => :l } },
                                        verify_jws_signature: ->(*) {} }) { v.verify({}, C09::BIND, C09::NOW) }
    end
    rows << ['listed empty issuer', odd.call(pay.merge('iss' => '')), iss_msg.call('')]
    rows << ['listed nil issuer', odd.call(pay.reject { |k, _| k == 'iss' }), iss_msg.call('undefined')]
    rows << ['listed real issuer', odd.call(pay)['ok'], true]
    expired = f.call('MAA token expired')
    nbf = f.call('MAA token not yet valid (nbf)')
    iat = f.call('MAA token issued in the future (iat)')
    skew2 = { 'clockSkewMs' => 1500 }
    [[s, {}, C09::SEV_OK], [s - 1, {}, expired], [s - 2, skew2, C09::SEV_OK], [s - 3, skew2, expired], [s + 0.5, {}, C09::SEV_OK],
     [s - 0.5, {}, expired]].each do |exp, o, want|
      rows << ["exp #{exp} #{o.inspect}", run.call(pay.merge('exp' => exp), opts: o), want]
    end
    [[s, {}, C09::SEV_OK], [s + 1, {}, nbf], [s + 2, skew2, C09::SEV_OK], [s + 3, skew2, nbf], [s - 100, {}, C09::SEV_OK]].each do |n, o, want|
      rows << ["nbf #{n} #{o.inspect}", run.call(pay.merge('nbf' => n), opts: o), want]
    end
    [[s, {}, C09::SEV_OK], [s + 1, {}, iat], [s + 1, skew2, C09::SEV_OK], [s + 2, skew2, C09::SEV_OK], [s + 3, skew2, iat]].each do |n, o, want|
      rows << ["iat #{n} #{o.inspect}", run.call(pay.merge('iat' => n), opts: o), want]
    end
    no_exp = f.call('token has no exp (cannot bound validity — fail closed)')
    rows << ['exp missing', run.call(pay.reject { |k, _| k == 'exp' }), no_exp]
    rows << ['exp string', run.call(pay.merge('exp' => "#{s + 100}")), no_exp]
    rows << ['exp true', run.call(pay.merge('exp' => true)), no_exp]
    rows << ['nbf string is no nbf', run.call(pay.merge('nbf' => "#{s + 999_999}")), C09::SEV_OK]
    rows << ['iat string is no iat', run.call(pay.merge('iat' => "#{s + 999_999}")), C09::SEV_OK]
    rows << ['nbf true is no nbf', run.call(pay.merge('nbf' => true)), C09::SEV_OK]
    rows << ['iat null is no iat', run.call(pay.merge('iat' => nil)), C09::SEV_OK]
    rows << ['clock in ms', run.call(pay.merge('exp' => s + 1), now: C09::NOW + 999)['ok'], true]
    rows << ['clock past the second', run.call(pay.merge('exp' => s), now: C09::NOW + 1000), expired]
    # attestation type
    ty = ->(t) { f.call("unexpected x-ms-attestation-type '#{t}' (expected sevsnpvm | tdxvm)") }
    no_t = pay.reject { |k, _| k == 'x-ms-attestation-type' }
    rows << ['type missing', run.call(no_t), ty.call('undefined')]
    rows << ['type vbs', run.call(pay.merge('x-ms-attestation-type' => 'vbs')), ty.call('vbs')]
    rows << ['type number', run.call(pay.merge('x-ms-attestation-type' => 5)), ty.call('undefined')]
    rows << ['type in tee wins', run.call(no_t.merge('x-ms-isolation-tee' => { 'x-ms-attestation-type' => 'vbs' })), ty.call('vbs')]
    rows << ['tee without type: top-level type', run.call(no_t.merge('x-ms-attestation-type' => 'vbs', 'x-ms-isolation-tee' => {})), ty.call('vbs')]
    rows << ['tee without type, top-level number', run.call(pay.merge('x-ms-attestation-type' => 5, 'x-ms-isolation-tee' => {})), ty.call('undefined')]
    rows << ['tee type number: the top-level type is used', run.call(pay.merge('x-ms-isolation-tee' => { 'x-ms-attestation-type' => 5 })),
             f.call('token carries no report-data claim to bind the PCA challenge')]
    tee_claims = pay.slice('x-ms-sevsnpvm-reportdata', 'x-ms-sevsnpvm-launchmeasurement')
    top = pay.reject { |k, _| tee_claims.key?(k) }
    rows << ['claims read from the tee object', run.call(top.merge('x-ms-isolation-tee' => tee_claims)), C09::SEV_OK]
    rows << ['tee object type', run.call(top.reject { |k, _| k == 'x-ms-attestation-type' }.merge('x-ms-isolation-tee' => tee_claims.merge('x-ms-attestation-type' => 'sevsnpvm'))),
             C09::SEV_OK]
    rows << ['tee not an object is ignored', run.call(pay.merge('x-ms-isolation-tee' => 'str')), C09::SEV_OK]
    rows << ['tee array is ignored', run.call(pay.merge('x-ms-isolation-tee' => [1])), C09::SEV_OK]
    rows << ['expected nil', run.call(pay, expected: nil), f.call('no expected attestation binding supplied')]
    C09.chk(rows)
  end

  t('AzureMaaVerifier#verify: the PCA binding, runtime user-data or report-data, every refusal verbatim') do
    next true if C09.skip?('azure.rb')

    run = C09.method(:az_run)
    f = C09.method(:fail_h)
    cm = C09.cm
    want = cm.attestation_binding(C09::BIND)
    ud = want.unpack1('H*')
    pay = C09.az_base_payload
    rt_pol = { 'sevSnpMeasurements' => ['ab'], 'runtimeUserDataBinding' => true }
    rt = ->(runtime, o = {}) { run.call(pay.merge('x-ms-runtime' => runtime), policy: rt_pol.merge(o)) }
    rows = []
    no_rt = f.call('token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)')
    rows << ['runtime missing', run.call(pay, policy: rt_pol), no_rt]
    rows << ['runtime string', rt.call('x'), no_rt]
    rows << ['runtime array', rt.call([1]), no_rt]
    no_ud = f.call('x-ms-runtime carries no user-data to bind the PCA challenge')
    rows << ['user-data missing', rt.call({}), no_ud]
    rows << ['user-data empty', rt.call('user-data' => ''), no_ud]
    rows << ['user-data number', rt.call('user-data' => 5), no_ud]
    bound = f.call('runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)')
    rows << ['user-data other', rt.call('user-data' => '00' * 64), bound]
    rows << ['user-data undecodable', rt.call('user-data' => 'A'), bound]
    rows << ['user-data one byte short', rt.call('user-data' => ud[0, 126]), bound]
    rows << ['user-data ok', rt.call('user-data' => ud), C09::SEV_OK]
    rows << ['user-data ok, uppercase', rt.call('user-data' => ud.upcase), C09::SEV_OK]
    rows << ['user-data ok, 0x', rt.call('user-data' => "0x#{ud}"), C09::SEV_OK]
    rows << ['runtime ignores the report-data claim', run.call(pay.merge('x-ms-runtime' => { 'user-data' => ud }, 'x-ms-sevsnpvm-reportdata' => '00' * 64), policy: rt_pol), C09::SEV_OK]
    rd_no = f.call('token carries no report-data claim to bind the PCA challenge')
    no_rd = pay.reject { |k, _| k == 'x-ms-sevsnpvm-reportdata' }
    rows << ['report-data missing', run.call(no_rd), rd_no]
    rows << ['report-data empty', run.call(pay.merge('x-ms-sevsnpvm-reportdata' => '')), rd_no]
    rows << ['report-data number', run.call(pay.merge('x-ms-sevsnpvm-reportdata' => 5)), rd_no]
    rows << ['report-data undecodable', run.call(pay.merge('x-ms-sevsnpvm-reportdata' => 'A')), f.call('report-data claim is not decodable (hex/base64)')]
    rd_bad = f.call('report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)')
    rows << ['report-data other', run.call(pay.merge('x-ms-sevsnpvm-reportdata' => '00' * 64)), rd_bad]
    rows << ['report-data base64', run.call(pay.merge('x-ms-sevsnpvm-reportdata' => [want].pack('m0'))), C09::SEV_OK]
    sha = Digest::SHA256.digest(want).unpack1('H*')
    pol_sha = { 'sevSnpMeasurements' => ['ab'], 'reportDataHash' => 'sha256' }
    rows << ['report-data sha256', run.call(pay.merge('x-ms-sevsnpvm-reportdata' => sha), policy: pol_sha), C09::SEV_OK]
    rows << ['report-data raw under sha256 policy', run.call(pay, policy: pol_sha), rd_bad]
    sha5 = Digest::SHA512.digest(want).unpack1('H*')
    rows << ['report-data sha512', run.call(pay.merge('x-ms-sevsnpvm-reportdata' => sha5), policy: pol_sha.merge('reportDataHash' => 'sha512')), C09::SEV_OK]
    tdx_pay = pay.reject { |k, _| k.start_with?('x-ms-sevsnpvm') }.merge('x-ms-attestation-type' => 'tdxvm', 'x-ms-tdx-mrtd' => 'cd')
    rows << ['tdx report-data claim', run.call(tdx_pay.merge('x-ms-tdx-report-data' => ud))['ok'], true]
    rows << ['tdx ignores the sev report-data key', run.call(tdx_pay.merge('x-ms-sevsnpvm-reportdata' => ud)), rd_no]
    rows << ['sev ignores the tdx report-data key', run.call(no_rd.merge('x-ms-tdx-report-data' => ud)), rd_no]
    mj = C09.msg_js
    MutationKill::Seam.with(cm, { attestation_binding: ->(_e) { raise mj, 'x' } }) do
      rows << ['binding fault (report-data)', run.call(pay), f.call('binding not constructible: JM')]
      rows << ['binding fault (runtime)', rt.call('user-data' => ud), f.call('binding not constructible: JM')]
    end
    orig = cm.method(:first_string)
    MutationKill::Seam.with(cm, { first_string: ->(rec, keys) { keys.equal?(C09.az::SEVSNP_REPORTDATA_KEYS) ? '' : orig.call(rec, keys) } }) do
      rows << ['report-data claim that reads back empty', run.call(pay), rd_no]
    end
    C09.chk(rows)
  end

  t('AzureMaaVerifier sev_result / tdx_result: allowlists, debug flags, SVN floors, TCB status and the exact identity') do
    next true if C09.skip?('azure.rb')

    k = C09.att::AzureMaaVerifier
    z = C09.az
    cm = C09.cm
    fl = ->(r) { { 'ok' => false, 'reason' => r } }
    mk = lambda do |pol|
      k.new('trustedIssuers' => ['https://i'], 'trustAnchors' => { 'rootSpkiSha256' => ['aa'] }, 'policy' => pol)
    end
    sev = lambda do |pol, tee|
      v = mk.call({ 'sevSnpMeasurements' => ['ab'] }.merge(pol))
      v.send(:sev_result, v.instance_variable_get(:@policy), tee, fl)
    end
    tee = { 'x-ms-sevsnpvm-launchmeasurement' => 'AB' }
    sev_ok = lambda do |extra = {}, host = {}|
      { 'ok' => true, 'bound' => true,
        'measured' => { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => 'ab', 'operator' => '' },
        'hostAsserted' => { 'attestation_type' => 'sevsnpvm' }.merge(host) }.merge(extra)
    end
    rows = []
    v_tdx = mk.call({ 'tdxMrtds' => ['cd'] })
    rows << ['no sev list', v_tdx.send(:sev_result, v_tdx.instance_variable_get(:@policy), tee, fl),
             fl.call('sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)')]
    rows << ['ok, lower-cased', sev.call({}, tee), sev_ok.call]
    rows << ['measurement missing', sev.call({}, {}), fl.call('sevsnpvm token carries no launch-measurement claim')]
    rows << ['measurement empty', sev.call({}, { 'x-ms-sevsnpvm-launchmeasurement' => '' }), fl.call('sevsnpvm token carries no launch-measurement claim')]
    rows << ['measurement number', sev.call({}, { 'x-ms-sevsnpvm-launchmeasurement' => 5 }), fl.call('sevsnpvm token carries no launch-measurement claim')]
    rows << ['measurement other', sev.call({}, { 'x-ms-sevsnpvm-launchmeasurement' => 'ff' }), fl.call('SEV-SNP launch measurement not in policy allowlist')]
    rows << ['allowlist upper', sev.call({ 'sevSnpMeasurements' => ['AB'] }, tee), sev_ok.call]
    orig = cm.method(:first_string)
    empty_for = ->(keys) { ->(rec, ks) { ks.equal?(keys) ? '' : orig.call(rec, ks) } }
    MutationKill::Seam.with(cm, { first_string: empty_for.call(z::SEVSNP_MEASUREMENT_KEYS) }) do
      rows << ['measurement reads back empty', sev.call({}, tee), fl.call('sevsnpvm token carries no launch-measurement claim')]
    end
    dbg = fl.call('SEV-SNP guest is debuggable (no confidentiality)')
    rows << ['debuggable', sev.call({}, tee.merge('x-ms-sevsnpvm-is-debuggable' => true)), dbg]
    rows << ['debuggable, allowed', sev.call({ 'allowDebug' => true }, tee.merge('x-ms-sevsnpvm-is-debuggable' => true)), sev_ok.call]
    rows << ['debuggable, allowDebug string', sev.call({ 'allowDebug' => 'yes' }, tee.merge('x-ms-sevsnpvm-is-debuggable' => true)), dbg]
    rows << ['debuggable false', sev.call({}, tee.merge('x-ms-sevsnpvm-is-debuggable' => false)), sev_ok.call]
    rows << ['debuggable string', sev.call({}, tee.merge('x-ms-sevsnpvm-is-debuggable' => 'true')), sev_ok.call]
    hd = fl.call('SEV-SNP host-data not in policy allowlist')
    hkey = 'x-ms-sevsnpvm-hostdata'
    rows << ['host-data pinned, missing', sev.call({ 'sevSnpHostData' => ['aa'] }, tee), hd]
    rows << ['host-data pinned, other', sev.call({ 'sevSnpHostData' => ['aa'] }, tee.merge(hkey => 'bb')), hd]
    rows << ['host-data pinned, upper', sev.call({ 'sevSnpHostData' => ['aa'] }, tee.merge(hkey => 'AA')), sev_ok.call({}, 'host_data' => 'aa')]
    rows << ['host-data pinned, upper list', sev.call({ 'sevSnpHostData' => ['AA'] }, tee.merge(hkey => 'aa')), sev_ok.call({}, 'host_data' => 'aa')]
    rows << ['host-data, empty list', sev.call({ 'sevSnpHostData' => [] }, tee), sev_ok.call]
    rows << ['host-data, string list refused at construction', C09.err { sev.call({ 'sevSnpHostData' => 'aa' }, tee) }, [C09.att::AttestConstructError, 'createAzureMaaVerifier: policy.sevSnpHostData must be an array of strings']]
    rows << ['host-data reported', sev.call({}, tee.merge(hkey => 'AA')), sev_ok.call({}, 'host_data' => 'aa')]
    MutationKill::Seam.with(cm, { first_string: empty_for.call(z::SEVSNP_HOSTDATA_KEYS) }) do
      rows << ['host-data reads back empty, pinned', sev.call({ 'sevSnpHostData' => ['aa', ''] }, tee), hd]
      rows << ['host-data reads back empty, unpinned', sev.call({}, tee), sev_ok.call]
    end
    # SVN claims
    svn = lambda do |name, claim, host_key|
      [name, claim, host_key]
    end
    bl = svn.call('bootloader', 'x-ms-sevsnpvm-bootloader-svn', 'bootloader_svn')
    snp = svn.call('snp', 'x-ms-sevsnpvm-snpfw-svn', 'snpfw_svn')
    miss = ->(name, claim) { fl.call("SEV-SNP #{name} SVN claim '#{claim}' is missing or not a non-negative integer (policy requires a minimum)") }
    all = { 'x-ms-sevsnpvm-bootloader-svn' => 3, 'x-ms-sevsnpvm-snpfw-svn' => 4.0, 'x-ms-sevsnpvm-microcode-svn' => 5, 'x-ms-sevsnpvm-tee-svn' => 0 }
    rows << ['svn reported', sev.call({}, tee.merge(all)),
             sev_ok.call({}, 'bootloader_svn' => '3', 'snpfw_svn' => '4', 'microcode_svn' => '5', 'tee_svn' => '0')]
    [[-0.0, false], [0.0, true], [-1, false], [2.5, false], ['3', false], [nil, false], [true, false], [Float::INFINITY, false], [7, true]].each do |raw, reported|
      host = reported ? { 'bootloader_svn' => (raw.is_a?(Float) ? raw.to_i.to_s : raw.to_s) } : {}
      rows << ["svn #{raw.inspect} reported=#{reported}", sev.call({}, tee.merge('x-ms-sevsnpvm-bootloader-svn' => raw)), sev_ok.call({}, host)]
    end
    rows << ['svn -0 under a floor', sev.call({ 'sevSnpMinTcb' => { 'bootloader' => 0 } }, tee.merge(bl[1] => -0.0)), miss.call(bl[0], bl[1])]
    rows << ['svn missing under a floor', sev.call({ 'sevSnpMinTcb' => { 'snp' => 0 } }, tee), miss.call(snp[0], snp[1])]
    rows << ['svn string under a floor', sev.call({ 'sevSnpMinTcb' => { 'snp' => 0 } }, tee.merge(snp[1] => '5')), miss.call(snp[0], snp[1])]
    rows << ['svn below floor', sev.call({ 'sevSnpMinTcb' => { 'snp' => 6 } }, tee.merge(snp[1] => 5)), fl.call('SEV-SNP snp SVN 5 is below the policy minimum 6')]
    rows << ['svn below floor, floats', sev.call({ 'sevSnpMinTcb' => { 'snp' => 6.0 } }, tee.merge(snp[1] => 5.0)),
             fl.call('SEV-SNP snp SVN 5 is below the policy minimum 6')]
    rows << ['svn at floor', sev.call({ 'sevSnpMinTcb' => { 'snp' => 5 } }, tee.merge(snp[1] => 5)), sev_ok.call({}, 'snpfw_svn' => '5')]
    rows << ['svn above floor', sev.call({ 'sevSnpMinTcb' => { 'snp' => 4 } }, tee.merge(snp[1] => 5)), sev_ok.call({}, 'snpfw_svn' => '5')]
    rows << ['floors not an object', C09.err { mk.call({ 'sevSnpMeasurements' => ['ab'] }).send(:sev_result, { 'sevSnpMeasurements' => ['ab'], 'sevSnpMinTcb' => [] }, tee.merge(snp[1] => 1), fl) }, nil]
    # TDX
    tdx = lambda do |pol, t|
      v = mk.call({ 'tdxMrtds' => ['cd'] }.merge(pol))
      v.send(:tdx_result, v.instance_variable_get(:@policy), t, fl)
    end
    tt = { 'x-ms-tdx-mrtd' => 'CD' }
    tdx_ok = lambda do |host = {}|
      { 'ok' => true, 'bound' => true,
        'measured' => { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => 'cd', 'operator' => '' },
        'hostAsserted' => { 'attestation_type' => 'tdxvm' }.merge(host) }
    end
    v_sev = mk.call({ 'sevSnpMeasurements' => ['ab'] })
    rows << ['no tdx list', v_sev.send(:tdx_result, v_sev.instance_variable_get(:@policy), tt, fl), fl.call('tdxvm token but policy configures no TDX MRTD allowlist (fail closed)')]
    rows << ['tdx ok', tdx.call({}, tt), tdx_ok.call]
    rows << ['tdx ok, alternate key', tdx.call({}, { 'tdx_mrtd' => 'cd' }), tdx_ok.call]
    rows << ['mrtd missing', tdx.call({}, {}), fl.call('tdxvm token carries no MRTD claim')]
    rows << ['mrtd empty', tdx.call({}, { 'x-ms-tdx-mrtd' => '' }), fl.call('tdxvm token carries no MRTD claim')]
    rows << ['mrtd other', tdx.call({}, { 'x-ms-tdx-mrtd' => 'ee' }), fl.call('TDX MRTD not in policy allowlist')]
    rows << ['mrtd allowlist upper', tdx.call({ 'tdxMrtds' => ['CD'] }, tt), tdx_ok.call]
    MutationKill::Seam.with(cm, { first_string: empty_for.call(z::TDX_MRTD_KEYS) }) do
      rows << ['mrtd reads back empty', tdx.call({}, tt), fl.call('tdxvm token carries no MRTD claim')]
    end
    tdbg = fl.call('TDX guest is debuggable (no confidentiality)')
    rows << ['td debug', tdx.call({}, tt.merge('tdx_td_attributes_debug' => true)), tdbg]
    rows << ['td debug, allowed', tdx.call({ 'allowDebug' => true }, tt.merge('tdx_td_attributes_debug' => true)), tdx_ok.call]
    rows << ['td debug string', tdx.call({}, tt.merge('tdx_td_attributes_debug' => 'true')), tdx_ok.call]
    rows << ['dbgstat enabled', tdx.call({}, tt.merge('dbgstat' => 'enabled')), tdbg]
    rows << ['dbgstat enabled, allowed', tdx.call({ 'allowDebug' => true }, tt.merge('dbgstat' => 'enabled')), tdx_ok.call]
    rows << ['dbgstat enabled, allowDebug string', tdx.call({ 'allowDebug' => 'yes' }, tt.merge('dbgstat' => 'enabled')), tdbg]
    rows << ['dbgstat disabled', tdx.call({}, tt.merge('dbgstat' => 'disabled')), tdx_ok.call]
    rows << ['dbgstat number', tdx.call({}, tt.merge('dbgstat' => 5)), tdx_ok.call]
    st = ->(s) { fl.call("TDX platform TCB status '#{s}' is not accepted by policy") }
    rows << ['status UpToDate', tdx.call({}, tt.merge('attester_tcb_status' => 'UpToDate')), tdx_ok.call('tcb_status' => 'UpToDate')]
    rows << ['status SWHardeningNeeded', tdx.call({}, tt.merge('attester_tcb_status' => 'SWHardeningNeeded')), tdx_ok.call('tcb_status' => 'SWHardeningNeeded')]
    rows << ['status OutOfDate', tdx.call({}, tt.merge('attester_tcb_status' => 'OutOfDate')), st.call('OutOfDate')]
    rows << ['status number is none', tdx.call({}, tt.merge('attester_tcb_status' => 5)), tdx_ok.call]
    rows << ['status policy list', tdx.call({ 'tdxAllowedTcbStatuses' => ['OutOfDate'] }, tt.merge('attester_tcb_status' => 'OutOfDate')), tdx_ok.call('tcb_status' => 'OutOfDate')]
    rows << ['status policy list refuses default', tdx.call({ 'tdxAllowedTcbStatuses' => ['OutOfDate'] }, tt.merge('attester_tcb_status' => 'UpToDate')), st.call('UpToDate')]
    rows << ['status empty list refuses', tdx.call({ 'tdxAllowedTcbStatuses' => [] }, tt.merge('attester_tcb_status' => 'UpToDate')), st.call('UpToDate')]
    rows << ['status empty string not reported', tdx.call({ 'tdxAllowedTcbStatuses' => [''] }, tt.merge('attester_tcb_status' => '')), tdx_ok.call]
    rt = fl.call('TDX RTMR0 not in policy allowlist')
    rows << ['rtmr pinned, missing', tdx.call({ 'tdxRtmrs' => ['aa'] }, tt), rt]
    rows << ['rtmr pinned, other', tdx.call({ 'tdxRtmrs' => ['aa'] }, tt.merge('x-ms-tdx-rtmr0' => 'bb')), rt]
    rows << ['rtmr pinned, upper', tdx.call({ 'tdxRtmrs' => ['aa'] }, tt.merge('tdx_rtmr0' => 'AA')), tdx_ok.call('rtmr0' => 'aa')]
    rows << ['rtmr pinned, upper list', tdx.call({ 'tdxRtmrs' => ['AA'] }, tt.merge('tdx_rtmr0' => 'aa')), tdx_ok.call('rtmr0' => 'aa')]
    rows << ['rtmr empty list', tdx.call({ 'tdxRtmrs' => [] }, tt), tdx_ok.call]
    rows << ['rtmr string list refused at construction', C09.err { tdx.call({ 'tdxRtmrs' => 'aa' }, tt) }, [C09.att::AttestConstructError, 'createAzureMaaVerifier: policy.tdxRtmrs must be an array of strings']]
    rows << ['rtmr reported', tdx.call({}, tt.merge('tdx_rtmr0' => 'AA')), tdx_ok.call('rtmr0' => 'aa')]
    MutationKill::Seam.with(cm, { first_string: empty_for.call(z::TDX_RTMR0_KEYS) }) do
      rows << ['rtmr reads back empty, pinned', tdx.call({ 'tdxRtmrs' => ['aa', ''] }, tt), rt]
      rows << ['rtmr reads back empty, unpinned', tdx.call({}, tt), tdx_ok.call]
    end
    C09.chk(rows)
  end
end
