# frozen_string_literal: true

# AMD SEV-SNP attestation verifier (native counterpart of `createAmdSnpVerifier`).
#
# Parses and verifies a genuine SEV-SNP ATTESTATION_REPORT: the VCEK -> ASK -> ARK chain to a PINNED per-family ARK, the
# ECDSA-P384 / SHA-384 report signature under the VCEK, the VCEK <-> report binding (CHIP_ID + reported-TCB SPLs), the PCA
# nonce binding (direct `report-data`, or Azure `azure-runtime-data`), and the acceptance policy. Fails closed; the reason
# strings are those of the reference implementation.
require_relative 'cert'

module AtlasPca
  module Attest
    # A policy value that the reference holds as a BigInt (compared as a whole u64).
    BigU64 = Struct.new(:v)

    module Amd
      SUITE = 'amd-sev-snp-ecdsa-p384'
      ARK_SPKI_SHA384 = {
        'milan' => '1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e',
        'genoa' => '32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880',
        'turin' => '3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5'
      }.freeze
      P384_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
      POLICY_DEBUG_BIT = 1 << 19

      # ATTESTATION_REPORT layout (AMD SEV-SNP ABI specification), little-endian
      VERSION = 0x000
      GUEST_SVN = 0x004
      POLICY = 0x008
      VMPL = 0x030
      SIGNATURE_ALGO = 0x034
      CURRENT_TCB = 0x038
      REPORT_DATA = 0x050
      MEASUREMENT = 0x090
      HOST_DATA = 0x0C0
      REPORTED_TCB = 0x180
      CHIP_ID = 0x1A0
      COMMITTED_TCB = 0x1E0
      LAUNCH_TCB = 0x1F0
      SIGNED_END = 0x2A0
      SIG_R = 0x2A0
      SIG_S = 0x2E8
      REPORT_LEN = 0x4A0

      OID_HWID = '1.3.6.1.4.1.3704.1.4'
      OID_BL_SPL = '1.3.6.1.4.1.3704.1.3.1'
      OID_TEE_SPL = '1.3.6.1.4.1.3704.1.3.2'
      OID_SNP_SPL = '1.3.6.1.4.1.3704.1.3.3'
      OID_UCODE_SPL = '1.3.6.1.4.1.3704.1.3.8'
      HWID_LEN = 64

      module_function

      def u32(b, o) = b.byteslice(o, 4).unpack1('V')
      def u64(b, o) = b.byteslice(o, 8).unpack1('Q<')
      def le_int(b) = b.reverse.unpack1('H*').to_i(16)

      # Parse the report layout. Raises ArgumentError when the buffer cannot hold the signed region and the r / s fields.
      def parse_sev_snp_report(b)
        min_len = SIG_S + 72
        raise ArgumentError, "parseSevSnpReport: report too short (#{b.bytesize} < #{min_len})" if b.bytesize < min_len

        b = b.b
        {
          'version' => u32(b, VERSION), 'guest_svn' => u32(b, GUEST_SVN), 'policy' => u64(b, POLICY), 'vmpl' => u32(b, VMPL),
          'signature_algo' => u32(b, SIGNATURE_ALGO), 'current_tcb' => u64(b, CURRENT_TCB),
          'report_data' => b.byteslice(REPORT_DATA, 64), 'measurement' => b.byteslice(MEASUREMENT, 48),
          'host_data' => b.byteslice(HOST_DATA, 32), 'reported_tcb' => u64(b, REPORTED_TCB), 'chip_id' => b.byteslice(CHIP_ID, 64),
          'committed_tcb' => u64(b, COMMITTED_TCB), 'launch_tcb' => u64(b, LAUNCH_TCB),
          'sig_r' => b.byteslice(SIG_R, 72), 'sig_s' => b.byteslice(SIG_S, 72), 'signed' => b.byteslice(0, SIGNED_END)
        }
      end

      # ECDSA-P384 / SHA-384 over the signed region, AMD's little-endian r || s. Never raises (fail closed).
      def verify_sev_snp_report_signature(report, vcek_key)
        r = le_int(report['sig_r'])
        s = le_int(report['sig_s'])
        return false if r <= 0 || r >= P384_N || s <= 0 || s >= P384_N

        der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
        Common.ecdsa_verify_der(vcek_key, der, report['signed'], 'sha384')
      rescue StandardError
        false
      end

      # One DER INTEGER, minimally encoded, 0..255: the number, or a failure string.
      def decode_spl(v)
        return 'is not a DER INTEGER' if v.bytesize < 3 || v.getbyte(0) != 0x02

        ln = v.getbyte(1)
        return 'has a wrong-length INTEGER' if ln < 1 || ln > 2 || v.bytesize != 2 + ln

        c0 = v.getbyte(2)
        return 'is negative' if c0.anybits?(0x80)

        if ln == 2
          return 'is out of range (> 255)' if c0 != 0x00
          return 'is a non-minimal INTEGER' if v.getbyte(3).nobits?(0x80)

          return v.getbyte(3)
        end
        c0
      end

      # Bind the VCEK certificate body to the report: hwID == chip_id and the four SPL extensions == REPORTED_TCB bytes.
      def check_vcek_report_binding(vcek_tbs, report)
        begin
          exts = Der.parse_tbs_extensions(vcek_tbs)
        rescue DerError => e
          return "VCEK extensions malformed: #{e.message}"
        end
        hw = exts[OID_HWID]
        return 'VCEK certificate has no CHIP_ID (hwID) extension' if hw.nil?
        return 'VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)' if hw.critical
        return "VCEK CHIP_ID (hwID) extension is #{hw.value.bytesize} bytes, expected #{HWID_LEN}" if hw.value.bytesize != HWID_LEN
        return 'VCEK CHIP_ID does not match report chip_id' if hw.value != report['chip_id']

        t = report['reported_tcb']
        byte_at = ->(i) { (t >> (8 * i)) & 0xFF }
        [[OID_BL_SPL, 'bootloader', byte_at.call(0)], [OID_TEE_SPL, 'tee', byte_at.call(1)],
         [OID_SNP_SPL, 'snp', byte_at.call(6)], [OID_UCODE_SPL, 'microcode', byte_at.call(7)]].each do |oid, name, want|
          ext = exts[oid]
          return "VCEK certificate has no #{name} SPL extension" if ext.nil?
          return "VCEK #{name} SPL extension is marked critical (the AMD profile is non-critical)" if ext.critical

          got = decode_spl(ext.value)
          return "VCEK #{name} SPL extension #{got}" if got.is_a?(String)
          return "VCEK #{name} SPL #{got} does not match report reported_tcb (#{want}) — TCB downgrade?" if got != want
        end
        nil
      end

      # VCEK -> ASK -> ARK, the ARK pinned by its SPKI SHA-384 (never taken from the supplied chain).
      def verify_amd_cert_chain(vcek_der, ask_ark_pem, trust_anchor, now_ms, clock_skew_ms = nil)
        return { 'ok' => false, 'reason' => 'nowMs (verifier clock) is required for the AMD chain validity check' } unless Common.num?(now_ms)

        skew = clock_skew_ms.nil? ? 0 : clock_skew_ms
        return { 'ok' => false, 'reason' => 'clockSkewMs must be a non-negative number' } if !Common.num?(skew) || skew.negative?

        vcek = Cert.new(vcek_der)
        pems = Common.pem_blocks(ask_ark_pem)
        if pems.length != 2
          return { 'ok' => false, 'reason' => 'ASK+ARK chain must contain exactly two certificates (ASK then ARK)' }
        end

        ask = Cert.from_pem(pems[0])
        ark = Cert.from_pem(pems[1])
        if ark.subject != ark.issuer || !ark.verify_self
          return { 'ok' => false, 'reason' => 'second certificate of the chain is not a self-signed ARK (chain out of order?)' }
        end
        if ask.subject == ask.issuer
          return { 'ok' => false, 'reason' => 'first certificate of the chain is self-signed, not an ASK (chain out of order?)' }
        end
        return { 'ok' => false, 'reason' => 'ASK subject does not match the VCEK issuer' } if ask.subject != vcek.issuer

        pin = (trust_anchor.nil? ? ARK_SPKI_SHA384['milan'] : trust_anchor).downcase
        return { 'ok' => false, 'reason' => 'ARK does not match the pinned AMD trust anchor' } if ark.spki_sha('sha384') != pin
        return { 'ok' => false, 'reason' => 'ASK is not signed by ARK' } if ask.issuer != ark.subject || !ask.verify(ark.public_key)
        return { 'ok' => false, 'reason' => 'VCEK is not signed by ASK' } unless vcek.verify(ask.public_key)

        ders = [['VCEK', vcek_der.b, vcek], ['ASK', ask.raw, ask], ['ARK', ark.raw, ark]]
        role_err = Der.check_chain_roles(ders.map { |d| d[1] })
        return { 'ok' => false, 'reason' => "AMD chain role check failed: #{role_err}" } if role_err

        ders.each do |label, der, cert|
          exts = Der.parse_cert_extensions(der)
          exts.each do |oid, ext|
            if ext.critical && !Der::RECOGNISED_CRITICAL_EXTENSIONS.include?(oid)
              return { 'ok' => false, 'reason' => "#{label} certificate has an unrecognised critical extension #{oid}" }
            end
          end
          bc = exts['2.5.29.19']
          if label != 'VCEK' && !(!bc.nil? && bc.critical == true)
            return { 'ok' => false, 'reason' => "#{label} certificate BasicConstraints is not marked critical" }
          end

          lo, hi = Der.der_validity_ms(cert.raw)
          return { 'ok' => false, 'reason' => "#{label} certificate validity is unparseable" } if lo.nil? || hi.nil?
          return { 'ok' => false, 'reason' => "#{label} certificate is not yet valid" } if now_ms + skew < lo
          return { 'ok' => false, 'reason' => "#{label} certificate has expired" } if now_ms - skew > hi
        end
        pk = vcek.public_key
        if Common.key_type(pk) != 'ec' || Common.node_curve(pk) != 'secp384r1'
          raise JsTypeError, "VCEK is not EC secp384r1 (got #{Common.key_type(pk)}/#{Common.node_curve(pk) || 'undefined'})"
        end

        key = Common.ec_key_from_point('P-384', Common.ec_point(pk, 'P-384'))
        { 'ok' => true, 'vcek' => key, 'vcekTbs' => Der.tbs_of_certificate(vcek_der) }
      rescue StandardError => e
        { 'ok' => false, 'reason' => "AMD chain verification error: #{e.message}" }
      end

      def fmt_num(v) = Common.js_str(v)

      def check_sev_snp_policy(report, policy)
        return "unexpected signature_algo #{report['signature_algo']}" if policy['requireEcdsaP384'] != false && report['signature_algo'] != 1
        if policy['allowDebug'] != true && report['policy'].anybits?(POLICY_DEBUG_BIT)
          return 'guest policy has the DEBUG bit set (host can inspect the guest)'
        end

        mg = policy['minGuestSvn']
        return "guest_svn #{report['guest_svn']} below minimum #{fmt_num(mg)}" if Common.num?(mg) && report['guest_svn'] < mg

        v = policy['minReportedTcb']
        return 'reported_tcb below minimum (rollback?)' if v.is_a?(BigU64) && report['reported_tcb'] < v.v

        v = policy['minCommittedTcb']
        return 'committed_tcb below minimum (rollback?)' if v.is_a?(BigU64) && report['committed_tcb'] < v.v

        v = policy['minLaunchTcb']
        return 'launch_tcb below minimum' if v.is_a?(BigU64) && report['launch_tcb'] < v.v

        want_vmpl = policy['requireVmpl']
        want_vmpl = 0 if want_vmpl.nil?
        if want_vmpl != 'any' && !(Common.num?(want_vmpl) && report['vmpl'] == want_vmpl)
          return "vmpl #{report['vmpl']} is not the required #{fmt_num(want_vmpl)}"
        end

        meas = policy['measurements']
        if meas.is_a?(Array) && !meas.empty? && !meas.map { |x| x.downcase }.include?(Common.to_hex(report['measurement']))
          return 'measurement not in policy allowlist'
        end

        hd = policy['hostData']
        if hd.is_a?(Array) && !hd.empty? && !hd.map { |x| x.downcase }.include?(Common.to_hex(report['host_data']))
          return 'host_data not in policy allowlist'
        end

        ci = policy['chipIds']
        if ci.is_a?(Array) && !ci.empty? && !ci.map { |x| x.downcase }.include?(Common.to_hex(report['chip_id']))
          return 'chip_id not in policy allowlist'
        end
        nil
      end

      def default_identity(report)
        { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false,
          'runtime_measurement' => Common.to_hex(report['measurement']), 'operator' => Common.to_hex(report['chip_id']) }
      end

      # Parse and verify a genuine report end to end, offline. Fails closed with a reason.
      def verify_genuine_sev_snp_report(report, vcek_der, ask_ark_pem, trust_anchor, now_ms, clock_skew_ms = nil, expected = nil, policy = nil)
        begin
          rep = parse_sev_snp_report(report)
        rescue ArgumentError => e
          return { 'ok' => false, 'reason' => "report parse failed: #{e.message}" }
        end
        # exactly 1184 bytes; the signature block beyond r and s is reserved-zero (anything else is a second encoding)
        if report.bytesize != REPORT_LEN
          return { 'ok' => false, 'reason' => "report length #{report.bytesize} is not the canonical #{REPORT_LEN}" }
        end
        if report.byteslice(SIG_S + 72..).bytes.any? { |x| x != 0 } || report.byteslice(SIG_R + 48, 24).bytes.any? { |x| x != 0 } ||
           report.byteslice(SIG_S + 48, 24).bytes.any? { |x| x != 0 }
          return { 'ok' => false, 'reason' => 'report signature block has non-zero reserved bytes' }
        end

        chain = verify_amd_cert_chain(vcek_der, ask_ark_pem, trust_anchor, now_ms, clock_skew_ms)
        return { 'ok' => false, 'reason' => "cert chain invalid: #{chain['reason'].nil? ? 'undefined' : chain['reason']}" } if !chain['ok'] || !chain.key?('vcek')
        return { 'ok' => false, 'reason' => 'report signature does not verify under VCEK' } unless verify_sev_snp_report_signature(rep, chain['vcek'])

        bind_err = check_vcek_report_binding(chain['vcekTbs'], rep)
        return { 'ok' => false, 'reason' => bind_err } if bind_err

        if !expected.nil? && Common.attestation_binding(expected) != rep['report_data']
          return { 'ok' => false, 'reason' => 'report_data does not bind holder/grant/epoch/nonce' }
        end
        unless policy.nil?
          pol_err = check_sev_snp_policy(rep, policy)
          return { 'ok' => false, 'reason' => pol_err } if pol_err
        end
        { 'ok' => true, 'report' => rep, 'measured' => default_identity(rep) }
      rescue StandardError => e
        { 'ok' => false, 'reason' => "genuine verification error (fail closed): #{e.message}" }
      end

      # The Azure binding: report_data[0:32] = sha256(runtime-data JSON), [32:64] = 0, and its 64-byte `user-data` = the PCA binding.
      def check_azure_runtime_data_binding(report_data, runtime_data, expected)
        return 'report_data is not 64 bytes' if report_data.bytesize != 64
        return 'report_data[32:64] is not zero (not an Azure runtime-data hash)' if report_data.byteslice(32, 32).bytes.any? { |x| x != 0 }
        return 'sha256(runtime data) does not equal the quote report_data' if Digest::SHA256.digest(runtime_data) != report_data.byteslice(0, 32)

        begin
          parsed = Common.js_json_loads(runtime_data.dup.force_encoding('UTF-8').scrub("�"))
        rescue JsError
          return 'runtime data is not valid JSON'
        end
        return 'runtime data is not a JSON object' unless parsed.is_a?(Hash)

        user_data = parsed['user-data']
        return 'runtime data carries no 64-byte hex user-data' if !user_data.is_a?(String) || user_data.length != 128 || !Common.hex?(user_data)

        begin
          want = Common.attestation_binding(expected)
        rescue JsTypeError => e
          return "binding not constructible: #{e.message}"
        end
        return 'runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)' if [user_data].pack('H*') != want

        nil
      end
    end

    # `verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}.
    class AmdSnpVerifier
      def initialize(opts)
        pol = opts['policy']
        policy = pol.is_a?(Hash) ? pol.dup : {}
        %w[minReportedTcb minCommittedTcb minLaunchTcb].each { |k| policy[k] = BigU64.new(Common.big_int(policy[k])) if policy.key?(k) }
        family = opts['family']
        pin = family.is_a?(String) ? Amd::ARK_SPKI_SHA384[family] : nil
        override = opts['trustAnchorArkSpkiSha384']
        pin = override if !override.nil? && family.is_a?(String) && Amd::ARK_SPKI_SHA384.key?(family) # conformance harness only
        raise AttestConstructError, "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'" if pin.nil? || pin.empty?

        @pin = pin
        @family = family
        unless %w[report-data azure-runtime-data].include?(opts['binding'])
          raise AttestConstructError, "createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'"
        end

        @binding = opts['binding']
        meas = policy['measurements']
        if !meas.is_a?(Array) || meas.empty?
          raise AttestConstructError, 'createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)'
        end

        policy['measurements'] = meas.dup # a private copy: an allowlist emptied after construction must not become accept-all
        @policy = policy
        @skew = opts['clockSkewMs']
        @resolve = opts['resolve_evidence']
      end

      def verify(document, expected, now_ms)
        fail_with = ->(reason) { { 'ok' => false, 'reason' => reason } }
        return fail_with.call('no AMD SEV-SNP evidence resolver configured (fail closed)') if @resolve.nil?

        ev = @resolve.call(document)
        unless ev.is_a?(Hash) && ev['report'].is_a?(String) && ev['vcekDer'].is_a?(String) && ev['askArkPem'].is_a?(String)
          return fail_with.call('no AMD SEV-SNP evidence for this action')
        end
        return fail_with.call('no expected attestation binding supplied') if expected.nil?

        direct = @binding == 'report-data'
        r = Amd.verify_genuine_sev_snp_report(ev['report'], ev['vcekDer'], ev['askArkPem'], @pin, now_ms, @skew,
                                              direct ? expected : nil, @policy)
        if !r['ok'] || !r.key?('report') || !r.key?('measured')
          return fail_with.call("SEV-SNP report invalid: #{r['reason'] || 'unknown'}")
        end

        unless direct
          rd = ev['runtimeData']
          return fail_with.call('azure-runtime-data binding needs the runtime-data JSON bytes') unless rd.is_a?(String)

          why = Amd.check_azure_runtime_data_binding(r['report']['report_data'], rd, expected)
          return fail_with.call(why) if why
        end
        { 'ok' => true, 'bound' => true, 'measured' => r['measured'],
          'hostAsserted' => { 'attestation_type' => 'amd-sev-snp', 'family' => @family,
                              'measurement' => Common.to_hex(r['report']['measurement']) } }
      rescue StandardError => e
        fail_with.call("amd-snp verification error (fail closed): #{e.message}")
      end
    end
  end
end
