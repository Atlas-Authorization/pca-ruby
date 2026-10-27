# frozen_string_literal: true

# NVIDIA GPU (Hopper / Blackwell, CC mode) SPDM attestation verifier and its RIM / CRL / OCSP collateral hook.
#
# Native counterpart of `createNvidiaSpdmVerifier` and `nvidiaCollateralHook`: the device chain to a PINNED NVIDIA root, the SPDM
# GET_MEASUREMENTS transcript signature (ECDSA P-384), the PCA binding through the SPDM request nonce, the pinned measurement
# blocks, and (optionally) the signed Reference Integrity Manifests, firmware policy and CRL / OCSP revocation. Fails closed
# with the reference's reason strings.
require_relative 'intel'
require_relative 'ocsp'
require_relative 'xml'

module AtlasPca
  module Attest
    module Nvidia
      SUITE = 'nvidia-gpu-spdm-ecdsa-p384-sha384'
      REQ_LEN = 37
      NONCE_LEN = 32
      SIG_LEN = 96
      MAX_CHAIN = 5
      OPAQUE_DRIVER_VERSION = 3
      OPAQUE_VBIOS_VERSION = 6
      OPAQUE_CHIP_INFO = 35
      NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#'
      ALG_C14N11 = 'http://www.w3.org/2006/12/xml-c14n11'
      ALG_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
      ALG_ECDSA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384'
      ALG_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384'
      NVDEC0_DISABLED = 0x55
      NVDEC_BLOCK_INDEX = 35

      module_function

      def b_at(b, o) = o >= 0 && o < b.bytesize ? b.getbyte(o) : 0
      def u16_at(b, o) = b_at(b, o) | (b_at(b, o + 1) << 8)
      def u24_at(b, o) = b_at(b, o) | (b_at(b, o + 1) << 8) | (b_at(b, o + 2) << 16)

      # nil when the request version is >= 0x11 and the response echoes it, else the refusal reason.
      def spdm_version_reason(report)
        rq = report['request']['version']
        rs = report['response_version']
        return nil if rq >= 0x11 && rs == rq

        "SPDM version 0x#{rq.to_s(16)}/0x#{rs.to_s(16)} is not an accepted GET_MEASUREMENTS version"
      end

      # Parse an SPDM request || response GPU attestation transcript. Total: raises ArgumentError on any structural problem.
      def parse_nvidia_spdm_evidence(b)
        b = b.b
        raise ArgumentError, "parseNvidiaSpdmEvidence: transcript too short (#{b.bytesize})" if b.bytesize < REQ_LEN + 8 + NONCE_LEN + 2 + SIG_LEN

        code = b_at(b, 1)
        raise ArgumentError, "parseNvidiaSpdmEvidence: request code 0x#{code.to_s(16)} is not GET_MEASUREMENTS" if code != 0xE0

        request = { 'version' => b_at(b, 0), 'nonce' => b.byteslice(4, NONCE_LEN) }
        r = b.byteslice(REQ_LEN..)
        raise ArgumentError, 'parseNvidiaSpdmEvidence: response code is not MEASUREMENTS' if b_at(r, 1) != 0x60

        num_blocks = b_at(r, 4)
        rec_len = u24_at(r, 5)
        o = 8
        if o + rec_len + NONCE_LEN + 2 + SIG_LEN > r.bytesize
          raise ArgumentError, 'parseNvidiaSpdmEvidence: measurement record length overruns transcript'
        end

        measurements = []
        rec_end = o + rec_len
        while o < rec_end
          raise ArgumentError, 'parseNvidiaSpdmEvidence: truncated measurement block header' if o + 4 > rec_end

          index = b_at(r, o)
          size = u16_at(r, o + 2)
          body_start = o + 4
          raise ArgumentError, 'parseNvidiaSpdmEvidence: measurement block overruns record' if body_start + size > rec_end || size < 3

          value_type = b_at(r, body_start)
          vsize = u16_at(r, body_start + 1)
          raise ArgumentError, 'parseNvidiaSpdmEvidence: DMTF value overruns measurement block' if 3 + vsize > size

          measurements << { 'index' => index, 'valueType' => value_type, 'digest' => r.byteslice(body_start + 3, vsize) }
          o = body_start + size
        end
        raise ArgumentError, "parseNvidiaSpdmEvidence: header says #{num_blocks} blocks, parsed #{measurements.length}" if measurements.length != num_blocks

        o += NONCE_LEN
        opaque_len = u16_at(r, o)
        o += 2
        if o + opaque_len + SIG_LEN != r.bytesize
          raise ArgumentError, 'parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript'
        end

        opaque = {}
        opaque_end = o + opaque_len
        while o < opaque_end
          raise ArgumentError, 'parseNvidiaSpdmEvidence: truncated opaque TLV header' if o + 4 > opaque_end

          t = u16_at(r, o)
          ln = u16_at(r, o + 2)
          o += 4
          raise ArgumentError, 'parseNvidiaSpdmEvidence: opaque TLV overruns opaque data' if o + ln > opaque_end

          opaque[t] = r.byteslice(o, ln)
          o += ln
        end
        { 'request' => request, 'response_version' => b_at(r, 0), 'measurements' => measurements, 'opaque' => opaque, 'signature' => r.byteslice(r.bytesize - SIG_LEN, SIG_LEN),
          'signedBytes' => b.byteslice(0, b.bytesize - SIG_LEN) }
      end

      # NVIDIA's VBIOS version rendering: byte-reverse, then re-pair as dotted hex (e.g. `96.00.9f.00.04`).
      def format_vbios_version(raw)
        hx = raw.b.reverse.unpack1('H*')
        half = hx.length / 2
        temp = hx[half..] + hx[(half - 2)...half]
        temp.scan(/.{1,2}/).join('.')
      end

      # ---- device chain

      def parse_pem_chain(pem)
        blocks = Common.pem_blocks(pem)
        raise ArgumentError, 'parsePemChain: no certificates found' if blocks.empty?
        raise ArgumentError, "parsePemChain: chain longer than #{MAX_CHAIN}" if blocks.length > MAX_CHAIN

        blocks.map { |b| Cert.from_pem(b) }
      end

      # Every link signature-verified, every issuer a CA, every certificate valid at `now`, the root self-signed and PINNED.
      def verify_nvidia_device_chain(pem, root_spki_sha256, now_ms)
        begin
          chain = parse_pem_chain(pem)
        rescue StandardError => e
          return { 'ok' => false, 'reason' => "device chain unparseable: #{e.message}" }
        end
        chain.each_with_index do |c, i|
          return { 'ok' => false, 'reason' => "device chain cert ##{i} is outside its validity window" } unless Der.x509_valid_at?(c.raw, now_ms)

          pk = c.public_key
          if Common.key_type(pk) != 'ec' || Common.node_curve(pk) != 'secp384r1'
            return { 'ok' => false, 'reason' => "device chain cert ##{i} is not an ECDSA P-384 key" }
          end
        end
        (chain.length - 1).times do |i|
          issuer = chain[i + 1]
          return { 'ok' => false, 'reason' => "device chain cert ##{i + 1} issues a certificate but is not a CA" } unless issuer.ca
          unless chain[i].verify(issuer.public_key)
            return { 'ok' => false, 'reason' => "device chain link ##{i} signature does not verify under its issuer" }
          end
        end
        root = chain[-1]
        return { 'ok' => false, 'reason' => 'device chain root is not a self-signed CA' } if !root.ca || !root.verify_self

        pins = root_spki_sha256.map(&:downcase)
        return { 'ok' => false, 'reason' => 'chain root is not a pinned NVIDIA root' } unless pins.include?(root.spki_sha256)

        { 'ok' => true, 'leaf' => chain[0], 'chain' => chain }
      end

      # ---- RIM (SWID XML, XMLDSig)

      def pem_of_der_b64(b64)
        body = b64.gsub(/\s+/, '')
        lines = body.scan(/.{1,64}/)
        "-----BEGIN CERTIFICATE-----\n#{lines.join("\n")}\n-----END CERTIFICATE-----"
      end

      def int_value?(v) = v.is_a?(Float) ? (v.finite? && v == v.floor) : v.is_a?(Integer)

      # A RIM document (XML text): the strict XMLDSig profile, the digest, the ECDSA-P384 signature and the signer chain to the
      # pinned CoRIM signing root; golden measurements are read ONLY from the verified tree.
      def verify_nvidia_rim(xml, rim_root_spki_sha256, now_ms)
        fail_with = ->(reason) { { 'ok' => false, 'reason' => reason } }
        return fail_with.call('RIM: empty or oversized document') if !xml.is_a?(String) || xml.empty? || xml.length > 4_000_000
        return fail_with.call('RIM: no pinned RIM root configured') if !rim_root_spki_sha256.is_a?(Array) || rim_root_spki_sha256.empty?

        doc = Xml.parse_xml(xml)
        return fail_with.call("RIM: #{doc.violations[0]}") unless doc.violations.empty?

        root = doc.root
        return fail_with.call('RIM: root element is not SoftwareIdentity') if root.local != 'SoftwareIdentity'
        return fail_with.call('RIM: expected exactly one Signature element') if root.descendants(NS_DSIG, 'Signature').length != 1

        sigs = root.element_children(NS_DSIG, 'Signature')
        return fail_with.call('RIM: the Signature must be a direct child of the root') if sigs.length != 1

        sig = sigs[0]
        signed_info = sig.element_children(NS_DSIG, 'SignedInfo')
        return fail_with.call('RIM: expected exactly one SignedInfo') if signed_info.length != 1

        si = signed_info[0]
        alg_of = ->(els) { els.empty? ? nil : els[0].get_attribute('Algorithm') }
        return fail_with.call('RIM: CanonicalizationMethod must be C14N 1.1') if alg_of.call(si.element_children(NS_DSIG, 'CanonicalizationMethod')) != ALG_C14N11
        return fail_with.call('RIM: SignatureMethod must be ECDSA-SHA384') if alg_of.call(si.element_children(NS_DSIG, 'SignatureMethod')) != ALG_ECDSA384

        refs = si.element_children(NS_DSIG, 'Reference')
        return fail_with.call('RIM: expected exactly one Reference') if refs.length != 1

        ref = refs[0]
        return fail_with.call('RIM: Reference URI must be "" (the whole document)') if ref.get_attribute('URI') != ''

        tr = ref.element_children(NS_DSIG, 'Transforms')
        transforms = (tr.empty? ? ref : tr[0]).element_children(NS_DSIG, 'Transform').map { |t| t.get_attribute('Algorithm') }
        if transforms.length != 2 || transforms[0] != ALG_ENVELOPED || transforms[1] != ALG_C14N11
          return fail_with.call('RIM: transforms must be exactly [enveloped-signature, C14N 1.1]')
        end
        return fail_with.call('RIM: DigestMethod must be SHA-384') if alg_of.call(ref.element_children(NS_DSIG, 'DigestMethod')) != ALG_SHA384

        dv = ref.element_children(NS_DSIG, 'DigestValue')
        sv = sig.element_children(NS_DSIG, 'SignatureValue')
        digest_value = dv.empty? ? nil : dv[0].text_content.gsub(/\s+/, '')
        sig_value_b64 = sv.empty? ? nil : sv[0].text_content.gsub(/\s+/, '')
        return fail_with.call('RIM: missing DigestValue / SignatureValue') if digest_value.nil? || digest_value.empty? || sig_value_b64.nil? || sig_value_b64.empty?

        key_info = sig.element_children(NS_DSIG, 'KeyInfo')
        x509_data = key_info.empty? ? [] : key_info[0].element_children(NS_DSIG, 'X509Data')
        cert_b64 = x509_data.empty? ? [] : x509_data[0].element_children(NS_DSIG, 'X509Certificate').map(&:text_content)
        return fail_with.call('RIM: no signer certificates in KeyInfo') if cert_b64.empty?

        chain = verify_nvidia_device_chain(cert_b64.map { |c| pem_of_der_b64(c) }.join("\n"), rim_root_spki_sha256, now_ms)
        return fail_with.call("RIM signer chain: #{chain['reason']}") unless chain['ok']

        si_canon = Xml.canonicalize(si)
        sig_raw = Common.node_b64decode(sig_value_b64)
        return fail_with.call('RIM: SignatureValue is not a 96-byte P-384 signature') if sig_raw.bytesize != 96
        unless Common.ecdsa_verify_raw(chain['leaf'].public_key, sig_raw, si_canon.b, 'sha384')
          return fail_with.call('RIM: SignedInfo signature does not verify under the signer certificate')
        end

        canon = Xml.canonicalize(root, sig)
        if Base64.strict_encode64(Digest::SHA384.digest(canon.b)) != digest_value
          return fail_with.call('RIM: document digest does not match the signed DigestValue')
        end

        meta = root.element_children.find { |c| c.local == 'Meta' }
        payload = root.element_children.find { |c| c.local == 'Payload' }
        return fail_with.call('RIM: missing Meta / Payload') if meta.nil? || payload.nil?

        golden = {}
        payload.element_children.each do |r|
          next if r.local != 'Resource' || r.get_attribute('type') != 'Measurement'

          index = Common.js_number(r.get_attribute('index'))
          alternatives = Common.js_number(r.get_attribute('alternatives'))
          size = Common.js_number(r.get_attribute('size'))
          hash_attrs = r.attrs.select { |a| a.local.match?(/\AHash[0-9]+\z/) }.sort_by { |a| a.local[4..].to_i }
          hashes = hash_attrs.map { |a| a.value.downcase }
          if !int_value?(index) || index.negative? || !int_value?(alternatives) || alternatives < 1 || !int_value?(size) || size < 1
            return fail_with.call('RIM: malformed Measurement resource')
          end

          index = index.to_i
          alternatives = alternatives.to_i
          size = size.to_i
          if hashes.length != alternatives || hashes.any? { |h| !h.match?(/\A[0-9a-f]+\z/) || h.length != size * 2 }
            return fail_with.call("RIM: Measurement #{index} hash list is inconsistent with alternatives/size")
          end
          return fail_with.call("RIM: duplicate Measurement index #{index}") if golden.key?(index)

          golden[index] = { 'index' => index, 'active' => r.get_attribute('active').downcase == 'true', 'alternatives' => alternatives,
                            'size' => size, 'hashes' => hashes }
        end
        return fail_with.call('RIM: no measurements') if golden.empty?

        { 'ok' => true,
          'rim' => { 'tagId' => root.get_attribute('tagId'), 'product' => meta.get_attribute('product'),
                     'version' => meta.get_attribute('colloquialVersion'), 'golden' => golden } }
      rescue XmlError, StandardError => e
        { 'ok' => false, 'reason' => "RIM: verification error (fail closed): #{e.message}" }
      end

      # ---- RIM ids, comparison, revocation

      def ascii(b)
        s = (b || ''.b).dup.force_encoding('ISO-8859-1').encode('UTF-8')
        Common.js_trim(s.sub(/\0+\z/, ''))
      end

      # The RIM ids this report requires (read from the GPU's own signed opaque data); nil when they cannot be named.
      def nvidia_rim_ids_for_report(report)
        o = report['opaque']
        driver_version = ascii(o[OPAQUE_DRIVER_VERSION])
        vb = o[OPAQUE_VBIOS_VERSION]
        project = ascii(o[17]).upcase
        project_sku = ascii(o[18]).upcase
        chip_sku = ascii(o[15]).upcase
        return nil if driver_version.empty? || vb.nil? || project.empty? || project_sku.empty? || chip_sku.empty?

        chip = 'GH100'
        chip_raw = o[OPAQUE_CHIP_INFO]
        unless chip_raw.nil?
          chip = ascii(chip_raw)
          return nil unless chip.match?(/\A[A-Z][A-Z0-9]{2,11}\z/)
        end
        vbios_version = format_vbios_version(vb)
        { 'chip' => chip,
          'driver' => chip == 'GH100' ? "NV_GPU_DRIVER_GH100_#{driver_version}" : "NV_GPU_CC_DRIVER_#{chip}_#{driver_version}",
          'vbios' => "NV_GPU_VBIOS_#{project}_#{project_sku}_#{chip_sku}_#{vbios_version.delete('.').upcase}",
          'driverVersion' => driver_version, 'vbiosVersion' => vbios_version }
      end

      # NVIDIA's merge / alternatives / NVDEC0 rules.
      def compare_report_to_rims(report, driver, vbios)
        merged = {}
        driver['golden'].each_value { |g| merged[g['index']] = g if g['active'] }
        vbios['golden'].each_value do |g|
          next unless g['active']
          if merged.key?(g['index'])
            return { 'ok' => false, 'reason' => "driver and VBIOS RIMs both have an active measurement at index #{g['index']}" }
          end

          merged[g['index']] = g
        end
        return { 'ok' => false, 'reason' => 'RIMs carry no active golden measurements' } if merged.empty?

        runtime = report['measurements'].to_h { |m| [m['index'] - 1, m['digest']] }
        return { 'ok' => false, 'reason' => 'RIMs list more active measurements than the report carries' } if merged.length > runtime.length

        nvdec = report['opaque'][11]
        nvdec_disabled = !nvdec.nil? && !nvdec.empty? && nvdec.getbyte(0) == NVDEC0_DISABLED
        mismatches = 0
        merged.keys.sort.each do |index|
          g = merged[index]
          next if index + 1 == NVDEC_BLOCK_INDEX && nvdec_disabled

          digest = runtime[index]
          hx = digest.nil? ? '' : Common.to_hex(digest)
          mismatches += 1 if digest.nil? || digest.bytesize != g['size'] || !g['hashes'].include?(hx)
        end
        return { 'ok' => false, 'reason' => "runtime measurements differ from the golden RIM values at #{mismatches} index(es)" } if mismatches.positive?

        { 'ok' => true }
      end

      # The device chain against CRLs: every supplied CRL verifies under one chain certificate and is fresh, no chain certificate
      # (other than the root) is listed by its issuer, and `require_issuers` each have a verified CRL.
      def check_nvidia_chain_revocation(chain, crls, now_ms, require_issuers = nil)
        return { 'ok' => false, 'reason' => 'no CRLs supplied' } if crls.empty?

        covered = {}
        crls.each_with_index do |crl, ci|
          issuer_idx = -1
          revoked = nil
          last_reason = 'no chain certificate verifies it'
          chain.each_with_index do |cert, i|
            r = Intel.verify_crl(crl, cert.public_key, now_ms)
            if r['ok']
              issuer_idx = i
              revoked = r['revoked']
              break
            end
            last_reason = r['reason'] if last_reason == 'no chain certificate verifies it' || last_reason.include?('signature does not verify')
          end
          return { 'ok' => false, 'reason' => "CRL ##{ci} rejected: #{last_reason}" } if issuer_idx.negative? || revoked.nil?

          covered[issuer_idx] = true
          (chain.length - 1).times do |i|
            if i + 1 == issuer_idx && Intel.serial_is_revoked?(revoked, chain[i].serial_hex)
              return { 'ok' => false, 'reason' => "chain certificate '#{chain[i].subject.gsub("\n", ', ')}' is revoked" }
            end
          end
        end
        (require_issuers || []).each do |need|
          unless covered.keys.any? { |i| chain[i].subject.include?(need) }
            return { 'ok' => false, 'reason' => "no verified CRL issued by a certificate matching '#{need}'" }
          end
        end
        { 'ok' => true, 'verifiedCrls' => crls.length }
      end

      # ---- firmware policy

      def parse_version(v, radix)
        pat = radix == 10 ? /\A[0-9]+(\.[0-9]+)*\z/ : /\A[0-9a-fA-F]{1,4}(\.[0-9a-fA-F]{1,4})*\z/
        return nil if !v.is_a?(String) || !v.match?(pat)

        v.split('.').map { |x| x.to_i(radix) }
      end

      def cmp_version(a, b)
        [a.length, b.length].max.times do |i|
          d = (a[i] || 0) - (b[i] || 0)
          return d.negative? ? -1 : 1 unless d.zero?
        end
        0
      end

      def compile_firmware_policy(fw)
        return ->(_ids) {} if fw.nil? || fw == false || (fw.respond_to?(:empty?) && fw.empty?)

        need = lambda do |v, radix, what|
          p = parse_version(v, radix)
          raise AttestConstructError, "nvidiaCollateralHook: malformed #{what} '#{Common.js_str(v)}'" if p.nil?

          p
        end
        min_d = fw['minDriverVersion'] && fw['minDriverVersion'] != '' ? need.call(fw['minDriverVersion'], 10, 'minDriverVersion') : nil
        min_v = fw['minVbiosVersion'] && fw['minVbiosVersion'] != '' ? need.call(fw['minVbiosVersion'], 16, 'minVbiosVersion') : nil
        deny_d = (fw['denyDriverVersions'] || []).map { |v| need.call(v, 10, 'denyDriverVersions entry') }
        deny_v = (fw['denyVbiosVersions'] || []).map { |v| need.call(v, 16, 'denyVbiosVersions entry') }
        lambda do |ids|
          d = parse_version(ids['driverVersion'], 10)
          v = parse_version(ids['vbiosVersion'], 16)
          next "driver version '#{ids['driverVersion']}' in the GPU report is not parseable" if d.nil?
          next "VBIOS version '#{ids['vbiosVersion']}' in the GPU report is not parseable" if v.nil?
          next "driver #{ids['driverVersion']} is below the minimum #{fw['minDriverVersion']}" if !min_d.nil? && cmp_version(d, min_d).negative?
          next "VBIOS #{ids['vbiosVersion']} is below the minimum #{fw['minVbiosVersion']}" if !min_v.nil? && cmp_version(v, min_v).negative?
          next "driver #{ids['driverVersion']} is on the deny list" if deny_d.any? { |x| cmp_version(d, x).zero? }
          next "VBIOS #{ids['vbiosVersion']} is on the deny list" if deny_v.any? { |x| cmp_version(v, x).zero? }

          nil
        end
      end
    end

    # The post-verification hook: RIM signature + golden comparison + driver / VBIOS version binding + revocation.
    # `resolve.call(ids, evidence)` supplies the bundle {driverRimXml, vbiosRimXml, crls?, ocsp?} (or nil).
    class NvidiaCollateralHook
      def initialize(opts)
        pins = opts['rimRootSpkiSha256']
        raise AttestConstructError, 'nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root' if !pins.is_a?(Array) || pins.empty?

        @pins = pins
        @firmware = Nvidia.compile_firmware_policy(opts['firmware'])
        @resolve = opts['resolve']
        @revocation = opts['revocation']
        @require_crls = opts['requireCrls']
        @require_issuers = opts['requireCrlIssuers']
      end

      def call(ctx)
        ids = Nvidia.nvidia_rim_ids_for_report(ctx['report'])
        return 'GPU report does not carry the opaque fields needed to name its RIMs' if ids.nil?

        subject = ctx['leaf'].subject
        # the chip name comes from the (signed) report: escaped so no report byte can alter the pattern
        unless subject.match?(Regexp.new("(^|[^A-Za-z0-9])#{Regexp.escape(ids['chip'])}([^A-Za-z0-9]|$)"))
          return "device leaf subject '#{subject.gsub("\n", ', ')}' is not a #{ids['chip']} device certificate (chip family mismatch)"
        end

        fw_why = @firmware.call(ids)
        return "firmware policy: #{fw_why}" if fw_why && !fw_why.empty?

        bundle = @resolve.call(ids, ctx['evidence'])
        return 'no RIM collateral supplied for this report' if bundle.nil?

        d = Nvidia.verify_nvidia_rim(bundle['driverRimXml'], @pins, ctx['nowMs'])
        v = Nvidia.verify_nvidia_rim(bundle['vbiosRimXml'], @pins, ctx['nowMs'])
        return "driver RIM: #{d['reason']}" unless d['ok']
        return "VBIOS RIM: #{v['reason']}" unless v['ok']

        if d['rim']['product'] != ids['chip']
          return "driver RIM product '#{d['rim']['product']}' does not match the GPU chip '#{ids['chip']}' (wrong-family manifest)"
        end
        if v['rim']['product'] != ids['chip']
          return "VBIOS RIM product '#{v['rim']['product']}' does not match the GPU chip '#{ids['chip']}' (wrong-family manifest)"
        end
        if d['rim']['version'] != ids['driverVersion']
          return "driver RIM version '#{d['rim']['version']}' does not match the report's driver '#{ids['driverVersion']}'"
        end
        if v['rim']['version'].delete('.').upcase != ids['vbiosVersion'].delete('.').upcase
          return "VBIOS RIM version '#{v['rim']['version']}' does not match the report's VBIOS '#{ids['vbiosVersion']}'"
        end

        cmp = Nvidia.compare_report_to_rims(ctx['report'], d['rim'], v['rim'])
        return cmp['reason'] unless cmp['ok']

        mode = @revocation
        mode = (@require_crls == false ? nil : 'crl') if mode.nil?
        crls = bundle['crls'] || []
        if !crls.empty? || mode == 'crl' || mode == 'both'
          rev = Nvidia.check_nvidia_chain_revocation(ctx['chain'], crls, ctx['nowMs'], @require_issuers)
          return "revocation: #{rev['reason']}" unless rev['ok']
        end
        ocsp = bundle['ocsp'] || []
        if !ocsp.empty? || mode == 'ocsp' || mode == 'both'
          o = Ocsp.check_nvidia_chain_ocsp(ctx['chain'], ocsp, ctx['nowMs'])
          return "revocation (OCSP): #{o['reason']}" unless o['ok']
        end
        nil
      end
    end

    # `verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}.
    class NvidiaSpdmVerifier
      def initialize(opts)
        pins = opts['rootSpkiSha256']
        if !pins.is_a?(Array) || pins.empty?
          raise AttestConstructError, 'createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)'
        end

        pol = opts['policy'].is_a?(Hash) ? opts['policy'] : {}
        meas = pol['measurements']
        pinned = meas.is_a?(Hash) ? meas.to_a : []
        @post_verify = opts['postVerify']
        if pinned.empty? && @post_verify.nil?
          raise AttestConstructError, 'createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)'
        end

        want = pinned.map { |i, d| [i.is_a?(String) ? Common.js_number(i) : i.to_f, Common.js_str(d).downcase] }
        want.each do |i, _d|
          raise AttestConstructError, 'createNvidiaSpdmVerifier: measurement index out of range' if !Nvidia.int_value?(i) || i.negative? || i > 255
        end
        @want = want.map { |i, d| [i.to_i, d] }
        @pins = pins
        @leaf_includes = pol['leafSubjectIncludes']
        @resolve = opts['resolve_evidence']
      end

      def verify(document, expected, now_ms)
        fail_with = ->(reason) { { 'ok' => false, 'reason' => reason } }
        return fail_with.call('no NVIDIA GPU evidence resolver configured (fail closed)') if @resolve.nil?

        ev = @resolve.call(document)
        if !ev.is_a?(Hash) || !ev['evidence'].is_a?(String) || !ev['certChainPem'].is_a?(String)
          return fail_with.call('no NVIDIA GPU evidence for this action')
        end

        chain = Nvidia.verify_nvidia_device_chain(ev['certChainPem'], @pins, now_ms)
        return fail_with.call(chain['reason']) unless chain['ok']

        leaf = chain['leaf']
        inc = @leaf_includes
        return fail_with.call("device leaf subject does not contain '#{inc}'") if inc && !(inc.respond_to?(:empty?) && inc.empty?) && !leaf.subject.include?(inc)

        begin
          report = Nvidia.parse_nvidia_spdm_evidence(ev['evidence'])
        rescue ArgumentError => e
          return fail_with.call("GPU attestation report parse failed: #{e.message}")
        end
        # SPDM 1.1+ is the first version with the signed GET_MEASUREMENTS layout parsed here; request and response must agree
        reason = Nvidia.spdm_version_reason(report)
        return fail_with.call(reason) if reason
        unless Common.ecdsa_verify_raw(leaf.public_key, report['signature'], report['signedBytes'], 'sha384')
          return fail_with.call('GPU attestation report signature does not verify under the device identity key')
        end
        return fail_with.call('no expected attestation binding supplied') if expected.nil?

        begin
          challenge = Common.attestation_challenge_sha256(expected)
        rescue JsTypeError => e
          return fail_with.call("binding not constructible: #{e.message}")
        end
        if report['request']['nonce'] != challenge
          return fail_with.call('SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)')
        end

        by_index = report['measurements'].to_h { |m| [m['index'], m] }
        @want.each do |idx, digest_hex|
          m = by_index[idx]
          return fail_with.call("measurement block #{idx} missing from report") if m.nil?
          return fail_with.call("measurement block #{idx} does not match the pinned digest") if Common.to_hex(m['digest']) != digest_hex
        end
        unless @post_verify.nil?
          why = @post_verify.call({ 'report' => report, 'chain' => chain['chain'], 'leaf' => leaf, 'nowMs' => now_ms, 'evidence' => ev })
          return fail_with.call(why) if why && !why.empty?
        end
        h = Digest::SHA384.new
        report['measurements'].sort_by { |m| m['index'] }.each { |m| h << m['digest'] }
        host = { 'attestation_type' => 'nvidia-gpu-cc', 'gpu_measurements_sha384' => h.hexdigest, 'leaf_subject' => leaf.subject.gsub("\n", ', ') }
        drv = report['opaque'][Nvidia::OPAQUE_DRIVER_VERSION]
        vbios = report['opaque'][Nvidia::OPAQUE_VBIOS_VERSION]
        host['driver_version'] = drv.dup.force_encoding('UTF-8').scrub("�").sub(/\0+\z/, '') unless drv.nil?
        host['vbios_version'] = Nvidia.format_vbios_version(vbios) unless vbios.nil?
        { 'ok' => true, 'bound' => true,
          'measured' => { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => '', 'operator' => '' },
          'hostAsserted' => host }
      rescue StandardError => e
        fail_with.call("nvidia-spdm verification error (fail closed): #{e.message}")
      end
    end
  end
end
