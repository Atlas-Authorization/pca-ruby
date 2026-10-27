# frozen_string_literal: true

# Intel TDX (DCAP v4, ECDSA-P256) attestation verifier and Intel PCS collateral evaluation.
#
# Native counterpart of `createIntelDcapVerifier`, `verifyGenuineTdxQuote` and `verifyIntelTdxCollateral`: the PCK chain to the
# pinned Intel SGX Root CA, the QE report under the PCK leaf, the attestation key endorsed by the QE, the TD quote signature,
# the PCA nonce binding, the MRTD / FMSPC / RTMR0 allowlists and (by default REQUIRED) the signed TCB info / QE identity / CRL
# collateral. Fails closed with the reference's reason strings.
require_relative 'amd'

module AtlasPca
  module Attest
    module Intel
      SUITE = 'intel-tdx-dcap-ecdsa-p256'
      SGX_ROOT_CA_SPKI_SHA256 = 'a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e'
      HEADER_LEN = 48
      TD_REPORT_LEN = 584
      QE_ATTRIBUTES_OFF = 48
      QE_REPORT_DATA_OFF = 0x140
      SGX_REPORT_LEN = 384
      OID_SGX_FMSPC = [0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04].pack('C*').freeze
      OID_SGX_TCB = [0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x02].pack('C*').freeze
      STATUS_ORDER = %w[UpToDate SWHardeningNeeded ConfigurationNeeded ConfigurationAndSWHardeningNeeded OutOfDateConfigurationNeeded
                        OutOfDate Revoked].freeze
      DEFAULT_ACCEPTED_STATUSES = %w[UpToDate SWHardeningNeeded].freeze
      JS_SPACE = '\s   -     　﻿'

      module_function

      def u16(b, o) = b.byteslice(o, 2).unpack1('v')
      def u32(b, o) = b.byteslice(o, 4).unpack1('V')
      def zero?(s) = s.bytes.all?(&:zero?)

      # ---- quote parsing

      # Parse a DCAP v4 / ECDSA-P256 / TDX quote. Raises ArgumentError (the reference's messages) on any structural violation.
      def parse_dcap_quote(quote)
        quote = quote.b
        raise ArgumentError, 'parseDcapQuote: too short for header + TD report + sig length' if quote.bytesize < HEADER_LEN + TD_REPORT_LEN + 4

        version = u16(quote, 0)
        att_key_type = u16(quote, 2)
        tee_type = u32(quote, 4)
        raise ArgumentError, "parseDcapQuote: unsupported quote version #{version} (expected 4)" if version != 4
        raise ArgumentError, "parseDcapQuote: unsupported attestation key type #{att_key_type} (expected ECDSA-P256 = 2)" if att_key_type != 2
        raise ArgumentError, "parseDcapQuote: unexpected TEE type 0x#{tee_type.to_s(16)} (expected TDX = 0x81)" if tee_type != 0x81

        header = quote.byteslice(0, HEADER_LEN)
        td_body = quote.byteslice(HEADER_LEN, TD_REPORT_LEN)
        o = HEADER_LEN + TD_REPORT_LEN
        sig_len = u32(quote, o)
        o += 4
        sig_end = o + sig_len
        raise ArgumentError, "parseDcapQuote: signature data (#{sig_len}) overruns the quote" if sig_end > quote.bytesize

        need = lambda do |n, what|
          raise ArgumentError, "parseDcapQuote: truncated reading #{what}" if o + n > sig_end
        end
        need.call(64, 'quote signature')
        quote_signature = quote.byteslice(o, 64)
        o += 64
        need.call(64, 'attestation public key')
        ak_pub_raw = quote.byteslice(o, 64)
        o += 64
        need.call(6, 'outer cert-data header')
        outer_type = u16(quote, o)
        outer_size = u32(quote, o + 2)
        o += 6
        raise ArgumentError, "parseDcapQuote: outer cert-data type #{outer_type} (expected QE-report-cert-data = 6)" if outer_type != 6

        outer_end = o + outer_size
        raise ArgumentError, 'parseDcapQuote: outer cert-data overruns signature data' if outer_end > sig_end

        need.call(SGX_REPORT_LEN, 'QE report')
        qe_report = quote.byteslice(o, SGX_REPORT_LEN)
        o += SGX_REPORT_LEN
        need.call(64, 'QE report signature')
        qe_sig = quote.byteslice(o, 64)
        o += 64
        need.call(2, 'QE auth-data size')
        auth_size = u16(quote, o)
        o += 2
        need.call(auth_size, 'QE auth-data')
        qe_auth = quote.byteslice(o, auth_size)
        o += auth_size
        need.call(6, 'inner cert-data header')
        inner_type = u16(quote, o)
        inner_size = u32(quote, o + 2)
        o += 6
        raise ArgumentError, "parseDcapQuote: inner cert-data type #{inner_type} (expected PCK-cert-chain = 5)" if inner_type != 5
        raise ArgumentError, 'parseDcapQuote: inner cert-data overruns outer cert-data' if o + inner_size > outer_end

        pck_chain_pem = quote.byteslice(o, inner_size).dup.force_encoding('ISO-8859-1').encode('UTF-8')
        # Azure pads the quote with zero bytes after the declared signature data; anything else is unverified data riding along
        raise ArgumentError, 'parseDcapQuote: non-zero bytes after the signature data' unless zero?(quote.byteslice(sig_end..))

        { 'header' => header, 'tdReportBody' => td_body, 'quoteSignature' => quote_signature, 'akPubRaw' => ak_pub_raw,
          'qeReportBody' => qe_report, 'qeReportSignature' => qe_sig, 'qeAuthData' => qe_auth, 'pckChainPem' => pck_chain_pem }
      end

      def parse_dcap_td_report(body)
        raise ArgumentError, "parseDcapTdReport: body too short (#{body.bytesize} < #{TD_REPORT_LEN})" if body.bytesize < TD_REPORT_LEN

        { 'teeTcbSvn' => body.byteslice(0, 16), 'mrSeam' => body.byteslice(16, 48), 'mrSignerSeam' => body.byteslice(64, 48),
          'tdAttributes' => body.byteslice(120, 8), 'mrTd' => body.byteslice(136, 48), 'rtmr0' => body.byteslice(328, 48),
          'reportData' => body.byteslice(520, 64) }
      end

      # ---- PCK certificate

      # A lenient DER TLV at `off`; nil on any malformed or overrunning length.
      def read_der_tlv(buf, off)
        return nil if off + 2 > buf.bytesize

        tag = buf.getbyte(off)
        ln = buf.getbyte(off + 1)
        p = off + 2
        if ln.anybits?(0x80)
          n = ln & 0x7F
          return nil if n.zero? || n > 4 || p + n > buf.bytesize

          ln = 0
          n.times do
            ln = (ln * 256) + buf.getbyte(p)
            p += 1
          end
        end
        end_ = p + ln
        return nil if end_ > buf.bytesize

        { 'tag' => tag, 'start' => p, 'end' => end_ }
      end

      # FMSPC + the PCK leaf's issued TCB, read from the Intel SGX extension (1.2.840.113741.1.13.1). Raises on anything off.
      def extract_pck_fmspc_and_tcb(leaf_der)
        leaf_der = leaf_der.b
        fi = leaf_der.index(OID_SGX_FMSPC)
        raise ArgumentError, 'extractPckFmspcAndTcb: FMSPC OID not found in certificate' if fi.nil?

        fv = read_der_tlv(leaf_der, fi + OID_SGX_FMSPC.bytesize)
        raise ArgumentError, 'extractPckFmspcAndTcb: malformed FMSPC OCTET STRING' if fv.nil? || fv['tag'] != 0x04 || fv['end'] - fv['start'] != 6

        fmspc = leaf_der.byteslice(fv['start'], fv['end'] - fv['start'])
        ti = leaf_der.index(OID_SGX_TCB)
        raise ArgumentError, 'extractPckFmspcAndTcb: TCB OID not found in certificate' if ti.nil?

        seq = read_der_tlv(leaf_der, ti + OID_SGX_TCB.bytesize)
        raise ArgumentError, 'extractPckFmspcAndTcb: malformed TCB SEQUENCE' if seq.nil? || seq['tag'] != 0x30

        sgx = Array.new(16, 0)
        pcesvn = -1
        p = seq['start']
        idx = 0
        while p < seq['end']
          pair = read_der_tlv(leaf_der, p)
          raise ArgumentError, 'extractPckFmspcAndTcb: malformed TCB component' if pair.nil? || pair['tag'] != 0x30

          oid = read_der_tlv(leaf_der, pair['start'])
          raise ArgumentError, 'extractPckFmspcAndTcb: TCB component missing OID' if oid.nil? || oid['tag'] != 0x06

          val = read_der_tlv(leaf_der, oid['end'])
          raise ArgumentError, 'extractPckFmspcAndTcb: TCB component missing value' if val.nil?

          last = leaf_der.getbyte(oid['end'] - 1)
          if val['tag'] == 0x02
            n = 0
            (val['start']...val['end']).each { |b| n = (n << 8) | leaf_der.getbyte(b) }
            if last >= 1 && last <= 16
              sgx[last - 1] = n & 0xFF
            elsif last == 17
              pcesvn = n & 0xFFFF
            end
          end
          p = pair['end']
          idx += 1
          break if idx > 64
        end
        raise ArgumentError, 'extractPckFmspcAndTcb: PCESVN not found in TCB extension' if pcesvn.negative?

        { 'fmspc' => fmspc, 'sgxTcbComponents' => sgx.pack('C*'), 'pcesvn' => pcesvn }
      end

      # The embedded PCK chain to the PINNED Intel SGX Root CA: every certificate valid at `now`, every link signed, CA roles.
      def verify_intel_pck_chain(pck_chain_pem, trust_anchor = nil, now_ms = nil)
        blocks = pck_chain_pem.is_a?(String) ? Common.pem_blocks(pck_chain_pem) : nil
        return { 'ok' => false, 'reason' => 'no PEM certificates in the PCK chain' } if blocks.nil? || blocks.empty?

        certs = blocks.map { |b| Cert.from_pem(b) }
        issuers = certs.map(&:issuer).uniq
        by_subject = {}
        certs.each { |c| by_subject[c.subject] = c }
        leaf = certs.find { |c| !issuers.include?(c.subject) } || certs[0]
        ordered = []
        seen = {}
        cur = leaf
        while !cur.nil? && !seen.key?(cur.subject)
          ordered << cur
          seen[cur.subject] = true
          break if cur.subject == cur.issuer

          cur = by_subject[cur.issuer]
        end
        root = ordered[-1]
        return { 'ok' => false, 'reason' => 'PCK chain does not terminate in a self-signed root' } if root.subject != root.issuer
        if ordered.length != certs.length
          return { 'ok' => false, 'reason' => 'PCK chain is not a single connected path (orphan/duplicate certificates)' }
        end

        now = now_ms.nil? ? (Time.now.to_f * 1000) : now_ms
        return { 'ok' => false, 'reason' => 'nowMs is not a finite number' } unless Common.num?(now)

        ordered.each do |c|
          unless Der.x509_valid_at?(c.raw, now)
            return { 'ok' => false, 'reason' => 'PCK chain certificate outside its validity period', 'failure' => 'validity' }
          end
        end
        (ordered.length - 1).times do |i|
          child = ordered[i]
          parent = ordered[i + 1]
          return { 'ok' => false, 'reason' => "certificate at depth #{i} issuer does not match its parent subject" } if child.issuer != parent.subject
          return { 'ok' => false, 'reason' => "certificate at depth #{i} is not signed by its issuer" } unless child.verify(parent.public_key)
        end
        return { 'ok' => false, 'reason' => 'root certificate is not self-signed' } unless root.verify(root.public_key)

        pin = (trust_anchor.nil? ? SGX_ROOT_CA_SPKI_SHA256 : trust_anchor).downcase
        return { 'ok' => false, 'reason' => 'Intel SGX Root CA does not match the pinned trust anchor' } if root.spki_sha('sha256') != pin

        role_fail = Der.check_chain_roles(ordered.map(&:raw))
        return { 'ok' => false, 'reason' => role_fail } if role_fail

        ordered.each_with_index do |c, i|
          crit = Der.unrecognised_critical_extension(c.raw) # raises on a malformed table: fail closed below
          if crit
            return { 'ok' => false, 'reason' => "PCK chain certificate at depth #{i} has an unrecognised critical extension #{crit}" }
          end
        end
        leaf_pk = leaf.public_key
        return { 'ok' => false, 'reason' => "PCK leaf key is not EC (got #{Common.key_type(leaf_pk)})" } if Common.key_type(leaf_pk) != 'ec'

        leaf_key = Common.ec_key_from_point('P-256', Common.ec_point(leaf_pk, 'P-256'))
        { 'ok' => true, 'leafKey' => leaf_key, 'leafDer' => leaf.raw, 'leafCert' => leaf, 'depth' => ordered.length }
      rescue StandardError => e
        { 'ok' => false, 'reason' => "PCK chain X.509 verification error (fail closed): #{e.message}" }
      end

      def verify_p256(msg, sig_compact, key)
        Common.ecdsa_verify_raw(key, sig_compact, msg, 'sha256')
      rescue StandardError
        false
      end

      # A genuine DCAP v4 TDX quote end to end, offline (no PCS collateral). Fails closed with a reason.
      def verify_genuine_tdx_quote(quote, trust_anchor = nil, expected = nil, policy = nil, now_ms = nil)
        begin
          q = parse_dcap_quote(quote)
        rescue ArgumentError => e
          return { 'ok' => false, 'reason' => "quote parse failed: #{e.message}" }
        end
        begin
          report = parse_dcap_td_report(q['tdReportBody'])
        rescue ArgumentError => e
          return { 'ok' => false, 'reason' => "TD report parse failed: #{e.message}" }
        end
        chain = verify_intel_pck_chain(q['pckChainPem'], trust_anchor, now_ms)
        if !chain['ok'] || !chain.key?('leafKey') || !chain.key?('leafDer')
          return { 'ok' => false, 'reason' => "PCK chain invalid: #{chain['reason'] || 'unknown'}" }
        end

        begin
          pck_tcb = extract_pck_fmspc_and_tcb(chain['leafDer'])
        rescue ArgumentError => e
          return { 'ok' => false, 'reason' => "PCK FMSPC/TCB extraction failed: #{e.message}" }
        end
        unless verify_p256(q['qeReportBody'], q['qeReportSignature'], chain['leafKey'])
          return { 'ok' => false, 'reason' => 'QE report signature does not verify under the PCK leaf' }
        end
        # a debug QE can forge endorsements (SGX REPORT.ATTRIBUTES.FLAGS bit 1)
        if q['qeReportBody'].getbyte(QE_ATTRIBUTES_OFF).anybits?(0x02)
          return { 'ok' => false, 'reason' => 'QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)' }
        end

        qe_data = q['qeReportBody'].byteslice(QE_REPORT_DATA_OFF, 64)
        ak_binding = Digest::SHA256.digest(q['akPubRaw'] + q['qeAuthData'])
        if qe_data.byteslice(0, 32) != ak_binding || !zero?(qe_data.byteslice(32, 32))
          return { 'ok' => false, 'reason' => 'QE report_data does not bind the attestation key (AK not endorsed by this QE)' }
        end

        begin
          ak_pub = Common.ec_key_from_point('P-256', "\x04".b + q['akPubRaw'])
        rescue StandardError
          return { 'ok' => false, 'reason' => 'attestation public key is not a valid P-256 point' }
        end
        unless verify_p256(q['header'] + q['tdReportBody'], q['quoteSignature'], ak_pub)
          return { 'ok' => false, 'reason' => 'TD quote signature does not verify under the attestation key' }
        end

        unless expected.nil?
          begin
            expected_data = Common.attestation_binding(expected)
          rescue JsTypeError => e
            return { 'ok' => false, 'reason' => "binding not constructible: #{e.message}" }
          end
          return { 'ok' => false, 'reason' => 'report_data does not bind holder/grant/epoch/nonce' } if expected_data != report['reportData']
        end
        pol = policy || {}
        if pol['allowDebug'] != true && report['tdAttributes'].getbyte(0).anybits?(1)
          return { 'ok' => false, 'reason' => 'TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)' }
        end

        fmspc_hex = Common.to_hex(pck_tcb['fmspc'])
        unless policy.nil?
          allowed = lambda do |key, value, need_nonempty|
            lst = policy[key]
            next true if !lst.is_a?(Array) || (need_nonempty && lst.empty?)

            lst.map(&:downcase).include?(Common.to_hex(value))
          end
          return { 'ok' => false, 'reason' => 'MRTD not in policy allowlist' } unless allowed.call('mrtds', report['mrTd'], true)
          return { 'ok' => false, 'reason' => 'FMSPC not in policy allowlist' } unless allowed.call('fmspcs', pck_tcb['fmspc'], true)
          return { 'ok' => false, 'reason' => 'MRSEAM not in policy allowlist' } unless allowed.call('mrSeams', report['mrSeam'], false)
          return { 'ok' => false, 'reason' => 'MRSIGNERSEAM not in policy allowlist' } unless allowed.call('mrSignerSeams', report['mrSignerSeam'], false)
          return { 'ok' => false, 'reason' => 'RTMR0 not in policy allowlist' } unless allowed.call('rtmrs', report['rtmr0'], true)
        end
        measured = { 'model_id' => '', 'weights_digest' => '', 'weights_measured' => false,
                     'runtime_measurement' => Common.to_hex(report['mrTd']), 'operator' => '' }
        { 'ok' => true, 'report' => report, 'fmspc' => fmspc_hex, 'pckTcb' => pck_tcb, 'chainDepth' => chain['depth'], 'measured' => measured }
      rescue StandardError => e
        { 'ok' => false, 'reason' => "genuine TDX verification error (fail closed): #{e.message}" }
      end

      # ---- collateral: CRL

      TlvC = Struct.new(:tag, :start, :end_) do
        def next_ = end_
      end

      def tlv(b, off, limit = nil)
        limit ||= b.bytesize
        raise ArgumentError, 'DER truncated' if off + 2 > limit

        tag = b.getbyte(off)
        ln = b.getbyte(off + 1)
        p = off + 2
        if ln.anybits?(0x80)
          n = ln & 0x7F
          raise ArgumentError, 'DER bad length' if n.zero? || n > 4 || p + n > limit

          ln = 0
          n.times { |i| ln = (ln * 256) + b.getbyte(p + i) }
          p += n
        end
        raise ArgumentError, 'DER overrun' if p + ln > limit

        TlvC.new(tag, p, p + ln)
      end

      # Date.UTC: months and days roll over, years 0..99 mean 1900..1999.
      def date_utc(y, mon0, d, h, mi, s)
        y += 1900 if y >= 0 && y <= 99
        y += mon0.div(12)
        mon0 %= 12
        days = Der.days_from_civil(y, mon0 + 1, 1) + (d - 1)
        ((((((days * 24) + h) * 60) + mi) * 60) + s) * 1000
      end

      def der_time(b, t)
        s = b.byteslice(t.start, t.end_ - t.start).dup.force_encoding('ISO-8859-1').encode('UTF-8')
        if t.tag == 0x17
          m = s.match(/\A([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\z/)
          raise ArgumentError, 'bad UTCTime' if m.nil?

          yy = m[1].to_i
          return date_utc(yy >= 50 ? 1900 + yy : 2000 + yy, m[2].to_i - 1, m[3].to_i, m[4].to_i, m[5].to_i, m[6].to_i)
        end
        if t.tag == 0x18
          m = s.match(/\A([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\z/)
          raise ArgumentError, 'bad GeneralizedTime' if m.nil?

          return date_utc(m[1].to_i, m[2].to_i - 1, m[3].to_i, m[4].to_i, m[5].to_i, m[6].to_i)
        end
        raise ArgumentError, 'not a DER time'
      end

      def norm_serial(hex_str) = hex_str.downcase.sub(/\A0+/, '')

      def parse_crl(der)
        outer = tlv(der, 0)
        raise ArgumentError, 'CRL: bad outer SEQUENCE' if outer.tag != 0x30 || outer.next_ != der.bytesize

        tbs_t = tlv(der, outer.start, outer.end_)
        raise ArgumentError, 'CRL: bad TBSCertList' if tbs_t.tag != 0x30

        tbs = der.byteslice(outer.start, tbs_t.next_ - outer.start)
        alg_t = tlv(der, tbs_t.next_, outer.end_)
        sig_t = tlv(der, alg_t.next_, outer.end_)
        raise ArgumentError, 'CRL: bad signature' if sig_t.tag != 0x03 || sig_t.next_ != outer.end_

        sig_der = der.byteslice(sig_t.start + 1, sig_t.end_ - sig_t.start - 1)
        p = tbs_t.start
        t = tlv(der, p, tbs_t.end_)
        if t.tag == 0x02
          p = t.next_
          t = tlv(der, p, tbs_t.end_)
        end
        p = t.next_
        iss = tlv(der, p, tbs_t.end_)
        raise ArgumentError, 'CRL: bad issuer' if iss.tag != 0x30

        tu = tlv(der, iss.next_, tbs_t.end_)
        this_update = der_time(der, tu)
        q = tu.next_
        next_update = nil
        revoked = {}
        if q < tbs_t.end_
          n = tlv(der, q, tbs_t.end_)
          if [0x17, 0x18].include?(n.tag)
            next_update = der_time(der, n)
            q = n.next_
          end
          if q < tbs_t.end_
            n = tlv(der, q, tbs_t.end_)
            if n.tag == 0x30
              e = n.start
              while e < n.end_
                ent = tlv(der, e, n.end_)
                ser = tlv(der, ent.start, ent.end_)
                raise ArgumentError, 'CRL: bad revoked entry' if ser.tag != 0x02

                revoked[norm_serial(der.byteslice(ser.start, ser.end_ - ser.start).unpack1('H*'))] = true
                e = ent.next_
              end
            end
          end
        end
        raise ArgumentError, 'CRL: missing nextUpdate' if next_update.nil?

        { 'tbs' => tbs, 'thisUpdate' => this_update, 'nextUpdate' => next_update, 'revoked' => revoked, 'sigDer' => sig_der }
      end

      # A CRL (DER) under `issuer_key` at `now`: {ok, revoked} (lowercase hex serials, no leading zeros) or {ok: false, reason}.
      def verify_crl(crl_der, issuer_key, now_ms)
        begin
          crl = parse_crl(crl_der.b)
        rescue ArgumentError => e
          return { 'ok' => false, 'reason' => "CRL parse failed: #{e.message}" }
        end
        kt = Common.key_type(issuer_key)
        good = if kt == 'ec' then Common.ecdsa_verify_der(issuer_key, crl['sigDer'], crl['tbs'], 'sha256')
               elsif kt == 'rsa' then Common.rsa_pkcs1_verify(issuer_key, crl['sigDer'], crl['tbs'], 'sha256')
               else false
               end
        return { 'ok' => false, 'reason' => 'CRL signature does not verify under the issuer' } unless good
        return { 'ok' => false, 'reason' => 'CRL thisUpdate is in the future' } if now_ms < crl['thisUpdate']
        return { 'ok' => false, 'reason' => 'CRL is stale (nextUpdate passed)' } if now_ms > crl['nextUpdate']

        { 'ok' => true, 'revoked' => crl['revoked'] }
      end

      def serial_is_revoked?(revoked, serial_hex) = revoked.key?(norm_serial(serial_hex))

      # ---- collateral: signed JSON

      def signer_key_from_chain(chain_pem, pin, now_ms, root_revoked)
        chain = verify_intel_pck_chain(chain_pem, pin, now_ms)
        return { 'error' => 'issuer chain certificate outside its validity period' } if chain['failure'] == 'validity'
        return { 'error' => "issuer chain invalid: #{chain['reason'] || 'unknown'}" } if !chain['ok'] || !chain.key?('leafDer')

        Common.pem_blocks(chain_pem).each do |b|
          c = Cert.from_pem(b)
          return { 'error' => 'issuer chain certificate outside its validity period' } unless Der.x509_valid_at?(c.raw, now_ms)
          return { 'error' => 'issuer chain certificate is revoked by the Intel Root CA CRL' } if serial_is_revoked?(root_revoked, c.serial_hex)
        end
        { 'key' => chain['leafCert'].public_key }
      end

      def raw_json_object(text, name)
        m = text.match(/\A[#{JS_SPACE}]*\{[#{JS_SPACE}]*"#{Regexp.escape(name)}"[#{JS_SPACE}]*:[#{JS_SPACE}]*/)
        return nil if m.nil?

        s = m.end(0)
        return nil if s >= text.length || text[s] != '{'

        depth = 0
        in_str = false
        i = s
        while i < text.length
          ch = text[i]
          if in_str
            if ch == '\\'
              i += 1
            elsif ch == '"'
              in_str = false
            end
          elsif ch == '"'
            in_str = true
          elsif ch == '{'
            depth += 1
          elsif ch == '}'
            depth -= 1
            return text[s..i] if depth.zero?
          end
          i += 1
        end
        nil
      end

      def verify_signed_json(text, name, key)
        raw = raw_json_object(text, name)
        return { 'error' => "#{name} not found / malformed" } if raw.nil?

        begin
          doc = Common.js_json_loads(text)
        rescue JsError
          return { 'error' => "#{name} document is not valid JSON" }
        end
        sig = doc.is_a?(Hash) ? doc['signature'] : nil
        return { 'error' => "#{name} signature missing or malformed" } if !sig.is_a?(String) || !sig.match?(/\A[0-9a-fA-F]{128}\z/)

        unless Common.ecdsa_verify_raw(key, [sig].pack('H*'), raw.dup.force_encoding('UTF-8').b, 'sha256')
          return { 'error' => "#{name} signature does not verify under the TCB Signing certificate" }
        end

        body = doc[name]
        return { 'error' => "#{name} is not an object" } unless body.is_a?(Hash)

        { 'body' => body }
      end

      ISO = /\A([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?(Z|[+-][0-9]{2}:[0-9]{2})?)?\z/

      # Date.parse for the ISO 8601 forms Intel PCS emits (a zone-less date-time is read as UTC); nil for anything else.
      def js_date_parse(s)
        m = s.match(ISO)
        return nil if m.nil?

        y = m[1].to_i
        mo = m[2].to_i
        d = m[3].to_i
        h = (m[4] || 0).to_i
        mi = (m[5] || 0).to_i
        sec = (m[6] || 0).to_i
        ms = (m[7] || '0')[0, 3].ljust(3, '0').to_i
        return nil if mo < 1 || mo > 12 || d < 1 || d > 31 || h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0 || ms != 0))
        return nil if d > Der.days_in_month(y, mo)

        t = (((((Der.days_from_civil(y, mo, d) * 24) + h) * 60) + mi) * 60 + sec) * 1000 + ms
        tz = m[8]
        if tz && tz != 'Z'
          off = ((tz[1, 2].to_i * 60) + tz[4, 2].to_i) * 60_000
          t -= tz[0] == '+' ? off : -off
        end
        t
      end

      def check_fresh(body, what, now_ms)
        issue = body['issueDate'].is_a?(String) ? js_date_parse(body['issueDate']) : nil
        nxt = body['nextUpdate'].is_a?(String) ? js_date_parse(body['nextUpdate']) : nil
        return "#{what}: issueDate/nextUpdate missing" if issue.nil? || nxt.nil?
        return "#{what}: issueDate is in the future" if now_ms < issue
        return "#{what}: stale (nextUpdate passed)" if now_ms > nxt

        nil
      end

      # ---- collateral: status evaluation

      def as_status(s) = s.is_a?(String) && STATUS_ORDER.include?(s) ? s : nil
      def worst(a, b) = STATUS_ORDER.index(a) >= STATUS_ORDER.index(b) ? a : b

      def svns(comps)
        return nil if !comps.is_a?(Array) || comps.length != 16

        out = []
        comps.each do |c|
          return nil if !c.is_a?(Hash) || !Common.num?(c['svn'])

          out << c['svn']
        end
        out
      end

      def hex_bytes(s, ln)
        return nil if !s.is_a?(String) || s.length != ln * 2 || !s.match?(/\A[0-9a-fA-F]+\z/)

        [s].pack('H*')
      end

      def advisories(level)
        a = level['advisoryIDs']
        a.is_a?(Array) ? a.grep(String) : []
      end

      def masked_eq?(value, mask, expected)
        value.bytesize.times do |i|
          return false if ((value.getbyte(i) & mask.getbyte(i)) ^ (expected.getbyte(i) & mask.getbyte(i))) != 0
        end
        true
      end

      def hit_level(levels, svn)
        levels.find { |l| l.is_a?(Hash) && l['tcb'].is_a?(Hash) && Common.num?(l['tcb']['isvsvn']) && l['tcb']['isvsvn'] <= svn }
      end

      def evaluate_tcb(info, pck, td)
        levels = info['tcbLevels']
        return { 'error' => 'TCB info has no tcbLevels' } if !levels.is_a?(Array) || levels.empty?

        minor = td['teeTcbSvn'].getbyte(1)
        module_status = 'UpToDate'
        adv = {}
        if minor.positive?
          ident_id = format('TDX_%02X', minor)
          ids = info['tdxModuleIdentities']
          ident = ids.is_a?(Array) ? ids.find { |x| x.is_a?(Hash) && x['id'] == ident_id } : nil
          return { 'error' => "TDX module identity #{ident_id} not present in TCB info" } if ident.nil?

          mod_mr_signer = ident['mrsigner']
          mod_attr = ident['attributes']
          mod_mask = ident['attributesMask']
          lv = ident['tcbLevels'].is_a?(Array) ? ident['tcbLevels'] : []
          hit = hit_level(lv, td['teeTcbSvn'].getbyte(0))
          return { 'error' => "TDX module #{ident_id} SVN #{td['teeTcbSvn'].getbyte(0)} is below every known level" } if hit.nil?

          st = as_status(hit['tcbStatus'])
          return { 'error' => 'TDX module level has an unknown tcbStatus' } if st.nil?

          module_status = st
          advisories(hit).each { |a| adv[a] = true }
        else
          m = info['tdxModule']
          return { 'error' => 'TCB info missing tdxModule' } unless m.is_a?(Hash)

          mod_mr_signer = m['mrsigner']
          mod_attr = m['attributes']
          mod_mask = m['attributesMask']
        end
        ex_mr = hex_bytes(mod_mr_signer, 48)
        ex_attr = hex_bytes(mod_attr, 8)
        mask = hex_bytes(mod_mask, 8)
        return { 'error' => 'TDX module identity fields malformed' } if ex_mr.nil? || ex_attr.nil? || mask.nil?
        return { 'error' => 'TD report MRSIGNERSEAM does not match the TDX module identity' } if ex_mr != td['mrSignerSeam']
        return { 'error' => 'TD report SEAM attributes do not match the TDX module identity' } unless masked_eq?(td['seamAttributes'], mask, ex_attr)

        start = minor.positive? ? 2 : 0
        levels.each do |l|
          return { 'error' => 'malformed TCB level' } if !l.is_a?(Hash) || !l['tcb'].is_a?(Hash)

          sgx = svns(l['tcb']['sgxtcbcomponents'])
          tdx = svns(l['tcb']['tdxtcbcomponents'])
          return { 'error' => 'malformed TCB level components' } if sgx.nil? || tdx.nil? || !Common.num?(l['tcb']['pcesvn'])

          st = as_status(l['tcbStatus'])
          return { 'error' => 'TCB level has an unknown tcbStatus' } if st.nil?

          match = pck['pcesvn'] >= l['tcb']['pcesvn']
          i = 0
          while match && i < 16
            match = false if pck['sgx'].getbyte(i) < sgx[i]
            i += 1
          end
          i = start
          while match && i < 16
            match = false if td['teeTcbSvn'].getbyte(i) < tdx[i]
            i += 1
          end
          next unless match

          advisories(l).each { |a| adv[a] = true }
          return { 'platform' => st, 'module' => module_status, 'advisories' => adv.keys.sort }
        end
        { 'error' => 'platform TCB is below every level in the TCB info' }
      end

      def evaluate_qe(ident, qe)
        return { 'error' => 'QE identity id is not TD_QE' } if ident['id'] != 'TD_QE'
        return { 'error' => 'unsupported QE identity version' } if !Common.num?(ident['version']) || ident['version'] != 2

        miscsel = hex_bytes(ident['miscselect'], 4)
        misc_mask = hex_bytes(ident['miscselectMask'], 4)
        attr = hex_bytes(ident['attributes'], 16)
        attr_mask = hex_bytes(ident['attributesMask'], 16)
        mrsigner = hex_bytes(ident['mrsigner'], 32)
        if miscsel.nil? || misc_mask.nil? || attr.nil? || attr_mask.nil? || mrsigner.nil? || !Common.num?(ident['isvprodid'])
          return { 'error' => 'QE identity fields malformed' }
        end
        return { 'error' => 'QE report has wrong length' } if qe.bytesize != 384
        return { 'error' => 'QE MISCSELECT does not match the QE identity' } unless masked_eq?(qe.byteslice(16, 4), misc_mask, miscsel)
        return { 'error' => 'QE ATTRIBUTES do not match the QE identity' } unless masked_eq?(qe.byteslice(48, 16), attr_mask, attr)
        return { 'error' => 'QE MRSIGNER does not match the QE identity' } if qe.byteslice(128, 32) != mrsigner

        prod = qe.getbyte(256) | (qe.getbyte(257) << 8)
        isvsvn = qe.getbyte(258) | (qe.getbyte(259) << 8)
        return { 'error' => 'QE ISVPRODID does not match the QE identity' } if prod != ident['isvprodid']

        lv = ident['tcbLevels'].is_a?(Array) ? ident['tcbLevels'] : []
        hit = hit_level(lv, isvsvn)
        return { 'error' => 'QE ISVSVN is below every known level' } if hit.nil?

        st = as_status(hit['tcbStatus'])
        return { 'error' => 'QE level has an unknown tcbStatus' } if st.nil?

        { 'status' => st, 'advisories' => advisories(hit) }
      end

      def text_of(x) = x.is_a?(String) ? x.dup.force_encoding('UTF-8').scrub("�") : x

      # The quote, then its Intel PCS collateral (TCB info, QE identity, CRLs) at `now`: the evaluated TCB status and the policy decision.
      def verify_intel_tdx_collateral(quote, collateral, now_ms, policy = nil, trust_anchor = nil, allow_debug = false)
        fail_with = ->(reason) { { 'ok' => false, 'reason' => reason } }
        c = collateral
        if c.nil? || c.empty? || %w[tcbInfoJson qeIdentityJson pckCrlDer rootCrlDer tcbInfoIssuerChainPem qeIdentityIssuerChainPem].any? { |k| c[k].nil? || c[k] == false || c[k] == '' }
          return fail_with.call('collateral incomplete (fail closed)')
        end

        pin = trust_anchor
        base = verify_genuine_tdx_quote(quote, pin, nil, allow_debug == true ? { 'allowDebug' => true } : nil, now_ms)
        return fail_with.call("quote invalid: #{base['reason'] || 'unknown'}") if !base['ok'] || !base.key?('pckTcb') || base['fmspc'].nil? || base['fmspc'].empty?

        q = parse_dcap_quote(quote)
        quote_certs = Common.pem_blocks(q['pckChainPem']).map { |b| Cert.from_pem(b) }
        quote_certs.each do |x|
          return fail_with.call('PCK chain certificate outside its validity period') unless Der.x509_valid_at?(x.raw, now_ms)
        end
        leaf = quote_certs.find { |x| quote_certs.none? { |y| y.issuer == x.subject } }
        return fail_with.call('PCK leaf not found') if leaf.nil?

        ca = quote_certs.find { |x| x.subject == leaf.issuer }
        return fail_with.call('PCK CA not found in the quote chain') if ca.nil?

        root = quote_certs.find { |x| x.subject == x.issuer }
        return fail_with.call('Intel root not found in the quote chain') if root.nil?

        root_crl = verify_crl(c['rootCrlDer'], root.public_key, now_ms)
        return fail_with.call("Intel Root CA CRL: #{root_crl['reason']}") unless root_crl['ok']

        pck_crl = verify_crl(c['pckCrlDer'], ca.public_key, now_ms)
        return fail_with.call("PCK CRL: #{pck_crl['reason']}") unless pck_crl['ok']
        return fail_with.call('PCK CA certificate is revoked by the Intel Root CA CRL') if serial_is_revoked?(root_crl['revoked'], ca.serial_hex)
        return fail_with.call('PCK leaf certificate is revoked by the PCK CRL') if serial_is_revoked?(pck_crl['revoked'], leaf.serial_hex)

        tcb_key = signer_key_from_chain(c['tcbInfoIssuerChainPem'], pin, now_ms, root_crl['revoked'])
        return fail_with.call("TCB info: #{tcb_key['error']}") if tcb_key.key?('error')

        tcb_doc = verify_signed_json(text_of(c['tcbInfoJson']), 'tcbInfo', tcb_key['key'])
        return fail_with.call("TCB info: #{tcb_doc['error']}") if tcb_doc.key?('error')

        info = tcb_doc['body']
        stale = check_fresh(info, 'TCB info', now_ms)
        return fail_with.call(stale) if stale
        return fail_with.call('TCB info is not a TDX v3 document') if info['id'] != 'TDX' || !Common.num?(info['version']) || info['version'] != 3
        return fail_with.call('TCB info FMSPC does not match the quote PCK') if !info['fmspc'].is_a?(String) || info['fmspc'].downcase != base['fmspc']

        qe_key = signer_key_from_chain(c['qeIdentityIssuerChainPem'], pin, now_ms, root_crl['revoked'])
        return fail_with.call("QE identity: #{qe_key['error']}") if qe_key.key?('error')

        qe_doc = verify_signed_json(text_of(c['qeIdentityJson']), 'enclaveIdentity', qe_key['key'])
        return fail_with.call("QE identity: #{qe_doc['error']}") if qe_doc.key?('error')

        stale_qe = check_fresh(qe_doc['body'], 'QE identity', now_ms)
        return fail_with.call(stale_qe) if stale_qe

        min_eval = (policy || {})['minTcbEvaluationDataNumber']
        info_num = Common.num?(info['tcbEvaluationDataNumber']) ? info['tcbEvaluationDataNumber'] : -1
        qe_num = Common.num?(qe_doc['body']['tcbEvaluationDataNumber']) ? qe_doc['body']['tcbEvaluationDataNumber'] : -1
        return fail_with.call('tcbEvaluationDataNumber missing') if info_num.negative? || qe_num.negative?
        return fail_with.call('tcbEvaluationDataNumber below policy minimum') if !min_eval.nil? && (info_num < min_eval || qe_num < min_eval)

        body = q['tdReportBody']
        td = { 'teeTcbSvn' => body.byteslice(0, 16), 'mrSignerSeam' => body.byteslice(64, 48), 'seamAttributes' => body.byteslice(112, 8) }
        pck = extract_pck_fmspc_and_tcb(leaf.raw)
        tcb = evaluate_tcb(info, { 'sgx' => pck['sgxTcbComponents'], 'pcesvn' => pck['pcesvn'] }, td)
        return fail_with.call("TCB evaluation: #{tcb['error']}") if tcb.key?('error')

        qe = evaluate_qe(qe_doc['body'], q['qeReportBody'])
        return fail_with.call("QE identity: #{qe['error']}") if qe.key?('error')

        status = worst(worst(tcb['platform'], tcb['module']), qe['status'])
        advisory_ids = (tcb['advisories'] | qe['advisories']).sort
        result = { 'ok' => false, 'status' => status, 'advisoryIds' => advisory_ids }
        accepted = (policy || {})['acceptStatuses']
        accepted = DEFAULT_ACCEPTED_STATUSES if accepted.nil?
        unless accepted.include?(status)
          result['reason'] = "TCB status #{status} is not accepted by policy"
          return result
        end
        result['ok'] = true
        result
      rescue StandardError => e
        fail_with.call("collateral verification error (fail closed): #{e.message}")
      end
    end

    # `verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}.
    class IntelDcapVerifier
      def initialize(opts)
        unless %w[report-data azure-runtime-data].include?(opts['binding'])
          raise AttestConstructError, "createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'"
        end

        @binding = opts['binding']
        pol = opts['policy'].is_a?(Hash) ? opts['policy'] : {}
        mrtds_in = pol['mrtds']
        if !mrtds_in.is_a?(Array) || mrtds_in.empty?
          raise AttestConstructError, 'createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)'
        end

        mrtds = mrtds_in.map(&:downcase)
        if mrtds.any? { |m| !m.match?(/\A[0-9a-f]+\z/) || m.length != 96 }
          raise AttestConstructError, 'createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)'
        end

        %w[mrSeams mrSignerSeams].each do |name|
          next unless pol.key?(name)

          lst = pol[name]
          raise AttestConstructError, "createIntelDcapVerifier: policy.#{name}, if given, must be a NON-EMPTY list" if !lst.is_a?(Array) || lst.empty?
          if lst.any? { |m| !m.is_a?(String) || !m.match?(/\A[0-9a-fA-F]+\z/) || m.length != 96 }
            raise AttestConstructError, "createIntelDcapVerifier: every #{name} entry must be 96 hex chars (48 bytes)"
          end
        end
        anchor = opts['trustAnchorRootCaSpkiSha256']
        @pin = (anchor.nil? ? Intel::SGX_ROOT_CA_SPKI_SHA256 : anchor).downcase
        @policy = pol
        @mrtds = mrtds
        @allow_missing = opts['allowMissingCollateral'] == true
        @resolve = opts['resolve_evidence']
      end

      def verify(document, expected, now_ms)
        fail_with = ->(reason) { { 'ok' => false, 'reason' => reason } }
        return fail_with.call('no Intel DCAP evidence resolver configured (fail closed)') if @resolve.nil?

        ev = @resolve.call(document)
        return fail_with.call('no Intel DCAP quote for this action') if !ev.is_a?(Hash) || !ev['quote'].is_a?(String)
        return fail_with.call('no expected attestation binding supplied') if expected.nil?

        pol = @policy
        gp = { 'mrtds' => @mrtds }
        %w[mrSeams mrSignerSeams fmspcs rtmrs].each { |k| gp[k] = pol[k] if mesh_truthy(pol[k]) }
        gp['allowDebug'] = true if pol['allowDebug'] == true
        quote = ev['quote'].b
        q = Intel.verify_genuine_tdx_quote(quote, @pin, nil, gp, now_ms)
        if !q['ok'] || !q.key?('report') || !q.key?('measured') || q['fmspc'].nil? || q['fmspc'].empty?
          return fail_with.call("DCAP quote invalid: #{q['reason'] || 'unknown'}")
        end

        if @binding == 'report-data'
          begin
            want = Common.attestation_binding(expected)
          rescue JsTypeError => e
            return fail_with.call("binding not constructible: #{e.message}")
          end
          return fail_with.call('report_data does not bind holder/grant/epoch/nonce') if q['report']['reportData'] != want
        else
          rd = ev['runtimeData']
          return fail_with.call('azure-runtime-data binding needs the runtime-data JSON bytes') unless rd.is_a?(String)

          why = Amd.check_azure_runtime_data_binding(q['report']['reportData'], rd, expected)
          return fail_with.call(why) if why
        end
        host = { 'attestation_type' => 'tdx-dcap', 'fmspc' => q['fmspc'] }
        col = ev['collateral']
        if mesh_truthy(col)
          c = Intel.verify_intel_tdx_collateral(quote, col, now_ms, mesh_truthy(pol['collateral']) ? pol['collateral'] : nil, @pin, pol['allowDebug'] == true)
          host['tcb_status'] = c['status'] if c['status'] && !c['status'].empty?
          host['advisory_ids'] = c['advisoryIds'].join(',') if c['advisoryIds'] && !c['advisoryIds'].empty?
          return fail_with.call("Intel collateral: #{c['reason'] || 'rejected'}") unless c['ok']
        elsif @allow_missing
          host['tcb_status'] = 'unevaluated'
        else
          return fail_with.call('Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)')
        end
        { 'ok' => true, 'bound' => true, 'measured' => q['measured'], 'hostAsserted' => host }
      rescue StandardError => e
        fail_with.call("intel-dcap verification error (fail closed): #{e.message}")
      end

      private

      def mesh_truthy(v) = AtlasPca.mesh_truthy?(v)
    end
  end
end
