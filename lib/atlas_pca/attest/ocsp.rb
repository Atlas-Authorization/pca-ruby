# frozen_string_literal: true

# NVIDIA device-chain revocation through OCSP (RFC 6960), native counterpart of `checkNvidiaChainOcsp`.
#
# Verifies, offline, the DER OCSPResponses a caller obtained: responseStatus SUCCESSFUL with id-pkix-ocsp-basic, the CertID
# (serial + issuer name / key hashes), the BasicOCSPResponse signature under the issuing CA or a delegated responder certificate
# (signed by the supplied chain, inside its validity window, with the id-kp-OCSPSigning EKU), freshness, and the certStatus.
# Fails closed; the reason strings are those of the reference implementation.
require_relative 'cert'

module AtlasPca
  module Attest
    class OcspError < StandardError; end

    module Ocsp
      OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1'
      OID_AIA = '1.3.6.1.5.5.7.1.1'
      OID_AD_OCSP = '1.3.6.1.5.5.7.48.1'
      OID_EKU_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9'
      OID_EKU = '2.5.29.37'
      HASHES = { '1.3.14.3.2.26' => 'sha1', '2.16.840.1.101.3.4.2.1' => 'sha256', '2.16.840.1.101.3.4.2.2' => 'sha384',
                 '2.16.840.1.101.3.4.2.3' => 'sha512' }.freeze
      SIG_ALGS = { '1.2.840.10045.4.3.2' => %w[sha256 ec], '1.2.840.10045.4.3.3' => %w[sha384 ec], '1.2.840.10045.4.3.4' => %w[sha512 ec],
                   '1.2.840.113549.1.1.11' => %w[sha256 rsa], '1.2.840.113549.1.1.12' => %w[sha384 rsa],
                   '1.2.840.113549.1.1.13' => %w[sha512 rsa] }.freeze
      DEFAULT_MAX_AGE_MS = 7 * 24 * 3600 * 1000
      GEN_TIME = /\A([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]*[1-9]))?Z\z/
      UTC_TIME = /\A([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\z/

      module_function

      def time_in_range?(text, utc)
        m = (utc ? UTC_TIME : GEN_TIME).match(text)
        return false if m.nil?

        y = m[1].to_i
        y += y < 50 ? 2000 : 1900 if utc
        mo = m[2].to_i
        d = m[3].to_i
        h = m[4].to_i
        mi = m[5].to_i
        se = m[6].to_i
        return false if mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59

        d <= Der.days_in_month(y, mo)
      end

      def latin1(b) = b.dup.force_encoding('ISO-8859-1').encode('UTF-8')

      # Every UTCTime / GeneralizedTime anywhere in the (constructed) structure is a well-formed, in-range DER time.
      def all_times_well_formed?(der, start, end_)
        p = start
        while p < end_
          t = Der.tlv_at(der, p)
          raise OcspError, 'element overruns its parent' if t.end_ > end_

          if t.tag.nobits?(0xC0) && [23, 24].include?(t.tag & 0x1F) && t.tag.nobits?(0x20)
            return false unless time_in_range?(latin1(der.byteslice(t.start, t.end_ - t.start)), (t.tag & 0x1F) == 23)
          elsif t.tag.anybits?(0x20)
            return false unless all_times_well_formed?(der, t.start, t.end_)
          end
          p = t.end_
        end
        true
      end

      def gen_time_ms(text)
        m = GEN_TIME.match(text)
        if m
          y = m[1].to_i
          ms = (m[7] || '0')[0, 3].ljust(3, '0').to_i
        else
          m = UTC_TIME.match(text)
          raise OcspError, 'response times are not parseable' if m.nil?

          y = m[1].to_i
          y += y < 50 ? 2000 : 1900
          ms = 0
        end
        mo = m[2].to_i
        d = m[3].to_i
        h = m[4].to_i
        mi = m[5].to_i
        se = m[6].to_i
        ((((((Der.days_from_civil(y, mo, d) * 24) + h) * 60) + mi) * 60) + se) * 1000 + ms
      end

      # The child TLVs of a constructed element, each with the offset of its header.
      def children(der, t)
        out = []
        p = t.start
        while p < t.end_
          c = Der.tlv_at(der, p)
          raise OcspError, 'element overruns its parent' if c.end_ > t.end_

          out << [c, p]
          p = c.end_
        end
        out
      end

      def strip_zeros(b)
        i = 0
        i += 1 while i < b.bytesize - 1 && b.getbyte(i).zero?
        b.byteslice(i..)
      end

      def spki_key_bits(spki_der)
        seq = Der.tlv_at(spki_der, 0)
        kids = children(spki_der, seq)
        raise OcspError, 'malformed SubjectPublicKeyInfo' if kids.length < 2 || kids[1][0].tag != 0x03

        t = kids[1][0]
        spki_der.byteslice(t.start + 1, t.end_ - t.start - 1)
      end

      def verify_sig(alg_oid, tbs, sig, key)
        a = SIG_ALGS[alg_oid]
        return false if a.nil?

        hname, kind = a
        t = Common.key_type(key)
        return false if (kind == 'ec') != (t == 'ec')
        return false if kind == 'rsa' && t != 'rsa'

        kind == 'ec' ? Common.ecdsa_verify_der(key, sig, tbs, hname) : Common.rsa_pkcs1_verify(key, sig, tbs, hname)
      rescue StandardError
        false
      end

      def cert_id_hashes(issuer, hname)
        d = OpenSSL::Digest.new(hname.upcase)
        [d.digest(issuer.subject_der), OpenSSL::Digest.new(hname.upcase).digest(spki_key_bits(issuer.spki_der))]
      end

      def eku_of(cert)
        ext = cert.extensions[OID_EKU]
        return nil if ext.nil?

        seq = Der.read_tlv(ext.value, 0)
        return nil if seq.tag != 0x30

        out = []
        p = seq.start
        while p < seq.end_
          o = Der.read_tlv(ext.value, p, seq.end_)
          out << Der.oid_to_dotted(ext.value, o)
          p = o.end_
        end
        out
      rescue DerError
        nil
      end

      def fail_with(reason) = { 'ok' => false, 'reason' => reason }

      # One DER OCSPResponse for `cert`. Never raises; any malformation is {ok: false}.
      def verify_ocsp_response(response_der, cert, issuer, chain, now_ms, max_age_ms = nil, clock_skew_ms = 0)
        verify_inner(response_der.b, cert, issuer, chain, now_ms, max_age_ms, clock_skew_ms)
      rescue StandardError => e
        fail_with("OCSP response rejected: #{e.message}")
      end

      def verify_inner(der, cert, issuer, chain, now_ms, max_age_ms, skew)
        max_age = max_age_ms.nil? ? DEFAULT_MAX_AGE_MS : max_age_ms
        begin
          top = Der.tlv_at(der, 0)
        rescue DerError
          return fail_with('response is not valid DER')
        end
        return fail_with('trailing bytes after OCSPResponse') if top.end_ != der.bytesize
        raise OcspError, 'OCSPResponse is not a SEQUENCE' if top.tag != 0x30

        kids = children(der, top)
        raise OcspError, 'responseStatus is not an ENUMERATED' if kids.empty? || kids[0][0].tag != 0x0A

        status = der.byteslice(kids[0][0].start, kids[0][0].end_ - kids[0][0].start).unpack1('H*').to_i(16)
        return fail_with("OCSP responseStatus is #{status} (not successful)") if status != 0
        return fail_with('successful response carries no responseBytes') if kids.length < 2 || kids[1][0].tag != 0xA0

        rb = children(der, kids[1][0])
        raise OcspError, 'responseBytes is not a SEQUENCE' if rb.empty? || rb[0][0].tag != 0x30

        rbk = children(der, rb[0][0])
        raise OcspError, 'responseBytes is malformed' if rbk.length < 2 || rbk[0][0].tag != 0x06 || rbk[1][0].tag != 0x04
        return fail_with('responseType is not id-pkix-ocsp-basic') if Der.oid_to_dotted(der, rbk[0][0]) != OID_OCSP_BASIC

        basic = der.byteslice(rbk[1][0].start, rbk[1][0].end_ - rbk[1][0].start)
        begin
          btop = Der.tlv_at(basic, 0)
        rescue DerError
          return fail_with('BasicOCSPResponse is not valid DER')
        end
        raise OcspError, 'BasicOCSPResponse is not a SEQUENCE' if btop.tag != 0x30

        bk = children(basic, btop)
        raise OcspError, 'BasicOCSPResponse is malformed' if bk.length < 3 || bk[0][0].tag != 0x30 || bk[1][0].tag != 0x30 || bk[2][0].tag != 0x03
        return fail_with('response carries a malformed (out-of-range) ASN.1 time') unless all_times_well_formed?(basic, btop.start, btop.end_)

        tbs_t, tbs_off = bk[0]
        tbs_bytes = basic.byteslice(tbs_off, tbs_t.end_ - tbs_off)
        return fail_with('missing tbsResponseData') if tbs_bytes.empty?

        sig_alg_t = bk[1][0]
        sig_alg_oid = Der.oid_to_dotted(basic, Der.tlv_at(basic, sig_alg_t.start))
        return fail_with("unsupported OCSP signature algorithm #{sig_alg_oid}") unless SIG_ALGS.key?(sig_alg_oid)

        sig = basic.byteslice(bk[2][0].start + 1, bk[2][0].end_ - bk[2][0].start - 1)

        # ResponseData
        rd = children(basic, tbs_t)
        idx = 0
        idx += 1 if idx < rd.length && rd[idx][0].tag == 0xA0 # version
        raise OcspError, 'responderID is malformed' if idx >= rd.length || ![0xA1, 0xA2].include?(rd[idx][0].tag)

        rid_t = rd[idx][0]
        idx += 1
        raise OcspError, 'producedAt is malformed' if idx >= rd.length || rd[idx][0].tag != 0x18

        produced_at = gen_time_ms(latin1(basic.byteslice(rd[idx][0].start, rd[idx][0].end_ - rd[idx][0].start)))
        idx += 1
        raise OcspError, 'responses is malformed' if idx >= rd.length || rd[idx][0].tag != 0x30

        responses_t = rd[idx][0]

        # CertID match
        matches = []
        children(basic, responses_t).each do |single_t, single_off|
          sk = children(basic, single_t)
          raise OcspError, 'SingleResponse is malformed' if sk.length < 3 || sk[0][0].tag != 0x30

          cid = children(basic, sk[0][0])
          raise OcspError, 'CertID is malformed' if cid.length < 4

          alg = Der.tlv_at(basic, cid[0][0].start)
          hname = HASHES[Der.oid_to_dotted(basic, alg)]
          next if hname.nil?

          want_name, want_key = cert_id_hashes(issuer, hname)
          if strip_zeros(basic.byteslice(cid[3][0].start, cid[3][0].end_ - cid[3][0].start)) == strip_zeros(cert.serial) &&
             basic.byteslice(cid[1][0].start, cid[1][0].end_ - cid[1][0].start) == want_name &&
             basic.byteslice(cid[2][0].start, cid[2][0].end_ - cid[2][0].start) == want_key
            matches << [single_t, single_off]
          end
        end
        return fail_with('no SingleResponse matches the certificate (serial / issuer hashes differ)') if matches.empty?
        return fail_with('ambiguous: multiple SingleResponses match the certificate') if matches.length > 1

        single_t, = matches[0]
        sk = children(basic, single_t)

        rid_matches = lambda do |c|
          if rid_t.tag == 0xA1 # byName
            inner = children(basic, rid_t)
            next inner.length == 1 && basic.byteslice(inner[0][1], inner[0][0].end_ - inner[0][1]) == c.subject_der
          end
          oct_t = Der.tlv_at(basic, rid_t.start) # byKey [2] EXPLICIT OCTET STRING
          oct_t.tag == 0x04 && basic.byteslice(oct_t.start, oct_t.end_ - oct_t.start) == Digest::SHA1.digest(spki_key_bits(c.spki_der))
        end

        issuer_pub = issuer.public_key
        responder = 'issuer'
        is_issuer_id = rid_matches.call(issuer)
        issuer_ok = is_issuer_id && verify_sig(sig_alg_oid, tbs_bytes, sig, issuer_pub)
        unless issuer_ok
          embedded = []
          if bk.length > 3 && bk[3][0].tag == 0xA0
            children(basic, bk[3][0]).each do |st, _soff|
              children(basic, st).each { |ct, coff| embedded << Cert.new(basic.byteslice(coff, ct.end_ - coff)) }
            end
          end
          found = false
          why = 'no embedded responder certificate verifies the response'
          embedded.each do |cand|
            unless rid_matches.call(cand)
              why = 'embedded certificates do not match the responderID'
              next
            end
            eku = eku_of(cand)
            if eku.nil? || !eku.include?(OID_EKU_OCSP_SIGNING)
              why = 'delegated responder certificate lacks the id-kp-OCSPSigning EKU'
              next
            end
            nb, na = Der.der_validity_ms(cand.raw)
            if nb.nil? || na.nil? || !(nb - skew <= now_ms && now_ms <= na)
              why = 'delegated responder certificate is outside its validity window'
              next
            end
            issuer_idx = chain.index { |c| c.raw == issuer.raw } || -1
            signers = issuer_idx >= 0 ? chain[issuer_idx..] : [issuer]
            unless signers.any? { |s| cand.check_issued(s) && cand.verify(s.public_key) }
              why = 'delegated responder certificate is not signed by the supplied NVIDIA chain'
              next
            end
            unless verify_sig(sig_alg_oid, tbs_bytes, sig, cand.public_key)
              why = 'OCSP response signature does not verify under the delegated responder key'
              next
            end
            found = true
            break
          end
          return fail_with(is_issuer_id ? 'OCSP response signature does not verify under the issuer key' : why) unless found

          responder = 'delegated'
        end

        # freshness: certStatus is sk[1]; thisUpdate follows it
        status_t = sk[1][0]
        time_t = sk[2][0]
        raise OcspError, 'thisUpdate is malformed' if time_t.tag != 0x18

        this_update = gen_time_ms(latin1(basic.byteslice(time_t.start, time_t.end_ - time_t.start)))
        next_update = nil
        if sk.length > 3 && sk[3][0].tag == 0xA0
          inner = children(basic, sk[3][0])
          raise OcspError, 'nextUpdate is malformed' if inner.empty? || inner[0][0].tag != 0x18

          next_update = gen_time_ms(latin1(basic.byteslice(inner[0][0].start, inner[0][0].end_ - inner[0][0].start)))
        end
        return fail_with('response thisUpdate is in the future') if this_update > now_ms + skew
        return fail_with('response producedAt is in the future') if produced_at > now_ms + skew
        unless next_update.nil?
          return fail_with('response nextUpdate is invalid') if next_update < this_update
          return fail_with('response is stale (past nextUpdate)') if now_ms > next_update
        end
        return fail_with('response is older than the maximum accepted age') if now_ms - this_update > max_age
        return fail_with('malformed certStatus') if status_t.tag.nobits?(0x80) || status_t.tag.anybits?(0x40) # not a context-specific tag

        num = status_t.tag & 0x1F
        return { 'ok' => true, 'status' => 'good', 'responder' => responder } if num.zero?
        return { 'ok' => true, 'status' => 'unknown', 'responder' => responder } if num == 2
        if num == 1
          kids2 = children(basic, status_t)
          return fail_with('malformed revoked certStatus') if kids2.empty?

          txt = latin1(basic.byteslice(kids2[0][0].start, kids2[0][0].end_ - kids2[0][0].start))
          return fail_with('malformed revoked certStatus') unless txt.match?(/\A[0-9]{14}Z\z/)

          return { 'ok' => true, 'status' => 'revoked', 'responder' => responder }
        end
        fail_with('unrecognised certStatus')
      end

      # OCSP responder URLs advertised in the Authority Information Access extension.
      def cert_ocsp_urls(cert)
        ext = cert.extensions[OID_AIA]
        return [] if ext.nil?

        seq = Der.read_tlv(ext.value, 0)
        return [] if seq.tag != 0x30

        out = []
        p = seq.start
        while p < seq.end_
          ad = Der.read_tlv(ext.value, p, seq.end_)
          p = ad.end_
          oid_t = Der.read_tlv(ext.value, ad.start, ad.end_)
          loc = Der.read_tlv(ext.value, oid_t.end_, ad.end_)
          out << latin1(ext.value.byteslice(loc.start, loc.end_ - loc.start)) if Der.oid_to_dotted(ext.value, oid_t) == OID_AD_OCSP && loc.tag == 0x86
        end
        out
      rescue DerError
        []
      end

      def subj(c) = c.subject.gsub("\n", ', ')

      # The device chain against OCSP responses. Every response must verify for exactly one chain certificate; any REVOKED
      # fails; each certificate that advertises an OCSP URL must have a GOOD response.
      def check_nvidia_chain_ocsp(chain, responses, now_ms, max_age_ms = nil)
        return { 'ok' => false, 'reason' => 'chain too short for OCSP' } if chain.length < 2
        return { 'ok' => false, 'reason' => 'no OCSP responses supplied' } if responses.empty?

        last = chain.length - 1
        required = (0...last).select { |i| !cert_ocsp_urls(chain[i]).empty? }
        statuses = (0...last).to_h { |i| [i, 'absent'] }
        verified = 0
        responses.each_with_index do |der, ri|
          matched = false
          last_reason = 'matches no chain certificate'
          last.times do |i|
            r = verify_ocsp_response(der, chain[i], chain[i + 1], chain, now_ms, max_age_ms)
            unless r['ok']
              unless r['reason'].start_with?('no SingleResponse matches')
                return { 'ok' => false, 'reason' => "OCSP response ##{ri} for '#{subj(chain[i])}' rejected: #{r['reason']}", 'statuses' => statuses }
              end

              last_reason = r['reason']
              next
            end
            if matched
              return { 'ok' => false, 'reason' => "OCSP response ##{ri} matches more than one chain certificate", 'statuses' => statuses }
            end

            matched = true
            if statuses[i] != 'absent'
              return { 'ok' => false, 'reason' => "duplicate OCSP responses for chain certificate ##{i}", 'statuses' => statuses }
            end

            statuses[i] = r['status']
            verified += 1
            if r['status'] == 'revoked'
              return { 'ok' => false, 'reason' => "chain certificate '#{subj(chain[i])}' is revoked (OCSP)", 'statuses' => statuses }
            end
          end
          return { 'ok' => false, 'reason' => "OCSP response ##{ri} rejected: #{last_reason}", 'statuses' => statuses } unless matched
        end
        required.sort.each do |i|
          if statuses[i] != 'good'
            return { 'ok' => false, 'reason' => "no GOOD OCSP response for required certificate '#{subj(chain[i])}' (status: #{statuses[i]})", 'statuses' => statuses }
          end
        end
        { 'ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => verified, 'statuses' => statuses }
      end
    end
  end
end
