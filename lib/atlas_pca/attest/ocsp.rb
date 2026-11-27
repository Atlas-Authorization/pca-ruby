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
      OID_OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2'
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
      class TooDeep < StandardError; end

      # depth <= 100 and <= 10000 nodes (matches the TS asn1js bounds); `count` is a one-element array shared by the recursion.
      def all_times_well_formed?(der, start, end_, depth = 0, count = [0])
        raise TooDeep if depth > 100

        p = start
        while p < end_
          t = Der.tlv_at(der, p)
          raise OcspError, 'element overruns its parent' if t.end_ > end_

          count[0] += 1
          raise TooDeep if count[0] > 10_000

          if t.tag.nobits?(0xC0) && [23, 24].include?(t.tag & 0x1F) && t.tag.nobits?(0x20)
            return false unless time_in_range?(latin1(der.byteslice(t.start, t.end_ - t.start)), (t.tag & 0x1F) == 23)
          elsif t.tag.anybits?(0x20)
            return false unless all_times_well_formed?(der, t.start, t.end_, depth + 1, count)
          end
          p = t.end_
        end
        true
      end

      # The reader the reference parses a response with is lenient in one way a strict DER reader is not: a child is checked against the whole
      # buffer, never against the end its parent declared (the parent just continues after what the child consumed), indefinite lengths are read to
      # their end-of-contents, and certificates are re-encoded from that tree before they are used. Reproduced here so a response is accepted or
      # refused the same way: depth <= 100, nodes <= 10000, content <= 16 MiB, anything else that cannot be read is Invalid.
      class Ber
        class Invalid < StandardError; end
        Node = Struct.new(:id, :cons, :long, :indef, :kids, :val, :start)

        def self.parse(der)
          raise Invalid, 'empty' if der.empty?

          new(der).read(0, der.bytesize, 0)[0]
        end

        # The parsed certificate (or any element) of `der` written back with every length recomputed, as the reference re-encodes it.
        def self.reencode(der) = encode(parse(der))

        def self.encode(n)
          body = n.cons ? n.kids.map { |k| encode(k) }.join.b + (n.indef ? "\x00\x00".b : ''.b) : n.val
          len = if n.indef then "\x80".b
                elsif n.long || body.bytesize > 127
                  b = [body.bytesize].pack('Q>').sub(/\A\x00+/n, '')
                  b = "\x00".b if b.empty?
                  [0x80 | b.bytesize].pack('C') + b
                else [body.bytesize].pack('C')
                end
          n.id + len + body
        end

        # Every UTCTime / GeneralizedTime (universal, primitive) outside an OCTET / BIT STRING is a well-formed, in-range time.
        def self.times_ok?(n)
          return true if n.id.getbyte(0) & 0xC0 == 0 && [3, 4].include?(n.id.getbyte(0) & 0x1F)
          return n.kids.all? { |k| times_ok?(k) } if n.cons

          t = n.id.getbyte(0)
          return true unless t & 0xC0 == 0 && [23, 24].include?(t & 0x1F)

          Ocsp.time_in_range?(Ocsp.latin1(n.val), (t & 0x1F) == 23)
        end

        def initialize(der)
          @der = der
          @nodes = 0
        end

        # [node, next offset, block length]; `avail` is what the parent still declares (it can run out while a child overshoots).
        def read(off, avail, depth)
          raise Invalid, 'depth' if depth > 100
          raise Invalid, 'buffer' if avail <= 0 || @der.bytesize - off - avail < 0
          raise Invalid, 'nodes' if (@nodes += 1) > 10_000

          b0 = @der.getbyte(off)
          idlen = 1
          if b0 & 0x1F == 0x1F
            loop do
              raise Invalid, 'identifier' if idlen >= avail

              idlen += 1
              break if @der.getbyte(off + idlen - 1) & 0x80 == 0
            end
          end
          avail -= idlen
          p = off + idlen
          raise Invalid, 'length' if avail <= 0

          lb = @der.getbyte(p)
          raise Invalid, 'length' if lb == 0xFF

          indef = lb == 0x80
          long = false
          if indef || lb & 0x80 == 0
            length = indef ? 0 : lb
            lenlen = 1
          else
            cnt = lb & 0x7F
            raise Invalid, 'length' if cnt > 8 || cnt + 1 > avail

            length = @der.byteslice(p + 1, cnt).unpack('C*').inject(0) { |a, x| (a << 8) | x }
            long = true
            lenlen = cnt + 1
          end
          avail -= lenlen
          p += lenlen
          vlen = indef ? avail : length
          cons = b0 & 0x20 != 0
          raise Invalid, 'content' if vlen > 16 * 1024 * 1024 || (!cons && indef) || @der.bytesize - p - vlen < 0
          raise Invalid, 'reserved' if b0 & 0xC0 == 0 && ((b0 & 0x1F).zero? && cons && length.positive? || b0 & 0x1F == 15)

          node = Node.new(@der.byteslice(off, idlen), cons, long, indef, [], nil, p)
          unless cons
            node.val = @der.byteslice(p, vlen)
            return [node, p + vlen, idlen + lenlen + vlen]
          end

          cur = p
          bl = idlen + lenlen
          remaining = vlen
          while vlen.positive? && (indef || remaining.positive?)
            kid, cur, kbl = read(cur, remaining, depth + 1)
            bl += kbl
            remaining -= kbl
            node.kids << kid
            break if indef && kid.id == "\x00".b && !kid.cons # end-of-contents
          end
          node.kids.pop if indef && !node.kids.empty? && node.kids.last.id == "\x00".b && !node.kids.last.cons
          [node, cur, bl]
        end
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
      # `detail`: a success also carries thisUpdate, nextUpdate, producedAt, revokedAt and revocationReason (the reference's result); `expected_nonce`:
      # the response MUST echo exactly it.
      def verify_ocsp_response(response_der, cert, issuer, chain, now_ms, max_age_ms = nil, clock_skew_ms = 0, expected_nonce = nil, detail = false)
        r = verify_inner(response_der.b, cert, issuer, chain, now_ms, max_age_ms, clock_skew_ms, expected_nonce)
        detail || !r['ok'] ? r : r.slice('ok', 'status', 'responder')
      rescue StandardError, SystemStackError => e
        fail_with("OCSP response rejected: #{e.message}")
      end

      def verify_inner(der, cert, issuer, chain, now_ms, max_age_ms, skew, expected_nonce = nil)
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
          ber = Ber.parse(basic)
          btop = Der.tlv_at(basic, 0)
        rescue DerError, Ber::Invalid
          return fail_with('BasicOCSPResponse is not valid DER')
        end
        raise OcspError, 'BasicOCSPResponse is not a SEQUENCE' if btop.tag != 0x30

        bk = children(basic, btop)
        raise OcspError, 'BasicOCSPResponse is malformed' if bk.length < 3 || bk[0][0].tag != 0x30 || bk[1][0].tag != 0x30 || bk[2][0].tag != 0x03
        return fail_with('response carries a malformed (out-of-range) ASN.1 time') unless Ber.times_ok?(ber)

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
        ext_t = idx + 1 < rd.length && rd[idx + 1][0].tag == 0xA1 ? rd[idx + 1][0] : nil # [1] EXPLICIT responseExtensions

        # CertID match
        matches = []
        children(basic, responses_t).each do |single_t, single_off|
          sk = children(basic, single_t)
          raise OcspError, 'SingleResponse is malformed' if sk.length < 3 || sk[0][0].tag != 0x30
          # after thisUpdate only nextUpdate then singleExtensions: anything else would hide a past nextUpdate
          raise OcspError, 'SingleResponse is malformed' unless [[], [0xA0], [0xA1], [0xA0, 0xA1]].include?(sk[3..].map { |t, _| t.tag })

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
              children(basic, st).each do |ct, coff|
                # the certificate is taken from the response's own bytes, never re-encoded: a re-encoding turns a malformed copy (a wrong
                # inner length, a stray byte) into the genuine one, so a tampered certificate would verify
                raw = basic.byteslice(coff, ct.end_ - coff)
                cert = begin
                  Cert.new(raw)
                rescue StandardError
                  raise 'embedded certificate is not valid DER' # a fixed text: a parser's own message differs by version and language
                end
                raise 'embedded certificate is not canonical DER' unless cert.raw == raw

                embedded << cert
              end
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

        # the nonce: when one is expected the response MUST echo exactly it
        unless expected_nonce.nil?
          echoed = nil
          if ext_t
            children(basic, ext_t).each do |seq_t, _o|
              children(basic, seq_t).each do |e_t, _eo|
                ek = children(basic, e_t)
                next if ek.length < 2 || ek[0][0].tag != 0x06 || Der.oid_to_dotted(basic, ek[0][0]) != OID_OCSP_NONCE

                val_t = ek[-1][0]
                raw = basic.byteslice(val_t.start, val_t.end_ - val_t.start)
                echoed = raw
                begin
                  inner = Der.tlv_at(raw, 0)
                  echoed = raw.byteslice(inner.start, inner.end_ - inner.start) if inner.end_ == raw.bytesize && inner.tag == 0x04
                rescue DerError
                  echoed = raw
                end
                break
              end
              break unless echoed.nil?
            end
          end
          return fail_with('response does not echo the nonce') if echoed.nil?
          return fail_with('response nonce does not match the request nonce') if echoed.b != expected_nonce.b
        end

        # freshness: certStatus is sk[1]; thisUpdate follows it
        status_t = sk[1][0]
        time_t = sk[2][0]
        raise OcspError, 'thisUpdate is malformed' if time_t.tag != 0x18

        this_update = gen_time_ms(latin1(basic.byteslice(time_t.start, time_t.end_ - time_t.start)))
        next_update = nil
        if sk.length > 3 && sk[3][0].tag == 0xA0
          inner = children(basic, sk[3][0])
          raise OcspError, 'nextUpdate is malformed' if inner.length != 1 || inner[0][0].tag != 0x18

          next_update = gen_time_ms(latin1(basic.byteslice(inner[0][0].start, inner[0][0].end_ - inner[0][0].start)))
        end
        return fail_with('response thisUpdate is in the future') unless Attestation.finite?(now_ms) && Attestation.finite?(skew) && this_update <= now_ms + skew
        return fail_with('response producedAt is in the future') unless produced_at <= now_ms + skew
        unless next_update.nil?
          return fail_with('response nextUpdate is invalid') if next_update < this_update
          return fail_with('response is stale (past nextUpdate)') unless now_ms <= next_update
        end
        return fail_with('response is older than the maximum accepted age') unless now_ms - this_update <= max_age
        return fail_with('malformed certStatus') if status_t.tag.nobits?(0x80) || status_t.tag.anybits?(0x40) # not a context-specific tag

        times = { 'thisUpdate' => this_update, 'producedAt' => produced_at }
        times['nextUpdate'] = next_update unless next_update.nil?
        return { 'ok' => true, 'status' => 'good' }.merge(times, 'responder' => responder) if status_t.tag == 0x80
        return { 'ok' => true, 'status' => 'unknown' }.merge(times, 'responder' => responder) if status_t.tag == 0x82
        return fail_with('malformed certStatus') if [0xA0, 0xA2, 0x81].include?(status_t.tag) # the right number in the wrong form
        if status_t.tag == 0xA1
          kids2 = children(basic, status_t)
          return fail_with('malformed revoked certStatus') if kids2.empty?

          txt = latin1(basic.byteslice(kids2[0][0].start, kids2[0][0].end_ - kids2[0][0].start))
          return fail_with('malformed revoked certStatus') unless txt.match?(/\A[0-9]{14}Z\z/)

          at = Time.utc(txt[0, 4].to_i, txt[4, 2].to_i, txt[6, 2].to_i, txt[8, 2].to_i, txt[10, 2].to_i, txt[12, 2].to_i).to_i * 1000
          out = { 'ok' => true, 'status' => 'revoked' }.merge(times, 'revokedAt' => at)
          if kids2.length > 1 && kids2[1][0].tag == 0xA0
            enum = children(basic, kids2[1][0])
            out['revocationReason'] = basic.byteslice(enum[0][0].start, enum[0][0].end_ - enum[0][0].start).unpack1('H*').to_i(16) if !enum.empty? && enum[0][0].tag == 0x0A
          end
          return out.merge('responder' => responder)
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
      # `require_good`: which non-root certificates MUST have a GOOD response: 'aia' (default: those advertising an OCSP URL), 'all', or an Array
      # of chain indices; `expected_nonces`: the nonce expected per chain index (nil = none for that certificate).
      def check_nvidia_chain_ocsp(chain, responses, now_ms, max_age_ms = nil, require_good: 'aia', clock_skew_ms: nil, expected_nonces: nil)
        return { 'ok' => false, 'reason' => 'chain too short for OCSP' } if chain.length < 2
        return { 'ok' => false, 'reason' => 'no OCSP responses supplied' } if responses.empty?

        last = chain.length - 1
        required = []
        policy = require_good.nil? ? 'aia' : require_good
        if policy.is_a?(Array)
          policy.each do |i|
            return { 'ok' => false, 'reason' => "requireGood index #{Common.js_str(i)} is not a non-root chain certificate" } unless Common.int?(i) && i >= 0 && i < last

            required << i.to_i
          end
          required.uniq!
        else
          (0...last).each { |i| required << i if policy == 'all' || !cert_ocsp_urls(chain[i]).empty? }
        end
        statuses = (0...last).to_h { |i| [i, 'absent'] }
        verified = 0
        responses.each_with_index do |der, ri|
          matched = false
          last_reason = 'matches no chain certificate'
          last.times do |i|
            nonce = expected_nonces.is_a?(Array) ? expected_nonces[i] : nil
            r = verify_ocsp_response(der, chain[i], chain[i + 1], chain, now_ms, max_age_ms, clock_skew_ms.nil? ? 0 : clock_skew_ms, nonce)
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
        required.each do |i|
          if statuses[i] != 'good'
            return { 'ok' => false, 'reason' => "no GOOD OCSP response for required certificate '#{subj(chain[i])}' (status: #{statuses[i]})", 'statuses' => statuses }
          end
        end
        { 'ok' => true, 'verifiedCrls' => 0, 'verifiedOcsp' => verified, 'statuses' => statuses }
      end
    end
  end
end
