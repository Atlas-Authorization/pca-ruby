# frozen_string_literal: true

# Strict DER / X.509 readers shared by the hardware-attestation chain verifiers.
#
# Native counterpart of the strict X.509 helpers of @atlasauth/pca (x509-strict, x509-validity): every function raises or
# returns exactly what the reference does, including the exact error text (it is part of the conformance vectors).
# Pure stdlib; nothing here needs OpenSSL.
require_relative 'common'

module AtlasPca
  module Attest
    module Der
      # One TLV: tag, content start, content end (exclusive).
      Tlv = Struct.new(:tag, :start, :end_)
      # An extension: critical flag and the extnValue OCTET STRING content.
      CertExtension = Struct.new(:critical, :value)

      OID_BASIC_CONSTRAINTS = [0x55, 0x1D, 0x13].pack('C*').freeze
      OID_KEY_USAGE = [0x55, 0x1D, 0x0F].pack('C*').freeze
      RECOGNISED_CRITICAL_EXTENSIONS = %w[2.5.29.19 2.5.29.15].freeze
      # What the JWS / SPDM chain verifiers process or can safely ignore: the above and ExtendedKeyUsage.
      CHAIN_CRITICAL_OK = (RECOGNISED_CRITICAL_EXTENSIONS + %w[2.5.29.37]).freeze

      module_function

      # One strict DER TLV at `off` inside [0, limit): no multi-byte tags, definite minimal lengths up to 3 length bytes.
      def read_tlv(b, off, limit = nil)
        limit ||= b.bytesize
        raise DerError, 'DER: truncated header' if off + 2 > limit

        tag = b.getbyte(off)
        raise DerError, 'DER: multi-byte tags are not supported' if (tag & 0x1F) == 0x1F

        ln = b.getbyte(off + 1)
        p = off + 2
        if ln.anybits?(0x80)
          n = ln & 0x7F
          raise DerError, 'DER: unsupported length form' if n.zero? || n > 3
          raise DerError, 'DER: truncated length' if p + n > limit

          ln = 0
          raise DerError, 'DER: non-minimal length (leading zero)' if n > 1 && b.getbyte(p).zero?

          n.times { |i| ln = (ln << 8) | b.getbyte(p + i) }
          raise DerError, 'DER: non-minimal length (long form below 128)' if ln < 0x80

          p += n
        end
        raise DerError, 'DER: element overruns its parent' if p + ln > limit

        Tlv.new(tag, p, p + ln)
      end

      def oid_equals?(b, t, want) = t.tag == 0x06 && b.byteslice(t.start, t.end_ - t.start) == want

      # The CA-role-relevant extensions of a DER certificate (hasBasicConstraints, ca, pathLen?, hasKeyUsage, keyCertSign).
      def read_cert_role_info(cert_der)
        outer = read_tlv(cert_der, 0)
        raise DerError, 'certificate is not a DER SEQUENCE' if outer.tag != 0x30
        raise DerError, 'trailing bytes after the certificate' if outer.end_ != cert_der.bytesize

        tbs = read_tlv(cert_der, outer.start, outer.end_)
        raise DerError, 'certificate has no tbsCertificate' if tbs.tag != 0x30

        info = { 'hasBasicConstraints' => false, 'ca' => false, 'hasKeyUsage' => false, 'keyCertSign' => false }
        p = tbs.start
        while p < tbs.end_
          el = read_tlv(cert_der, p, tbs.end_)
          p = el.end_
          next if el.tag != 0xA3 # [3] EXPLICIT extensions

          seq = read_tlv(cert_der, el.start, el.end_)
          raise DerError, 'extensions is not a SEQUENCE' if seq.tag != 0x30

          q = seq.start
          while q < seq.end_
            ext = read_tlv(cert_der, q, seq.end_)
            q = ext.end_
            raise DerError, 'extension is not a SEQUENCE' if ext.tag != 0x30

            ident = read_tlv(cert_der, ext.start, ext.end_)
            r = ident.end_
            nxt = read_tlv(cert_der, r, ext.end_)
            if nxt.tag == 0x01
              r = nxt.end_
              nxt = read_tlv(cert_der, r, ext.end_)
            end
            raise DerError, 'extension value is not an OCTET STRING' if nxt.tag != 0x04

            if oid_equals?(cert_der, ident, OID_BASIC_CONSTRAINTS)
              raise DerError, 'duplicate BasicConstraints extension' if info['hasBasicConstraints']

              info['hasBasicConstraints'] = true
              bc = read_tlv(cert_der, nxt.start, nxt.end_)
              raise DerError, 'BasicConstraints is not a SEQUENCE' if bc.tag != 0x30

              c = bc.start
              if c < bc.end_
                first = read_tlv(cert_der, c, bc.end_)
                if first.tag == 0x01
                  raise DerError, 'BasicConstraints cA is not one byte' if first.end_ - first.start != 1

                  info['ca'] = cert_der.getbyte(first.start) != 0
                  c = first.end_
                end
              end
              if c < bc.end_
                pl = read_tlv(cert_der, c, bc.end_)
                if pl.tag != 0x02 || pl.end_ - pl.start < 1 || pl.end_ - pl.start > 2 || cert_der.getbyte(pl.start).anybits?(0x80)
                  raise DerError, 'BasicConstraints pathLenConstraint malformed'
                end

                n = 0
                (pl.start...pl.end_).each { |i| n = (n << 8) | cert_der.getbyte(i) }
                info['pathLen'] = n
                c = pl.end_
              end
              raise DerError, 'BasicConstraints has trailing data' if c != bc.end_
            elsif oid_equals?(cert_der, ident, OID_KEY_USAGE)
              raise DerError, 'duplicate keyUsage extension' if info['hasKeyUsage']

              info['hasKeyUsage'] = true
              bs = read_tlv(cert_der, nxt.start, nxt.end_)
              raise DerError, 'keyUsage is not a BIT STRING' if bs.tag != 0x03 || bs.end_ - bs.start < 2
              raise DerError, 'keyUsage BIT STRING has more than 7 unused bits' if cert_der.getbyte(bs.start) > 7

              info['keyCertSign'] = cert_der.getbyte(bs.start + 1).anybits?(0x04)
            end
          end
        end
        info
      end

      def oid_to_dotted(b, t)
        raise DerError, 'extension OID is malformed' if t.tag != 0x06 || t.end_ <= t.start

        arcs = []
        v = 0
        is_open = false
        (t.start...t.end_).each do |i|
          byte = b.getbyte(i)
          raise DerError, 'extension OID has a non-minimal arc' if !is_open && byte == 0x80

          v = (v << 7) | (byte & 0x7F)
          is_open = byte.anybits?(0x80)
          unless is_open
            arcs << v
            v = 0
          end
        end
        raise DerError, 'extension OID is truncated' if is_open

        first = arcs[0]
        head = if first < 40 then [0, first]
               elsif first < 80 then [1, first - 40]
               else [2, first - 80]
               end
        (head + arcs[1..]).join('.')
      end

      # STRICT extension table of a tbsCertificate (the SEQUENCE INCLUDING its header), keyed by dotted OID (insertion order).
      # DER INTEGER content as OpenSSL's reader takes it: not empty, no redundant leading 00 or FF.
      def minimal_integer?(b)
        return false if b.empty?
        return true if b.bytesize == 1

        hi = b.getbyte(0)
        top = b.getbyte(1) & 0x80
        !(hi.zero? && top.zero?) && !(hi == 0xFF && top != 0)
      end

      # The TLVs directly inside `el`.
      def children_of(der, el)
        out = []
        p = el.start
        while p < el.end_
          out << read_tlv(der, p, el.end_)
          p = out.last.end_
        end
        out
      end

      NAME_STRING_TAGS = [0x0C, 0x13, 0x14, 0x16].freeze

      # `kids` carry only `tags`, each at most once and in that order.
      def in_order!(kids, tags)
        rest = tags
        kids.each do |k|
          rest = rest.drop_while { |tag| tag != k.tag }
          raise DerError, 'member out of order or of no allowed type' if rest.empty?

          rest = rest.drop(1)
        end
      end

      # The AttributeTypeAndValues of an RDN. Refused beyond OpenSSL: value types other than UTF8, Printable, T61 and IA5.
      def rdn!(b, el)
        children_of(b, el).each do |atv|
          parts = atv.tag == 0x30 ? children_of(b, atv) : []
          raise DerError, 'attribute is not {type, value}' if parts.length != 2

          oid_to_dotted(b, parts[0])
          value = parts[1]
          raise DerError, 'attribute value type' unless NAME_STRING_TAGS.include?(value.tag)
          next unless value.tag == 0x0C
          raise DerError, 'attribute value is not UTF-8' unless b.byteslice(value.start, value.end_ - value.start).force_encoding('UTF-8').valid_encoding?
        end
      end

      # A GeneralName. Refused beyond OpenSSL: x400Address, ediPartyName, registeredID and the undefined constructed tags.
      def general_name!(b, n)
        case n.tag
        when 0x81, 0x82, 0x86, 0x87 then nil
        when 0xA0
          kids = children_of(b, n)
          raise DerError, 'otherName is not {type, [0] value}' if kids.length != 2 || kids[1].tag != 0xA0 || children_of(b, kids[1]).length != 1

          oid_to_dotted(b, kids[0])
        when 0xA4
          name = read_tlv(b, n.start, n.end_)
          raise DerError, 'directoryName is not one Name' if name.tag != 0x30 || name.end_ != n.end_

          children_of(b, name).each do |rdn|
            raise DerError, 'Name member is not an RDN' if rdn.tag != 0x31

            rdn!(b, rdn)
          end
        else raise DerError, 'not a supported GeneralName'
        end
      end

      def general_names!(b, el) = children_of(b, el).each { |n| general_name!(b, n) }

      def bit_string_content!(b, el)
        raise DerError, 'BIT STRING is malformed' if el.end_ == el.start || b.getbyte(el.start) > 7
      end

      def top_sequence(v)
        seq = read_tlv(v, 0)
        raise DerError, 'extension is not a SEQUENCE' if seq.tag != 0x30

        children_of(v, seq)
      end

      def positive_integer!(b, el)
        c = b.byteslice(el.start, el.end_ - el.start)
        raise DerError, 'not a positive DER INTEGER' if !minimal_integer?(c) || c.getbyte(0) > 0x7F
      end

      def basic_constraints!(v)
        kids = top_sequence(v)
        in_order!(kids, [0x01, 0x02])
        kids.each do |k|
          k.tag == 0x02 ? positive_integer!(v, k) : (raise DerError, 'cA is not one byte' if k.end_ - k.start != 1)
        end
      end

      def key_usage!(v)
        bits = read_tlv(v, 0)
        raise DerError, 'keyUsage is not a BIT STRING' if bits.tag != 0x03

        bit_string_content!(v, bits)
        raise DerError, 'keyUsage has no bits' if bits.end_ - bits.start < 2
      end

      def name_constraints!(v)
        kids = top_sequence(v)
        in_order!(kids, [0xA0, 0xA1])
        kids.each do |list|
          children_of(v, list).each do |sub|
            parts = sub.tag == 0x30 ? children_of(v, sub) : []
            raise DerError, 'GeneralSubtree has no base' if parts.empty?

            general_name!(v, parts[0])
            in_order!(parts[1..], [0x80, 0x81])
            parts[1..].each { |x| positive_integer!(v, x) }
          end
        end
      end

      def distribution_points!(v)
        top_sequence(v).each do |dp|
          raise DerError, 'DistributionPoint is not a SEQUENCE' if dp.tag != 0x30

          kids = children_of(v, dp)
          in_order!(kids, [0xA0, 0x81, 0xA2])
          # As Node reads it: reasons alone, nothing at all, or an empty cRLIssuer does not decode.
          raise DerError, 'DistributionPoint has no name or issuer' if kids.none? { |k| k.tag != 0x81 }

          kids.each do |k|
            case k.tag
            when 0x81 then bit_string_content!(v, k)
            when 0xA2
              raise DerError, 'cRLIssuer is empty' if k.end_ == k.start

              general_names!(v, k)
            else
              inner = children_of(v, k)
              raise DerError, 'distributionPoint is not one name' if inner.length != 1

              case inner[0].tag
              when 0xA0 then general_names!(v, inner[0])
              when 0xA1 then rdn!(v, inner[0])
              else raise DerError, 'distributionPoint is not a name'
              end
            end
          end
        end
      end

      # What ossl_x509v3_cache_extensions decodes: one that fails makes X509_check_issued refuse. A proxyCertInfo is refused outright.
      def cached_extension!(oid, v)
        case oid
        when '2.5.29.19' then basic_constraints!(v)
        when '2.5.29.15' then key_usage!(v)
        when '2.5.29.37' then top_sequence(v).each { |o| oid_to_dotted(v, o) }
        when '2.5.29.17' then top_sequence(v).each { |n| general_name!(v, n) }
        when '2.5.29.30' then name_constraints!(v)
        when '2.5.29.31' then distribution_points!(v)
        when '1.3.6.1.5.5.7.1.14' then raise DerError, 'proxyCertInfo is not supported'
        end
      end

      def parse_tbs_extensions(tbs_der)
        tbs = read_tlv(tbs_der, 0)
        raise DerError, 'tbsCertificate is not a SEQUENCE' if tbs.tag != 0x30
        raise DerError, 'trailing bytes after tbsCertificate' if tbs.end_ != tbs_der.bytesize

        out = {}
        seen = false
        block_end = -1
        p = tbs.start
        while p < tbs.end_
          el = read_tlv(tbs_der, p, tbs.end_)
          p = el.end_
          next if el.tag != 0xA3
          raise DerError, 'duplicate [3] extensions block' if seen

          seen = true
          block_end = el.end_
          seq = read_tlv(tbs_der, el.start, el.end_)
          raise DerError, 'extensions is not a SEQUENCE' if seq.tag != 0x30
          raise DerError, 'trailing bytes after the Extensions SEQUENCE' if seq.end_ != el.end_
          raise DerError, 'empty Extensions SEQUENCE' if seq.start == seq.end_

          q = seq.start
          while q < seq.end_
            ext = read_tlv(tbs_der, q, seq.end_)
            q = ext.end_
            raise DerError, 'extension is not a SEQUENCE' if ext.tag != 0x30

            ident = read_tlv(tbs_der, ext.start, ext.end_)
            dotted = oid_to_dotted(tbs_der, ident)
            r = ident.end_
            nxt = read_tlv(tbs_der, r, ext.end_)
            critical = false
            if nxt.tag == 0x01
              if nxt.end_ - nxt.start != 1 || tbs_der.getbyte(nxt.start) != 0xFF
                raise DerError, "extension #{dotted} has a non-DER critical flag"
              end

              critical = true
              r = nxt.end_
              nxt = read_tlv(tbs_der, r, ext.end_)
            end
            raise DerError, "extension #{dotted} value is not an OCTET STRING" if nxt.tag != 0x04
            raise DerError, "extension #{dotted} has trailing bytes" if nxt.end_ != ext.end_
            raise DerError, "duplicate extension #{dotted}" if out.key?(dotted)

            out[dotted] = CertExtension.new(critical, tbs_der.byteslice(nxt.start, nxt.end_ - nxt.start))
          end
        end
        raise DerError, 'extensions block is not the last TBS element' if seen && block_end != tbs.end_

        out
      end

      # The tbsCertificate bytes (header included) of a DER certificate; rejects trailing bytes after the certificate.
      def tbs_of_certificate(cert_der)
        outer = read_tlv(cert_der, 0)
        raise DerError, 'certificate is not a DER SEQUENCE' if outer.tag != 0x30
        raise DerError, 'trailing bytes after the certificate' if outer.end_ != cert_der.bytesize

        tbs = read_tlv(cert_der, outer.start, outer.end_)
        raise DerError, 'certificate has no tbsCertificate' if tbs.tag != 0x30

        cert_der.byteslice(outer.start, tbs.end_ - outer.start)
      end

      def parse_cert_extensions(cert_der) = parse_tbs_extensions(tbs_of_certificate(cert_der))

      # RFC 5280 4.2: the first critical extension this verifier does not understand, else nil. Raises on a malformed table.
      def unrecognised_critical_extension(cert_der, recognised = nil)
        ok = recognised.nil? ? RECOGNISED_CRITICAL_EXTENSIONS : recognised
        parse_cert_extensions(cert_der).each { |oid, e| return oid if e.critical && !ok.include?(oid) }
        nil
      end

      # CA roles over an ordered chain (index 0 = leaf ... last = self-signed root). A failure reason or nil.
      def check_chain_roles(ordered_der)
        n = ordered_der.length
        n.times do |i|
          info = read_cert_role_info(ordered_der[i])
          if i.zero? && n > 1
            return 'leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)' if info['ca']

            next
          end
          next if i.zero?
          return "issuer certificate at depth #{i} has no BasicConstraints (not a CA)" unless info['hasBasicConstraints']
          return "issuer certificate at depth #{i} is not a CA (BasicConstraints CA:FALSE)" unless info['ca']
          return "issuer certificate at depth #{i} keyUsage lacks keyCertSign" if info['hasKeyUsage'] && !info['keyCertSign']

          pl = info['pathLen']
          if !pl.nil? && pl < i - 1
            return "issuer certificate at depth #{i} pathLenConstraint #{pl} is exceeded (#{i - 1} intermediate(s) below)"
          end
        end
        nil
      rescue DerError => e
        "certificate extension parse failed: #{e.message}"
      end

      # The shared profile of the MAA x5c, GCP x5c and NVIDIA device chains (x509-strict.ts strictChainError): CA roles over the
      # ordered chain, then no unrecognised critical extension on any certificate. A failure reason or nil.
      def strict_chain_error(ordered_der)
        roles = check_chain_roles(ordered_der)
        return roles if roles

        ordered_der.each_with_index do |der, i|
          oid = unrecognised_critical_extension(der, CHAIN_CRITICAL_OK)
          return "certificate at depth #{i} has an unrecognised critical extension #{oid}" if oid
        end
        nil
      rescue StandardError => e
        "certificate extension parse failed: #{e.message}"
      end

      # ---- validity (x509-validity)

      def tlv_at(der, off)
        raise DerError, 'truncated' if off + 2 > der.bytesize

        tag = der.getbyte(off)
        ln = der.getbyte(off + 1)
        start = off + 2
        if ln.anybits?(0x80)
          n = ln & 0x7F
          raise DerError, 'bad length' if n.zero? || n > 4 || start + n > der.bytesize

          ln = 0
          n.times { |i| ln = (ln * 256) + der.getbyte(start + i) }
          start += n
        end
        end_ = start + ln
        raise DerError, 'truncated' if end_ > der.bytesize

        Tlv.new(tag, start, end_)
      end

      def digits?(s) = !s.empty? && s.match?(/\A[0-9]+\z/)

      # Days since 1970-01-01 of the proleptic Gregorian date (any year, including 0 and negatives).
      def days_from_civil(y, m, d)
        y -= 1 if m <= 2
        era = y.div(400)
        yoe = y - (era * 400)
        doy = (((153 * (m + (m > 2 ? -3 : 9))) + 2) / 5) + d - 1
        doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy
        (era * 146_097) + doe - 719_468
      end

      def days_in_month(y, m)
        return ((y % 4).zero? && !(y % 100).zero?) || (y % 400).zero? ? 29 : 28 if m == 2

        [4, 6, 9, 11].include?(m) ? 30 : 31
      end

      # Strict RFC 5280 Time (UTCTime 0x17 / GeneralizedTime 0x18) to epoch ms; nil for anything else (fail closed).
      def parse_der_time(tag, text)
        if tag == 0x17 && text.length == 13
          return nil unless digits?(text[0, 2])

          yy = text[0, 2].to_i
          y = yy >= 50 ? 1900 + yy : 2000 + yy
          rest = text[2..]
        elsif tag == 0x18 && text.length == 15
          return nil unless digits?(text[0, 4])

          y = text[0, 4].to_i
          rest = text[4..]
        else
          return nil
        end
        return nil if rest[10] != 'Z' || !digits?(text[0, text.length - 1])

        mon = rest[0, 2].to_i
        day = rest[2, 2].to_i
        h = rest[4, 2].to_i
        mi = rest[6, 2].to_i
        sec = rest[8, 2].to_i
        return nil if mon < 1 || mon > 12 || day < 1 || h > 23 || mi > 59 || sec > 59
        return nil if day > days_in_month(y, mon) # Feb 30, Apr 31, ...

        ((((days_from_civil(y, mon, day) * 24) + h) * 60) + mi) * 60_000 + (sec * 1000)
      end

      # The validity instants (epoch ms) of a DER certificate; nil members when malformed.
      def der_validity_ms(der)
        cert = tlv_at(der, 0)
        raise DerError, 'not a SEQUENCE' if cert.tag != 0x30

        tbs = tlv_at(der, cert.start)
        raise DerError, 'not a SEQUENCE' if tbs.tag != 0x30

        off = tbs.start
        el = tlv_at(der, off)
        if el.tag == 0xA0
          off = el.end_
          el = tlv_at(der, off)
        end
        raise DerError, 'serial' if el.tag != 0x02

        off = el.end_
        el = tlv_at(der, off)
        raise DerError, 'signature' if el.tag != 0x30

        off = el.end_
        el = tlv_at(der, off)
        raise DerError, 'issuer' if el.tag != 0x30

        validity = tlv_at(der, el.end_)
        raise DerError, 'validity' if validity.tag != 0x30 || validity.end_ > tbs.end_

        nb = tlv_at(der, validity.start)
        na = tlv_at(der, nb.end_)
        raise DerError, 'validity has extra fields' if na.end_ != validity.end_

        text = ->(t) { der.byteslice(t.start, t.end_ - t.start).force_encoding(Encoding::ISO_8859_1).encode('UTF-8') }
        [parse_der_time(nb.tag, text.call(nb)), parse_der_time(na.tag, text.call(na))]
      rescue DerError
        [nil, nil]
      end

      # True iff both bounds parse and `from - skew <= now <= to + skew`; false (fail closed) for any unparseable bound.
      def x509_valid_at?(der, now_ms, skew_ms = 0)
        lo, hi = der_validity_ms(der)
        return false if lo.nil? || hi.nil?

        now_ms + skew_ms >= lo && now_ms - skew_ms <= hi
      end
    end
  end
end
