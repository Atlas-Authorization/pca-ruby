# frozen_string_literal: true

# A minimal X.509 certificate model for the attestation chain verifiers.
#
# Parsing is done here (the vendor chains use RSASSA-PSS with an explicit DEFAULT `trailerField` that strict ASN.1 parsers
# reject and OpenSSL tolerates), so only the public-key and signature primitives come from OpenSSL. The behaviours the
# reference gets from node's OpenSSL-backed X509Certificate are reproduced: DN comparison through the OpenSSL text form,
# `X509_verify` (outer / inner algorithm must agree), `X509_check_ca == 1`, `X509_check_issued`.
require_relative 'common'
require_relative 'der'

module AtlasPca
  module Attest
    class Cert
      Tlv = Der::Tlv

      SIG_ALGS = {
        '1.2.840.10045.4.1' => %w[ec sha1], '1.2.840.10045.4.3.1' => %w[ec sha224], '1.2.840.10045.4.3.2' => %w[ec sha256],
        '1.2.840.10045.4.3.3' => %w[ec sha384], '1.2.840.10045.4.3.4' => %w[ec sha512],
        '1.2.840.113549.1.1.5' => %w[rsa sha1], '1.2.840.113549.1.1.14' => %w[rsa sha224], '1.2.840.113549.1.1.11' => %w[rsa sha256],
        '1.2.840.113549.1.1.12' => %w[rsa sha384], '1.2.840.113549.1.1.13' => %w[rsa sha512]
      }.freeze
      OID_PSS = '1.2.840.113549.1.1.10'
      OID_MGF1 = '1.2.840.113549.1.1.8'
      HASH_OIDS = {
        '1.3.14.3.2.26' => 'sha1', '2.16.840.1.101.3.4.2.4' => 'sha224', '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384', '2.16.840.1.101.3.4.2.3' => 'sha512'
      }.freeze

      SHORT_NAMES = {
        '2.5.4.3' => 'CN', '2.5.4.4' => 'SN', '2.5.4.5' => 'serialNumber', '2.5.4.6' => 'C', '2.5.4.7' => 'L', '2.5.4.8' => 'ST',
        '2.5.4.9' => 'street', '2.5.4.10' => 'O', '2.5.4.11' => 'OU', '2.5.4.12' => 'title', '2.5.4.13' => 'description',
        '2.5.4.15' => 'businessCategory', '2.5.4.17' => 'postalCode', '2.5.4.41' => 'name', '2.5.4.42' => 'GN',
        '2.5.4.43' => 'initials', '2.5.4.44' => 'generationQualifier', '2.5.4.46' => 'dnQualifier', '2.5.4.65' => 'pseudonym',
        '1.2.840.113549.1.9.1' => 'emailAddress', '0.9.2342.19200300.100.1.25' => 'DC', '0.9.2342.19200300.100.1.1' => 'UID',
        '1.3.6.1.4.1.311.60.2.1.1' => 'jurisdictionL', '1.3.6.1.4.1.311.60.2.1.2' => 'jurisdictionST',
        '1.3.6.1.4.1.311.60.2.1.3' => 'jurisdictionC'
      }.freeze

      # What node reports for a buffer that is neither DER nor PEM (it tries DER, then PEM, and surfaces the PEM error).
      NO_START_LINE = 'error:0480006C:PEM routines::no start line'

      class << self
        def escape(s)
          out = +''
          chars = s.chars
          chars.each_with_index do |ch, i|
            o = ch.ord
            out << if o < 0x20 || o == 0x7F then format('\\%02X', o)
                   elsif ',+"\\<>;'.include?(ch) then "\\#{ch}"
                   elsif i.zero? && '# '.include?(ch) then "\\#{ch}"
                   elsif i == chars.length - 1 && ch == ' ' then '\\ '
                   else ch
                   end
          end
          out
        end

        def name_value(der, off, t)
          raw = der.byteslice(t.start, t.end_ - t.start)
          case t.tag
          when 0x0C then escape(raw.dup.force_encoding('UTF-8').scrub("�"))
          when 0x13, 0x16, 0x1A, 0x12, 0x14 then escape(raw.dup.force_encoding('ISO-8859-1').encode('UTF-8'))
          when 0x1E then escape(raw.dup.force_encoding('UTF-16BE').encode('UTF-8', invalid: :replace, undef: :replace, replace: "�"))
          when 0x1C then escape(raw.dup.force_encoding('UTF-32BE').encode('UTF-8', invalid: :replace, undef: :replace, replace: "�"))
          else "##{der.byteslice(off, t.end_ - off).unpack1('H*').upcase}"
          end
        end

        # OpenSSL's multi-line text of a DN, as node prints `subject` / `issuer` (short names, one entry per line, ' + ' joins an RDN).
        def render_name(der)
          seq = Der.tlv_at(der, 0)
          raise CertError, 'name is not a SEQUENCE' if seq.tag != 0x30

          lines = []
          p = seq.start
          while p < seq.end_
            rdn = Der.tlv_at(der, p)
            p = rdn.end_
            raise CertError, 'RDN is not a SET' if rdn.tag != 0x31

            parts = []
            q = rdn.start
            while q < rdn.end_
              atv = Der.tlv_at(der, q)
              q = atv.end_
              oid_t = Der.tlv_at(der, atv.start)
              val_off = oid_t.end_
              val_t = Der.tlv_at(der, val_off)
              dotted = Der.oid_to_dotted(der, oid_t)
              parts << "#{SHORT_NAMES.fetch(dotted, dotted)}=#{name_value(der, val_off, val_t)}"
            end
            lines << parts.join(' + ')
          end
          lines.join("\n")
        end

        # A PEM block must hold exactly one DER certificate: bytes after it inside the block are refused.
        def from_pem(pem)
          der = Common.pem_to_der(pem)
          outer = Der.tlv_at(der, 0)
          raise CertError, 'error:0680007B:asn1 encoding routines::header too long' if outer.end_ != der.bytesize

          new(der)
        rescue ArgumentError, DerError
          raise CertError, NO_START_LINE
        end

        def alg_parts(alg_der)
          seq = Der.tlv_at(alg_der, 0)
          oid_t = Der.tlv_at(alg_der, seq.start)
          dotted = Der.oid_to_dotted(alg_der, oid_t)
          params = oid_t.end_ < seq.end_ ? Der.tlv_at(alg_der, oid_t.end_) : nil
          [dotted, params]
        end

        def hash_of_alg_id(der, t)
          raise CertError, 'hash algorithm is not a SEQUENCE' if t.tag != 0x30

          oid_t = Der.tlv_at(der, t.start)
          h = HASH_OIDS[Der.oid_to_dotted(der, oid_t)]
          raise CertError, 'unsupported hash algorithm' if h.nil?

          h
        end

        # RSASSA-PSS-params with its DEFAULTs (sha1, mgf1-sha1, 20, 1); an explicitly encoded default value is tolerated.
        def pss_params(alg_der, params)
          hash_name = mgf_hash = 'sha1'
          salt = 20
          return [hash_name, mgf_hash, salt] if params.nil? || params.tag != 0x30

          p = params.start
          while p < params.end_
            el = Der.tlv_at(alg_der, p)
            p = el.end_
            inner = el.start < el.end_ ? Der.tlv_at(alg_der, el.start) : nil
            raise CertError, 'empty PSS parameter' if inner.nil?

            case el.tag
            when 0xA0 then hash_name = hash_of_alg_id(alg_der, inner)
            when 0xA1
              raise CertError, 'mask generation function is not a SEQUENCE' if inner.tag != 0x30

              oid_t = Der.tlv_at(alg_der, inner.start)
              raise CertError, 'unsupported mask generation function' if Der.oid_to_dotted(alg_der, oid_t) != OID_MGF1

              mgf_hash = hash_of_alg_id(alg_der, Der.tlv_at(alg_der, oid_t.end_))
            when 0xA2
              raise CertError, 'salt length is not an INTEGER' if inner.tag != 0x02

              salt = alg_der.byteslice(inner.start, inner.end_ - inner.start).unpack1('H*').to_i(16)
            when 0xA3
              if inner.tag != 0x02 || alg_der.byteslice(inner.start, inner.end_ - inner.start).unpack1('H*').to_i(16) != 1
                raise CertError, 'trailer field is not 1'
              end
            else raise CertError, 'unknown PSS parameter'
            end
          end
          [hash_name, mgf_hash, salt]
        end

        def verify_signature(alg_der, msg, sig, key)
          dotted, params = alg_parts(alg_der)
          if SIG_ALGS.key?(dotted)
            kind, hname = SIG_ALGS[dotted]
            return kind == 'ec' ? Common.ecdsa_verify_der(key, sig, msg, hname) : Common.rsa_pkcs1_verify(key, sig, msg, hname)
          end
          if dotted == OID_PSS
            return false if Common.key_type(key) != 'rsa'

            hname, mgf_h, salt = pss_params(alg_der, params)
            begin
              return key.verify_pss(hname.upcase, sig.b, msg.b, salt_length: salt, mgf1_hash: mgf_h.upcase)
            rescue OpenSSL::OpenSSLError, ArgumentError, TypeError
              return false
            end
          end
          false
        end

        # Public entry used by the CRL / OCSP code for an AlgorithmIdentifier.
        def verify_with_alg(alg_der, msg, sig, key)
          verify_signature(alg_der, msg, sig, key)
        rescue StandardError
          false
        end
      end

      attr_reader :raw, :tbs_der, :sig_alg_der, :sig_unused, :signature, :serial, :inner_sig_alg_der, :issuer_der, :subject_der, :spki_der

      # A parsed X.509 certificate (DER). Construction raises CertError / DerError on a structural problem.
      def initialize(der)
        der = der.b
        begin
          outer = Der.tlv_at(der, 0)
          raise CertError, NO_START_LINE if outer.tag != 0x30

          @raw = der.byteslice(0, outer.end_)
          tbs = Der.tlv_at(@raw, outer.start)
          raise CertError, NO_START_LINE if tbs.tag != 0x30

          alg = Der.tlv_at(@raw, tbs.end_)
          sigv = Der.tlv_at(@raw, alg.end_)
          if alg.tag != 0x30 || sigv.tag != 0x03 || sigv.end_ != outer.end_ || sigv.end_ - sigv.start < 1
            raise CertError, NO_START_LINE
          end

          @tbs_der = @raw.byteslice(outer.start, tbs.end_ - outer.start)
          @sig_alg_der = @raw.byteslice(tbs.end_, alg.end_ - tbs.end_)
          @sig_unused = @raw.getbyte(sigv.start)
          @signature = @raw.byteslice(sigv.start + 1, sigv.end_ - sigv.start - 1)
          off = tbs.start
          el = Der.tlv_at(@raw, off)
          if el.tag == 0xA0
            off = el.end_
            el = Der.tlv_at(@raw, off)
          end
          raise CertError, NO_START_LINE if el.tag != 0x02

          @serial = @raw.byteslice(el.start, el.end_ - el.start)
          off = el.end_
          inner = Der.tlv_at(@raw, off)
          raise CertError, NO_START_LINE if inner.tag != 0x30

          @inner_sig_alg_der = @raw.byteslice(off, inner.end_ - off)
          off = inner.end_
          iss = Der.tlv_at(@raw, off)
          raise CertError, NO_START_LINE if iss.tag != 0x30

          @issuer_der = @raw.byteslice(off, iss.end_ - off)
          off = iss.end_
          val = Der.tlv_at(@raw, off)
          raise CertError, NO_START_LINE if val.tag != 0x30

          off = val.end_
          sub = Der.tlv_at(@raw, off)
          raise CertError, NO_START_LINE if sub.tag != 0x30

          @subject_der = @raw.byteslice(off, sub.end_ - off)
          off = sub.end_
          spki = Der.tlv_at(@raw, off)
          raise CertError, NO_START_LINE if spki.tag != 0x30

          @spki_der = @raw.byteslice(off, spki.end_ - off)
          # SubjectPublicKeyInfo is exactly {algorithm SEQUENCE, subjectPublicKey BIT STRING}: bytes after the key are refused
          # while the certificate is read (OpenSSL's d2i does the same)
          spki_alg = Der.tlv_at(@raw, spki.start)
          spki_bits = spki_alg.end_ < spki.end_ ? Der.tlv_at(@raw, spki_alg.end_) : nil
          if spki_alg.tag != 0x30 || spki_bits.nil? || spki_bits.tag != 0x03 || spki_bits.end_ != spki.end_
            raise CertError, 'error:0680009F:asn1 encoding routines::unexpected eoc'
          end
          # after the key only the optional [1] issuerUID, [2] subjectUID and [3] extensions may follow
          rest = spki.end_
          while rest < tbs.end_
            tail = Der.tlv_at(@raw, rest)
            raise CertError, 'error:0680009F:asn1 encoding routines::unexpected eoc' if ![0xA1, 0xA2, 0xA3].include?(tail.tag) || tail.end_ > tbs.end_

            rest = tail.end_
          end
        rescue DerError => e
          raise CertError, NO_START_LINE
        end
        @key = nil
        @subject = nil
        @issuer = nil
        @exts = nil
        @exts_failed = false
      end

      def subject = (@subject ||= self.class.render_name(@subject_der))
      def issuer = (@issuer ||= self.class.render_name(@issuer_der))

      # Lowercase hex of the serial number without leading zeros (the form the CRL logic compares).
      def serial_hex = @serial.unpack1('H*').sub(/\A0+/, '')

      def public_key
        @key ||= begin
          Common.load_public_key(@spki_der)
        rescue StandardError => e
          raise CertError, "error:1E08010C:DECODER routines::unsupported (#{e.message})"
        end
      end

      def spki_sha256 = spki_sha('sha256')

      # Hex digest of the certificate's own SubjectPublicKeyInfo bytes (an RSA-PSS key keeps its algorithm identifier).
      def spki_sha(algo) = OpenSSL::Digest.new(algo.upcase).hexdigest(@spki_der)

      def extensions
        if @exts.nil? && !@exts_failed
          begin
            @exts = Der.parse_tbs_extensions(@tbs_der)
          rescue DerError
            @exts_failed = true
          end
        end
        @exts || {}
      end

      # nil when keyUsage is absent, else whether keyCertSign is asserted.
      def key_cert_sign
        e = extensions['2.5.29.15']
        return nil if e.nil?

        begin
          bs = Der.read_tlv(e.value, 0)
        rescue DerError
          return nil
        end
        return false if bs.tag != 0x03 || bs.end_ - bs.start < 2

        e.value.getbyte(bs.start + 1).anybits?(0x04)
      end

      # node's `ca` (X509_check_ca() == 1): BasicConstraints cA true, and keyUsage (when present) allows certificate signing.
      def ca
        return false if key_cert_sign == false

        e = extensions['2.5.29.19']
        return false if e.nil?

        begin
          seq = Der.read_tlv(e.value, 0)
          return false if seq.tag != 0x30 || seq.start == seq.end_

          first = Der.read_tlv(e.value, seq.start, seq.end_)
          first.tag == 0x01 && first.end_ - first.start >= 1 && e.value.getbyte(first.start) != 0
        rescue DerError
          false
        end
      end

      # X509_check_issued: the DN link, a matching authority key identifier, and keyCertSign on the issuer.
      def check_issued(issuer_cert)
        return false if issuer != issuer_cert.subject

        akid = extensions['2.5.29.35']
        skid = issuer_cert.extensions['2.5.29.14']
        if !akid.nil? && !skid.nil?
          begin
            seq = Der.read_tlv(akid.value, 0)
            if seq.tag == 0x30 && seq.start < seq.end_
              k = Der.read_tlv(akid.value, seq.start, seq.end_)
              if k.tag == 0x80
                sk = Der.read_tlv(skid.value, 0)
                if sk.tag == 0x04 && akid.value.byteslice(k.start, k.end_ - k.start) != skid.value.byteslice(sk.start, sk.end_ - sk.start)
                  return false
                end
              end
            end
          rescue DerError
            return false
          end
        end
        issuer_cert.key_cert_sign != false
      end

      # X509_verify: the outer and inner signature algorithms must agree, then the signature over the TBS.
      def verify(key)
        return false if @sig_alg_der != @inner_sig_alg_der || @sig_unused != 0

        self.class.verify_signature(@sig_alg_der, @tbs_der, @signature, key)
      rescue StandardError
        false
      end

      def verify_self = verify(public_key)
    end
  end
end
