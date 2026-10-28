# frozen_string_literal: true

# Offline Sigstore bundle verification for build provenance (track K9): a port of
# packages/pca-attest-eat/src/sigstore.ts.
#
#   require 'atlas_pca/sigstore_bundle'
#   roots = AtlasPca.parse_trusted_root(JSON.parse(File.read('trusted_root.json')))
#   r = AtlasPca.verify_sigstore_bundle(JSON.parse(bundle_json), roots)  # { ok: true, facts: } | { ok: false, code:, detail: }
#   AtlasPca.provenance_gate({ 'facts' => r[:facts], 'policy' => ... }) if r[:ok]
#
# Verifies a Sigstore bundle (v0.2 / v0.3) carrying a DSSE in-toto Statement against a pinned trusted_root.json, with no
# network access. Same order and refusal codes as the reference: RFC 3161 timestamps and the Rekor v1 SET first, then the
# Rekor entry (v1 dsse 0.0.1 / intoto 0.0.2, v2 hashedrekord 0.0.2), RFC 9162 inclusion and the signed-note checkpoint,
# the Fulcio path at every verified time, the embedded SCT, the entry body, the DSSE signature, identity and the Statement.
# Never raises on a bundle.
#
# A port rather than the sigstore gem: sigstore-ruby 0.2.3 has no Rekor v2 (hashedrekord 0.0.2, Ed25519 checkpoints),
# requires exactly one Rekor key in the trusted root (the public-good and staging roots pin several), takes the
# integratedTime as a signing time without a verified SET, and skips a missing inclusion proof offline. Needs only OpenSSL
# (stdlib).
require 'json'
require 'openssl'
require 'uri'
require_relative '../atlas_pca'
require_relative 'attest/common'
require_relative 'attest/der'
require_relative 'attest/cert'

module AtlasPca
  module SigstoreBundle
    module_function

    Cert = Attest::Cert
    Common = Attest::Common
    Der = Attest::Der

    MEDIA_TYPES = ['application/vnd.dev.sigstore.bundle+json;version=0.2', 'application/vnd.dev.sigstore.bundle+json;version=0.3',
                   'application/vnd.dev.sigstore.bundle.v0.3+json'].freeze
    INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json'
    OID_FULCIO = '1.3.6.1.4.1.57264.1.'
    OID_SCT_LIST = '1.3.6.1.4.1.11129.2.4.2'
    OID_SAN = '2.5.29.17'
    OID_EKU = '2.5.29.37'
    EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3'
    EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8'
    OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
    OID_TST_INFO = '1.2.840.113549.1.9.16.1.4'
    OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
    OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
    DIGEST_OIDS = { '2.16.840.1.101.3.4.2.1' => 'sha256', '2.16.840.1.101.3.4.2.2' => 'sha384',
                    '2.16.840.1.101.3.4.2.3' => 'sha512' }.freeze
    INF = Float::INFINITY

    class Fail < StandardError; end

    Validity = Struct.new(:start, :end_)
    # v2_name: a Rekor v2 log (Ed25519, signed-note checkpoints) carries its note name, the host of its base URL.
    PinnedLog = Struct.new(:key_id, :key, :valid, :v2_name)
    PinnedCa = Struct.new(:chain, :valid)
    PinnedRoots = Struct.new(:tlogs, :ctlogs, :cas, :tsas)
    Tlv = Struct.new(:tag, :start, :body, :end_)
    Ext = Struct.new(:oid, :value, :tlv)
    ParsedCert = Struct.new(:der, :tbs_kids, :exts_wrapper, :exts)

    def obj?(v) = v.is_a?(Hash)
    def get(v, k) = v.is_a?(Hash) ? v[k] : nil

    def b64(s)
      raise Fail, 'not base64' unless s.is_a?(String) && s.match?(%r{\A[A-Za-z0-9+/]*={0,2}\z}) && (s.length % 4).zero?

      s.unpack1('m')
    rescue ArgumentError
      raise Fail, 'not base64'
    end

    def date_ms(s)
      m = /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})\z/.match(s)
      return nil unless m

      y, mo, d, h, mi, se = (1..6).map { |i| m[i].to_i }
      return nil if mo < 1 || mo > 12 || d < 1 || d > Der.days_in_month(y, mo) || h > 23 || mi > 59 || se > 59

      off = m[8] == 'Z' ? 0 : (m[8][0] == '-' ? -1 : 1) * ((m[8][1, 2].to_i * 60) + m[8][4, 2].to_i) * 60_000
      ((((Der.days_from_civil(y, mo, d) * 24) + h) * 60 + mi) * 60_000) + (se * 1000) + (m[7] || '0')[0, 3].ljust(3, '0').to_i - off
    end

    def validity(v)
      s = obj?(v) && v['start'].is_a?(String) ? date_ms(v['start']) : nil
      raise Fail, 'validFor.start missing' if s.nil?

      e = INF
      if obj?(v) && v['end'].is_a?(String)
        e = date_ms(v['end'])
        raise Fail, 'validFor.end malformed' if e.nil?
      end
      Validity.new(s, e)
    end

    def sha256(*parts) = OpenSSL::Digest::SHA256.digest(parts.map(&:b).join)

    def der(tag, content)
      n = content.bytesize
      len = if n < 0x80 then [n]
            elsif n < 0x100 then [0x81, n]
            elsif n < 0x10000 then [0x82, n >> 8, n & 0xff]
            else [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff]
            end
      [tag, *len].pack('C*') + content.b
    end

    RSA_ALG_ID = ['300d06092a864886f70d0101010500'].pack('H*').freeze

    # A log key: ECDSA P-256 (id = SHA-256(SPKI)), PKCS#1 RSA (CT only), Ed25519 (Rekor v2, id = signed-note key hash).
    def pinned_log(t, transparency)
      raise Fail, 'log entry malformed' unless obj?(t) && obj?(t['publicKey']) && obj?(t['logId'])

      pk = t['publicKey']
      d = b64(pk['rawBytes'])
      key_id = b64(t['logId']['keyId'])
      valid = validity(pk['validFor'])
      case pk['keyDetails']
      when 'PKIX_ECDSA_P256_SHA_256'
        raise Fail, 'log id is not the SHA-256 of its key' if sha256(d) != key_id

        PinnedLog.new(key_id, Common.load_public_key(d), valid, nil)
      when 'PKCS1_RSA_PKCS1V5'
        return nil if transparency

        spki = der(0x30, RSA_ALG_ID + der(0x03, "\x00".b + d))
        key = OpenSSL::PKey.read(spki)
        raise Fail, 'log id is not the SHA-256 of its key' if sha256(spki) != key_id

        PinnedLog.new(key_id, key, valid, nil)
      when 'PKIX_ED25519'
        return nil unless transparency

        key = OpenSSL::PKey.read(d)
        name = t['baseUrl'].is_a?(String) ? URI.parse(t['baseUrl']).host.to_s.downcase : ''
        if name.empty? || sha256("#{name}\n", "\x01", d.byteslice(-32, 32)) != key_id
          raise Fail, 'log id is not the signed-note key hash of its key'
        end

        PinnedLog.new(key_id, key, valid, name)
      end
    end

    def pinned_chain(c)
      certs = get(get(c, 'certChain'), 'certificates')
      raise Fail, 'certificate authority entry malformed' unless certs.is_a?(Array) && !certs.empty?

      PinnedCa.new(certs.map { |x| Cert.new(b64(get(x, 'rawBytes'))) }, validity(c['validFor']))
    end

    # Parse a Sigstore trusted_root.json (v0.1, a String-keyed Hash). Raises ArgumentError on anything malformed.
    def parse_trusted_root(doc)
      raise Fail, 'not a trusted root v0.1' unless obj?(doc) && doc['mediaType'] == 'application/vnd.dev.sigstore.trustedroot+json;version=0.1'

      arr = ->(k) { doc[k].is_a?(Array) ? doc[k] : [] }
      tlogs = arr.call('tlogs').map { |t| pinned_log(t, true) }.compact
      ctlogs = arr.call('ctlogs').map { |t| pinned_log(t, false) }.compact
      cas = arr.call('certificateAuthorities').map { |c| pinned_chain(c) }
      tsas = arr.call('timestampAuthorities').map { |c| pinned_chain(c) }
      raise Fail, 'a trusted root needs a transparency log and a CA' if tlogs.empty? || cas.empty?

      PinnedRoots.new(tlogs, ctlogs, cas, tsas)
    rescue StandardError => e
      raise ArgumentError, e.message
    end

    # ---------------------------------------------------------------------------------------------- DER (as the reference)

    def tlv(b, off, limit = b.bytesize)
      raise Fail, 'DER truncated' if off + 2 > limit

      tag = b.getbyte(off)
      raise Fail, 'DER multi-byte tag' if (tag & 0x1f) == 0x1f

      len = b.getbyte(off + 1)
      body = off + 2
      if len.anybits?(0x80)
        n = len & 0x7f
        raise Fail, 'DER length' if n.zero? || n > 4 || body + n > limit

        len = b.byteslice(body, n).bytes.reduce(0) { |a, x| (a << 8) | x }
        body += n
      end
      raise Fail, 'DER overrun' if body + len > limit

      Tlv.new(tag, off, body, body + len)
    end

    def kids(b, t)
      out = []
      o = t.body
      while o < t.end_
        c = tlv(b, o, t.end_)
        out << c
        o = c.end_
      end
      out
    end

    def oid(b, t)
      raise Fail, 'not an OID' if t.nil? || t.tag != 0x06 || t.end_ <= t.body

      parts = []
      v = 0
      (t.body...t.end_).each do |i|
        x = b.getbyte(i)
        v = (v * 128) + (x & 0x7f)
        if x.nobits?(0x80)
          parts << v
          v = 0
        end
      end
      raise Fail, 'not an OID' if parts.empty?

      first = parts.shift
      a = [2, first / 40].min
      [a, first - (a * 40), *parts].join('.')
    end

    def body_of(b, t) = b.byteslice(t.body, t.end_ - t.body)
    def span(b, t) = b.byteslice(t.start, t.end_ - t.start)

    def utf8_strict(b)
      s = b.dup.force_encoding(Encoding::UTF_8)
      raise Fail, 'not UTF-8' unless s.valid_encoding?

      s.delete_prefix("﻿")
    end

    def utf8_lossy(b) = b.dup.force_encoding(Encoding::UTF_8).scrub("�")

    def parse_cert(d)
      cert = tlv(d, 0)
      raise Fail, 'certificate is not one SEQUENCE' if cert.tag != 0x30 || cert.end_ != d.bytesize

      tbs = kids(d, cert)[0]
      raise Fail, 'no TBSCertificate' if tbs.nil? || tbs.tag != 0x30

      tbs_kids = kids(d, tbs)
      wrapper = tbs_kids.find { |k| k.tag == 0xa3 }
      raise Fail, 'no extensions' if wrapper.nil?

      seq = kids(d, wrapper)[0]
      raise Fail, 'extensions malformed' if seq.nil? || seq.tag != 0x30

      seen = {}
      exts = kids(d, seq).map do |e|
        parts = kids(d, e)
        oct = parts[-1]
        raise Fail, 'extension value is not an OCTET STRING' if oct.nil? || oct.tag != 0x04

        o = oid(d, parts[0])
        raise Fail, "duplicate extension #{o}" if seen[o]

        seen[o] = true
        Ext.new(o, body_of(d, oct), e)
      end
      ParsedCert.new(d, tbs_kids, wrapper, exts)
    end

    def ext(c, o) = c.exts.find { |x| x.oid == o }

    # Fulcio extension .1.n: raw UTF-8 for n <= 6, a DER UTF8String for n >= 8.
    def fulcio_ext(c, n)
      e = ext(c, "#{OID_FULCIO}#{n}")
      return nil if e.nil?
      return utf8_strict(e.value) if n <= 6

      t = tlv(e.value, 0)
      raise Fail, "extension .1.#{n} is not a DER UTF8String" if t.tag != 0x0c || t.end_ != e.value.bytesize

      utf8_strict(body_of(e.value, t))
    end

    def san_identity(c)
      e = ext(c, OID_SAN)
      raise Fail, 'no subjectAltName' if e.nil?

      seq = tlv(e.value, 0)
      names = kids(e.value, seq)
      raise Fail, 'subjectAltName must hold exactly one name' if seq.tag != 0x30 || names.length != 1
      raise Fail, 'subjectAltName must be a URI or an email' unless [0x86, 0x81].include?(names[0].tag)

      utf8_strict(body_of(e.value, names[0]))
    end

    # node's X509Certificate.keyUsage: the extended key usage OIDs.
    def eku(c)
      e = c.extensions[OID_EKU]
      return [] if e.nil?

      kids(e.value, tlv(e.value, 0)).map { |k| oid(e.value, k) }
    end

    def inside?(c, at)
      lo, hi = Der.der_validity_ms(c.raw)
      !lo.nil? && !hi.nil? && lo <= at && at <= hi
    end

    # Leaf first, self-signed root last: issuer links, signatures, CA flags; every certificate valid at `at`.
    def chain_ok?(chain, at)
      chain.each_with_index.all? do |c, i|
        up = chain[i + 1] || c
        c.check_issued(up) && c.verify(up.public_key) && inside?(c, at) && (i.zero? || c.ca)
      end
    end

    def ed25519?(key) = !key.is_a?(OpenSSL::PKey::EC) && !key.is_a?(OpenSSL::PKey::RSA) && key.respond_to?(:oid) && key.oid == 'ED25519'

    # node's crypto.verify: ECDSA (DER), RSA PKCS#1 v1.5, or Ed25519 when hash_name is nil.
    def verify_sig(hash_name, data, key, sig)
      if hash_name.nil?
        return false unless ed25519?(key)

        return key.verify(nil, sig.b, data.b)
      end
      case Common.key_type(key)
      when 'ec' then Common.ecdsa_verify_der(key, sig, data, hash_name)
      when 'rsa' then Common.rsa_pkcs1_verify(key, sig, data, hash_name)
      else false
      end
    rescue StandardError
      false
    end

    # ---------------------------------------------------------------------------------------------- SCT (RFC 6962 3.2)

    def verify_sct(leaf, issuer, roots)
      e = ext(leaf, OID_SCT_LIST)
      return 'no embedded SCT' if e.nil?

      outer = tlv(e.value, 0)
      return 'SCT list is not an OCTET STRING' if outer.tag != 0x04

      list = body_of(e.value, outer)
      return 'SCT list length' if list.bytesize < 2 || list.unpack1('n') != list.bytesize - 2

      d = leaf.der
      ext_seq = kids(d, leaf.exts_wrapper)[0]
      kept = kids(d, ext_seq).reject { |k| k.start == e.tlv.start }.map { |k| span(d, k) }.join
      tbs = der(0x30, leaf.tbs_kids.map { |k| k.equal?(leaf.exts_wrapper) ? der(0xa3, der(0x30, kept)) : span(d, k) }.join)
      issuer_key_hash = sha256(issuer.spki_der)
      why = 'no SCT from a pinned CT log'
      o = 2
      while o < list.bytesize
        return 'SCT truncated' if o + 2 > list.bytesize

        n = list.byteslice(o, 2).unpack1('n')
        s = list.byteslice(o + 2, n) || ''.b
        o += 2 + n
        return 'SCT truncated' if s.bytesize != n || n < 47
        next if s.getbyte(0) != 0

        log_id = s.byteslice(1, 32)
        ts = s.byteslice(33, 8).unpack1('Q>')
        ext_len = s.byteslice(41, 2).unpack1('n')
        ext_b = s.byteslice(43, ext_len) || ''.b
        p = 43 + ext_len
        return 'SCT truncated' if p + 4 > s.bytesize

        hash_alg = s.getbyte(p)
        sig_alg = s.getbyte(p + 1)
        sig_len = s.byteslice(p + 2, 2).unpack1('n')
        sig = s.byteslice(p + 4, sig_len) || ''.b
        p += 4 + sig_len
        return 'SCT malformed' if p != s.bytesize || sig.bytesize != sig_len

        log = roots.ctlogs.find { |l| l.key_id == log_id }
        next if log.nil?

        if hash_alg != 4 || ![3, 1].include?(sig_alg)
          why = 'SCT is not SHA-256 with ECDSA or RSA'
          next
        end
        if ts < log.valid.start || ts > log.valid.end_
          why = 'SCT log key not valid at its timestamp'
          next
        end
        signed = [0, 0, ts, 1].pack('CCQ>n') + issuer_key_hash + [tbs.bytesize].pack('N').byteslice(1, 3) + tbs +
                 [ext_b.bytesize].pack('n') + ext_b
        return nil if verify_sig('sha256', signed, log.key, sig)

        why = 'SCT signature invalid'
      end
      why
    end

    # ---------------------------------------------------------------------------------------------- RFC 3161 timestamps

    def digest_of(b, t)
      alg = DIGEST_OIDS[oid(b, kids(b, t)[0])]
      raise Fail, 'unsupported digest algorithm' if alg.nil?

      alg
    end

    def digest(alg, data) = OpenSSL::Digest.new(alg.upcase).digest(data.b)

    def generalized_time(b, t)
      raise Fail, 'genTime is not a GeneralizedTime' if t.nil? || t.tag != 0x18

      m = /\A(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z\z/.match(body_of(b, t).dup.force_encoding(Encoding::BINARY))
      raise Fail, 'genTime malformed' unless m

      ms = Der.parse_der_time(0x18, "#{m[1]}#{m[2]}#{m[3]}#{m[4]}#{m[5]}#{m[6]}Z")
      raise Fail, 'genTime malformed' if ms.nil?

      ms + (m[7] ? m[7].ljust(9, '0')[0, 3].to_i : 0)
    end

    # Verify an RFC 3161 TimeStampResp (or bare token) over `data` (the raw signature bytes) against a pinned TSA; returns
    # genTime (epoch ms). Raises on any failure.
    def verify_rfc3161(token, data, tsas)
      token = token.b
      ci = tlv(token, 0)
      raise Fail, 'timestamp is not one SEQUENCE' if ci.end_ != token.bytesize || ci.tag != 0x30

      parts = kids(token, ci)
      p0 = parts[0]
      if p0 && p0.tag == 0x30 && p0.end_ - p0.body >= 3 && token.getbyte(kids(token, p0)[0].start) == 0x02
        st = kids(token, p0)[0]
        status = body_of(token, st)
        raise Fail, 'timestamp status is not granted' unless status.bytesize == 1 && [0, 1].include?(status.getbyte(0))
        raise Fail, 'no timeStampToken' if parts[1].nil?

        ci = parts[1]
        parts = kids(token, ci)
      end
      raise Fail, 'not CMS SignedData' if oid(token, parts[0]) != OID_SIGNED_DATA || parts[1]&.tag != 0xa0

      sd = kids(token, parts[1])[0]
      sdk = kids(token, sd)
      encap = sdk.each_with_index.find { |k, i| i > 1 && k.tag == 0x30 }&.first
      raise Fail, 'no encapsulated content' if encap.nil?

      ek = kids(token, encap)
      raise Fail, 'content is not TSTInfo' if oid(token, ek[0]) != OID_TST_INFO || ek[1]&.tag != 0xa0

      octet = kids(token, ek[1])[0]
      raise Fail, 'TSTInfo is not an OCTET STRING' if octet.nil? || octet.tag != 0x04

      tst_bytes = body_of(token, octet)
      tk = kids(tst_bytes, tlv(tst_bytes, 0))
      mi = kids(tst_bytes, tk.fetch(2))
      mi_alg = digest_of(tst_bytes, mi.fetch(0))
      raise Fail, 'messageImprint is not the hash of the signature' if digest(mi_alg, data) != body_of(tst_bytes, mi.fetch(1))

      gen_time = generalized_time(tst_bytes, tk[4])
      signer_infos = sdk.fetch(-1)
      raise Fail, 'no signerInfos' if signer_infos.tag != 0x31

      sis = kids(token, signer_infos)
      raise Fail, 'exactly one SignerInfo is required' if sis.length != 1

      si = kids(token, sis[0])
      d_alg = digest_of(token, si.fetch(2))
      attrs = si.fetch(3)
      raise Fail, 'signed attributes are required' if attrs.tag != 0xa0

      ct_ok = false
      md_ok = false
      kids(token, attrs).each do |a|
        ak = kids(token, a)
        vals = kids(token, ak.fetch(1))
        o = oid(token, ak[0])
        raise Fail, 'an attribute must have one value' if vals.length != 1

        ct_ok = oid(token, vals[0]) == OID_TST_INFO if o == OID_CONTENT_TYPE
        md_ok = digest(d_alg, tst_bytes) == body_of(token, vals[0]) if o == OID_MESSAGE_DIGEST
      end
      raise Fail, 'signed attributes do not commit to the TSTInfo' unless ct_ok && md_ok

      signed_attrs = "\x31".b + token.byteslice(attrs.start + 1, attrs.end_ - attrs.start - 1)
      sig_t = si.fetch(5)
      raise Fail, 'signature is not an OCTET STRING' if sig_t.tag != 0x04

      sig = body_of(token, sig_t)
      tsas.each do |tsa|
        next if gen_time < tsa.valid.start || gen_time > tsa.valid.end_

        leaf = tsa.chain[0]
        next unless eku(leaf).include?(EKU_TIME_STAMPING)
        next unless verify_sig(d_alg, signed_attrs, leaf.public_key, sig)
        next unless chain_ok?(tsa.chain, gen_time)

        return gen_time
      end
      raise Fail, 'no pinned timestamp authority signed it (valid at its time)'
    end

    # ---------------------------------------------------------------------------------------------- Rekor

    # Signed-note checkpoint: origin, size, root; then `— <name> <b64(hint4 || sig)>` lines (v1 ECDSA, v2 Ed25519).
    def verify_checkpoint(text, log, size, root)
      cut = text.index("\n\n")
      return 'checkpoint has no signature block' if cut.nil?

      body = text[0, cut + 1]
      lines = body.split("\n", -1)
      return 'checkpoint body too short or without an origin' if lines.length < 4 || lines[0].empty?
      return 'checkpoint size differs from the proof' if !lines[1].match?(/\A[1-9][0-9]*\z/) || lines[1].to_i != size
      return 'checkpoint root differs from the proof' if b64(lines[2]) != root

      text[(cut + 2)..].split("\n", -1).each do |l|
        m = %r{\A— (\S+) ([A-Za-z0-9+/=]+)\z}.match(l)
        next unless m

        raw = b64(m[2])
        next if raw.bytesize < 5 || raw.byteslice(0, 4) != log.key_id.byteslice(0, 4)
        next if log.v2_name && m[1] != log.v2_name
        return nil if verify_sig(log.v2_name ? nil : 'sha256', body.b, log.key, raw.byteslice(4..))
      end
      'no checkpoint signature by the pinned log key'
    end

    def dec_int(v)
      raise Fail, 'not a decimal integer string' unless v.is_a?(String) && v.match?(/\A(0|[1-9][0-9]{0,15})\z/)

      n = v.to_i
      raise Fail, 'integer out of range' if n > (2**53) - 1

      n
    end

    # DSSE PAE (secure-systems-lab/dsse protocol.md).
    def dsse_pae(payload_type, payload)
      t = payload_type.b
      "DSSEv1 #{t.bytesize} ".b + t + " #{payload.bytesize} ".b + payload.b
    end

    def leaf_hash_alg(key)
      return nil unless Common.key_type(key) == 'ec'

      { 'prime256v1' => 'sha256', 'secp384r1' => 'sha384' }[key.group.curve_name]
    end

    def pem_der(pem)
      m = %r{\A-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?\z}.match(pem)
      m ? b64(m[1].delete("\n")) : ''.b
    end

    def kind_of(k, v) = k.is_a?(String) && v.is_a?(String) ? "#{k}/#{v}" : ''

    def json_parse(text) = Common.js_json_loads(text)

    # ---------------------------------------------------------------------------------------------- the verifier

    def no(code, detail) = { ok: false, code: code, detail: detail }

    # Verify a Sigstore bundle (a String-keyed Hash) carrying a DSSE in-toto statement. Never raises.
    # { ok: true, core: (String keys, as the shared vectors), statement: } | { ok: false, code:, detail: }.
    def verify_sigstore_bundle_core(bundle, roots)
      stage = 'malformed'
      return no('malformed', 'not a bundle') unless obj?(bundle) && obj?(bundle['verificationMaterial'])

      mt = bundle['mediaType']
      return no('media_type', "unsupported media type #{mt}") unless mt.is_a?(String) && MEDIA_TYPES.include?(mt)

      vm = bundle['verificationMaterial']
      cert_raw = if mt == MEDIA_TYPES[0]
                   certs = get(vm['x509CertificateChain'], 'certificates')
                   certs.is_a?(Array) ? get(certs[0], 'rawBytes') : nil
                 else
                   get(vm['certificate'], 'rawBytes')
                 end
      return no('not_keyless', 'no Fulcio certificate (public-key bundles are not supported)') if cert_raw.nil?

      env = bundle['dsseEnvelope']
      return no('envelope', 'not a DSSE bundle') if !obj?(env) || bundle.key?('messageSignature')
      return no('envelope', 'payloadType is not application/vnd.in-toto+json') if env['payloadType'] != INTOTO_PAYLOAD_TYPE

      sigs0 = env['signatures']
      unless sigs0.is_a?(Array) && sigs0.length == 1 && obj?(sigs0[0])
        return no('envelope', 'a DSSE envelope must carry exactly one signature')
      end

      payload = b64(env['payload'])
      dsse_sig = b64(sigs0[0]['sig'])
      pae = dsse_pae(INTOTO_PAYLOAD_TYPE, payload)
      stage = 'cert_parse'
      leaf_der = b64(cert_raw)
      leaf = Cert.new(leaf_der)
      pc = parse_cert(leaf_der)
      alg = leaf_hash_alg(leaf.public_key)

      # ---- the log entry and its log
      stage = 'tlog_count'
      entries = vm['tlogEntries']
      unless entries.is_a?(Array) && entries.length == 1 && obj?(entries[0])
        return no('tlog_count', 'exactly one transparency log entry is required')
      end

      t = entries[0]
      stage = 'tlog_kind'
      kv = kind_of(get(t['kindVersion'], 'kind'), get(t['kindVersion'], 'version'))
      return no('tlog_kind', "unsupported entry #{kv}") unless ['dsse/0.0.1', 'intoto/0.0.2', 'hashedrekord/0.0.2'].include?(kv)

      v2 = kv == 'hashedrekord/0.0.2'
      stage = 'tlog_key'
      key_id = b64(get(t['logId'], 'keyId'))
      log = roots.tlogs.find { |l| l.key_id == key_id }
      return no('tlog_key', 'the entry names a log the verifier did not pin') if log.nil?
      return no('tlog_key', 'the entry type does not match the log version') if v2 != !log.v2_name.nil?

      log_index = dec_int(t['logIndex'])
      body = b64(t['canonicalizedBody'])

      # ---- time first: every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
      stage = 'tsa'
      times = []
      ts_list = get(vm['timestampVerificationData'], 'rfc3161Timestamps')
      (ts_list.is_a?(Array) ? ts_list : []).each do |ts|
        times << verify_rfc3161(b64(get(ts, 'signedTimestamp')), dsse_sig, roots.tsas)
      end
      tsa_count = times.length
      set = false
      if !v2 && obj?(t['inclusionPromise'])
        stage = 'tlog_set'
        integrated = dec_int(t['integratedTime'])
        msg = "{\"body\":#{JSON.generate(t['canonicalizedBody'])},\"integratedTime\":#{integrated}," \
              "\"logID\":\"#{key_id.unpack1('H*')}\",\"logIndex\":#{log_index}}"
        unless verify_sig('sha256', msg, log.key, b64(t['inclusionPromise']['signedEntryTimestamp']))
          return no('tlog_set', 'signed entry timestamp invalid')
        end

        times << (integrated * 1000)
        set = true
      end
      if times.empty?
        return no('no_verified_time', 'no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp')
      end
      return no('tlog_key', 'the log key was not valid at a signing time') if times.any? { |at| at < log.valid.start || at > log.valid.end_ }

      # ---- inclusion
      stage = 'tlog_inclusion'
      ip = t['inclusionProof']
      return no('tlog_inclusion', 'no inclusion proof') unless obj?(ip) && ip['hashes'].is_a?(Array) && obj?(ip['checkpoint'])

      root = b64(ip['rootHash'])
      size = dec_int(ip['treeSize'])
      unless AtlasPca.verify_rfc9162_inclusion(AtlasPca.rfc9162_leaf_hash(body), dec_int(ip['logIndex']), size,
                                               ip['hashes'].map { |h| b64(h) }, root)
        return no('tlog_inclusion', 'the inclusion proof does not lead to the root')
      end

      stage = 'tlog_checkpoint'
      envelope = ip['checkpoint']['envelope']
      cpe = envelope.is_a?(String) ? verify_checkpoint(envelope, log, size, root) : 'checkpoint has no signature block'
      return no('tlog_checkpoint', cpe) if cpe

      # ---- certificate path at every verified time (hybrid model), CT
      stage = 'cert_chain'
      issuer = nil
      roots.cas.each do |ca|
        next if times.any? { |at| at < ca.valid.start || at > ca.valid.end_ }

        first = ca.chain[0]
        next unless leaf.check_issued(first) && leaf.verify(first.public_key)

        if times.all? { |at| chain_ok?(ca.chain, at) } && ca.chain.all?(&:ca)
          issuer = first
          break
        end
      end
      return no('cert_chain', 'no pinned CA issued the certificate, valid at every signing time') if issuer.nil?
      return no('cert_chain', 'the leaf is a CA certificate') if leaf.ca
      return no('cert_time', 'the certificate was not valid at a signing time') unless times.all? { |at| inside?(leaf, at) }
      return no('cert_eku', 'the certificate lacks the code-signing EKU') unless eku(leaf).include?(EKU_CODE_SIGNING)

      unless roots.ctlogs.empty?
        stage = 'sct'
        sct = verify_sct(pc, issuer, roots)
        return no('sct', sct) if sct
      end

      # ---- the entry body names this envelope
      stage = 'tlog_body'
      eb = json_parse(utf8_lossy(body))
      raise Fail, 'entry body is null' if eb.nil?

      eb = {} unless obj?(eb)
      spec = obj?(eb['spec']) ? eb['spec'] : {}
      return no('tlog_body', 'the entry body is not the kind the bundle names') if kind_of(eb['kind'], eb['apiVersion']) != kv

      payload_sha = OpenSSL::Digest::SHA256.hexdigest(payload)
      case kv
      when 'dsse/0.0.1'
        ph = spec['payloadHash']
        return no('tlog_body', 'the entry names another payload') if get(ph, 'algorithm') != 'sha256' || get(ph, 'value') != payload_sha

        sigs = spec['signatures'].is_a?(Array) ? spec['signatures'] : []
        return no('tlog_body', 'the entry must name exactly one signature') unless sigs.length == 1 && obj?(sigs[0])
        return no('tlog_body', 'the entry names another signature') if b64(sigs[0]['signature']) != dsse_sig
        return no('tlog_body', 'the entry names another certificate') if pem_der(utf8_lossy(b64(sigs[0]['verifier']))) != leaf_der
      when 'intoto/0.0.2'
        # Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
        c = obj?(spec['content']) ? spec['content'] : {}
        ph = c['payloadHash']
        return no('tlog_body', 'the entry names another payload') if get(ph, 'algorithm') != 'sha256' || get(ph, 'value') != payload_sha

        sigs = get(c['envelope'], 'signatures')
        sigs = [] unless sigs.is_a?(Array)
        return no('tlog_body', 'the entry must name exactly one signature') unless sigs.length == 1 && obj?(sigs[0])
        return no('tlog_body', 'the entry names another signature') if b64(b64(sigs[0]['sig'])) != dsse_sig
        return no('tlog_body', 'the entry names another certificate') if pem_der(utf8_lossy(b64(sigs[0]['publicKey']))) != leaf_der
      else
        # Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
        h = spec['hashedRekordV002']
        data = get(h, 'data')
        hash_name = { 'SHA2_256' => 'sha256', 'SHA2_384' => 'sha384', 'SHA2_512' => 'sha512' }[get(data, 'algorithm')]
        return no('tlog_body', "the entry digest algorithm is not the signing key's") if hash_name.nil? || hash_name != alg
        return no('tlog_body', 'the entry names another envelope') if b64(get(data, 'digest')) != digest(hash_name, pae)

        sg = get(h, 'signature')
        return no('tlog_body', 'the entry names another signature') if b64(get(sg, 'content')) != dsse_sig
        if b64(get(get(get(sg, 'verifier'), 'x509Certificate'), 'rawBytes')) != leaf_der
          return no('tlog_body', 'the entry names another certificate')
        end
      end

      # ---- DSSE signature
      stage = 'signature'
      return no('signature', 'unsupported leaf key type') if alg.nil?
      return no('signature', 'DSSE signature invalid') unless verify_sig(alg, pae, leaf.public_key, dsse_sig)

      # ---- identity
      stage = 'identity'
      identity = san_identity(pc)
      iss_v2 = fulcio_ext(pc, 8)
      iss_v1 = fulcio_ext(pc, 1)
      return no('identity', 'the two issuer extensions disagree') if !iss_v2.nil? && !iss_v1.nil? && iss_v2 != iss_v1

      oidc_issuer = iss_v2.nil? ? iss_v1 : iss_v2
      return no('identity', 'no OIDC issuer extension') if oidc_issuer.nil? || oidc_issuer.empty?

      source_repo = fulcio_ext(pc, 12)
      source_digest = fulcio_ext(pc, 13)
      source_ref = fulcio_ext(pc, 14)

      # ---- statement
      stage = 'statement'
      st = json_parse(utf8_strict(payload))
      raise Fail, 'statement is null' if st.nil?
      return no('statement', 'not an in-toto Statement v1') unless obj?(st) && st['_type'] == AtlasPca::INTOTO_STATEMENT_V1
      return no('statement', 'no subject') unless st['subject'].is_a?(Array) && !st['subject'].empty?

      subjects = []
      st['subject'].each do |s|
        d = get(s, 'digest')
        d = {} unless obj?(d)
        %w[sha256 sha512].each { |a| subjects << { 'alg' => a, 'digest' => d[a] } if d[a].is_a?(String) }
      end
      return no('statement', 'no sha256/sha512 subject digest (or more than 64)') if subjects.empty? || subjects.length > 64
      return no('statement', 'no predicateType') unless st['predicateType'].is_a?(String)

      core = { 'identity' => identity, 'oidc_issuer' => oidc_issuer }
      core['source_repo'] = source_repo unless source_repo.nil?
      core['source_ref'] = source_ref unless source_ref.nil?
      core['source_digest'] = source_digest unless source_digest.nil?
      core.merge!('predicate_type' => st['predicateType'], 'subjects' => subjects, 'signed_time' => times.min.div(1000),
                  'rekor_log_index' => log_index, 'rekor' => v2 ? 'v2' : 'v1', 'timestamps' => { 'tsa' => tsa_count, 'set' => set })
      { ok: true, core: core, statement: st }
    rescue StandardError, SystemStackError => e
      no(stage, "fail closed: #{e.message}")
    end

    # verify_sigstore_bundle_core, then the SLSA v1 predicate: the facts provenance_gate checks.
    def verify_sigstore_bundle(bundle, roots)
      r = verify_sigstore_bundle_core(bundle, roots)
      return r unless r[:ok]

      st = r[:statement]
      c = r[:core]
      unless st['predicateType'] == AtlasPca::SLSA_PROVENANCE_V1
        return { ok: false, code: 'predicate', detail: "predicate #{st['predicateType']} is not SLSA provenance v1" }
      end

      pr = obj?(st['predicate']) ? st['predicate'] : {}
      bd = obj?(pr['buildDefinition']) ? pr['buildDefinition'] : {}
      rd = obj?(pr['runDetails']) ? pr['runDetails'] : {}
      builder_id = get(rd['builder'], 'id')
      unless bd['buildType'].is_a?(String) && builder_id.is_a?(String) && obj?(bd['externalParameters'])
        return { ok: false, code: 'predicate', detail: 'buildType, externalParameters and builder.id are required (SLSA Build L1)' }
      end

      deps = bd['resolvedDependencies']
      dep0 = deps.is_a?(Array) && obj?(deps[0]) ? deps[0] : nil
      facts = { 'v' => 1, 'predicate_type' => AtlasPca::SLSA_PROVENANCE_V1, 'build_type' => bd['buildType'], 'builder_id' => builder_id,
                'subjects' => c['subjects'], 'identity' => c['identity'], 'oidc_issuer' => c['oidc_issuer'] }
      %w[source_repo source_ref source_digest].each { |k| facts[k] = c[k] if c.key?(k) }
      if dep0 && dep0['uri'].is_a?(String)
        ps = { 'uri' => dep0['uri'] }
        commit = get(dep0['digest'], 'gitCommit')
        ps['git_commit'] = commit if commit.is_a?(String)
        facts['provenance_source'] = ps
      end
      facts['integrated_time'] = c['signed_time']
      facts['rekor_log_index'] = c['rekor_log_index']
      { ok: true, facts: facts }
    end
  end

  module_function

  def parse_trusted_root(doc) = SigstoreBundle.parse_trusted_root(doc)
  def verify_sigstore_bundle_core(bundle, roots) = SigstoreBundle.verify_sigstore_bundle_core(bundle, roots)
  def verify_sigstore_bundle(bundle, roots) = SigstoreBundle.verify_sigstore_bundle(bundle, roots)
end
