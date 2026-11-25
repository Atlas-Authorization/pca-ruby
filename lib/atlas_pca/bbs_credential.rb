# frozen_string_literal: true

require_relative '../atlas_pca'
require_relative 'bbs'

module AtlasPca
  # PCA layer: a capability as a multi-message BBS credential with selective disclosure. The message vector is iss, sub, then one
  # message per caveat named "cav:<i>:<type>" whose value is the strict-canonical JSON of the caveat; each message's octets are
  # utf8(name) || 0x00 || utf8(value). Credentials, attributes and presentations are Hashes with the same member names as the
  # TypeScript types (String keys).
  module BbsCredential
    module_function

    # UTF-8 octets, U+FFFD for an unpaired surrogate (what a JavaScript TextEncoder produces; a lone surrogate is carried as its
    # WTF-8 bytes, an invalid UTF-8 string)
    def utf8(s)
      s.b.gsub(/\xED[\xA0-\xBF][\x80-\xBF]/n, "\xEF\xBF\xBD".b)
    end

    def encode_attribute(name, value)
      raise ArgumentError, 'attribute name and value must be strings' unless name.is_a?(String) && value.is_a?(String)
      raise ArgumentError, 'attribute name must not contain NUL' if name.b.include?("\0".b)

      utf8(name) + "\0".b + utf8(value)
    end

    def encode(attr)
      raise ArgumentError, 'not an object' unless attr.is_a?(Hash)

      encode_attribute(attr['name'], attr['value'])
    end

    def encode_all(attrs)
      raise ArgumentError, 'not an array' unless attrs.is_a?(Array)

      attrs.map { |a| encode(a) }
    end

    # JavaScript String(x) for the values a caveat type can hold
    def js_str(v)
      case v
      when String then v
      when nil then 'null'
      when Integer, Float then AtlasPca.fmt_number(v)
      else v.to_s
      end
    end

    # The ordered attribute vector for a capability: issuer, holder, then each caveat.
    def capability_attributes(capability)
      raise ArgumentError, 'capability must be an object' unless capability.is_a?(Hash)

      attrs = [{ 'index' => 0, 'name' => 'iss', 'value' => capability['issuer'] }, { 'index' => 1, 'name' => 'sub', 'value' => capability['holder'] }]
      caveats = capability['caveats'].is_a?(Array) ? capability['caveats'] : []
      caveats.each_with_index do |cv, i|
        raise TypeError, 'caveat must be an object' unless cv.is_a?(Hash)

        type = cv.key?('type') ? js_str(cv['type']) : 'undefined'
        attrs << { 'index' => i + 2, 'name' => "cav:#{i}:#{type}", 'value' => AtlasPca.canonicalize(cv) }
      end
      attrs
    end

    # Sign a capability's attributes as a BBS credential; header is optional application context (nil = empty).
    def issue_capability_credential(capability, sk, pk, header = nil)
      attributes = capability_attributes(capability)
      hdr = (header || ''.b).b
      signature = Bbs.sign(sk, pk, hdr, encode_all(attributes))
      { 'issuerPublicKey' => AtlasPca.b64e(pk), 'header' => AtlasPca.b64e(hdr), 'attributes' => attributes, 'signature' => AtlasPca.b64e(signature) }
    end

    # Verify a whole credential against its issuer key (every attribute). Never raises (except LoadError: no library).
    def verify_credential(cred)
      pk = AtlasPca.b64d(cred['issuerPublicKey'])
      header = AtlasPca.b64d(cred['header'])
      signature = AtlasPca.b64d(cred['signature'])
      return false if pk.nil? || header.nil? || signature.nil?

      Bbs.verify(pk, signature, header, encode_all(cred['attributes']))
    rescue StandardError
      false
    end

    # an integral JSON number as an Integer; raises otherwise
    def index_of(attr)
      raise ArgumentError, 'not an object' unless attr.is_a?(Hash)

      i = attr['index']
      ok = i.is_a?(Integer) || (i.is_a?(Float) && i.finite? && i == i.floor && i.abs <= 2**31)
      raise ArgumentError, 'attribute index is not an integer' unless ok

      i.to_i
    end

    # Selective-disclosure presentation revealing only the named attributes; presentation_header binds it to a context (nil = empty).
    # The proof is randomized.
    def present_credential(cred, disclose, presentation_header = nil)
      pk = AtlasPca.b64d(cred['issuerPublicKey']) || raise(ArgumentError, 'bad issuer key')
      header = AtlasPca.b64d(cred['header']) || raise(ArgumentError, 'bad header')
      signature = AtlasPca.b64d(cred['signature']) || raise(ArgumentError, 'bad signature')
      ph = (presentation_header || ''.b).b
      wanted = disclose.uniq
      messages = encode_all(cred['attributes'])
      idx = []
      disclosed = []
      cred['attributes'].each do |a|
        next unless wanted.include?(a['name'])

        idx << index_of(a)
        disclosed << a
      end
      missing = wanted.reject { |w| disclosed.any? { |d| d['name'] == w } }.sort
      raise ArgumentError, "presentCredential: unknown attribute(s): #{missing.join(', ')}" unless missing.empty?

      proof = Bbs.proof_gen(pk, signature, header, ph, messages, idx)
      { 'issuerPublicKey' => cred['issuerPublicKey'], 'header' => cred['header'], 'presentationHeader' => AtlasPca.b64e(ph),
        'messageCount' => cred['attributes'].length, 'disclosed' => disclosed, 'proof' => AtlasPca.b64e(proof) }
    end

    # Check a presentation. pk, disclosed and presentation_header default (when nil) to the values the presentation carries; pass
    # them to assert the verifier's own expectations. Never raises (except LoadError: no library).
    def verify_presentation(pres, pk: nil, disclosed: nil, presentation_header: nil)
      pkb = pk || AtlasPca.b64d(pres['issuerPublicKey'])
      header = AtlasPca.b64d(pres['header'])
      proof = AtlasPca.b64d(pres['proof'])
      return false if pkb.nil? || header.nil? || proof.nil?
      return false if !pk.nil? && AtlasPca.b64e(pk) != pres['issuerPublicKey']

      ph = presentation_header || AtlasPca.b64d(pres['presentationHeader'])
      return false if ph.nil?
      return false if !presentation_header.nil? && presentation_header.bytesize.positive? && AtlasPca.b64e(ph) != pres['presentationHeader']

      verify_inner(pres, pkb, header, proof, ph, disclosed)
    rescue StandardError
      false
    end

    def disclosure_key(x)
      raise ArgumentError, 'not an object' unless x.is_a?(Hash)

      "#{index_of(x)}\0#{x['name']}\0#{x['value']}"
    end

    def same_disclosure?(a, b)
      return false unless a.is_a?(Array) && b.is_a?(Array) && a.length == b.length

      a.map { |x| disclosure_key(x) }.sort == b.map { |x| disclosure_key(x) }.sort
    end

    def verify_inner(pres, pk, header, proof, ph, opts_disclosed)
      disclosed = opts_disclosed || pres['disclosed']
      return false if opts_disclosed && !same_disclosure?(opts_disclosed, pres['disclosed'])
      raise ArgumentError, 'not an array' unless disclosed.is_a?(Array)

      disclosed.each { |o| index_of(o) } # an attribute without an integer index fails closed
      ordered = disclosed.each_with_index.sort_by { |o, k| [index_of(o), k] }.map(&:first)
      msgs = ordered.map { |o| encode(o) }
      idx = ordered.map { |o| index_of(o) }
      count = pres['messageCount']
      count = nil unless count.is_a?(Numeric)
      return false if idx.any? { |i| i.negative? || (count && i >= count) }

      Bbs.proof_verify(pk, proof, header, ph, msgs, idx)
    end
  end
end
