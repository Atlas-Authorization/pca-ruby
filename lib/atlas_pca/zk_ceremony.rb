# frozen_string_literal: true

require 'digest'

module AtlasPca
  # Provenance of a Groth16 verifying key: the id of a key, the record tying a circuit version to its key, and the check of a
  # trusted-setup ceremony transcript (at least two chained contributions and a random beacon). Pure: no curve arithmetic. A
  # transcript that passes says the transcript is well-formed and names its key; it does not replay the ceremony.
  module ZkCeremony
    H64 = /\A[0-9a-f]{64}\z/
    VK_ID = /\Avk_[0-9a-f]{64}\z/
    ABSENT = Object.new.freeze
    MAX_SAFE = (2**53) - 1

    module_function

    # the text the reference tests a value as: a string is itself, a list its members joined by commas; nothing else can be a digest
    def text(v)
      case v
      when String then v
      when Array then v.map { |x| x.nil? ? '' : text(x) }.join(',')
      else ''
      end
    end

    # a lone surrogate (raw bytes that are not UTF-8) is never a digest; matching it would raise
    def h64?(v) = (t = text(v)).valid_encoding? && t.match?(H64)

    # equal as the reference compares (===): strings and numbers by value, a list or an object never equals another
    def same?(a, b)
      return a == b if a.is_a?(String) && b.is_a?(String)
      return a == b if a.is_a?(Numeric) && b.is_a?(Numeric)

      (a.nil? || a == true || a == false) && a.equal?(b)
    end

    def safe_int?(x) = (x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor)) && x.abs <= MAX_SAFE
    def member(h, k) = h.is_a?(Hash) ? h[k] : nil

    # 'vk_' + hex SHA-256 of the canonical JSON of a verifying key.
    def vk_id(vkey)
      raise AtlasPca::Malformed, 'canonicalize: unsupported type undefined' if vkey.equal?(ABSENT) # JS undefined

      "vk_#{Digest::SHA256.hexdigest(AtlasPca.canon_bytes(vkey))}"
    end

    # The provenance record {circuit, sourceSha256, r1csSha256, vkId} of a circuit version. Raises ArgumentError for an empty
    # circuit id or a hash that is not 64 lowercase hex characters.
    def circuit_provenance(circuit:, source_sha256:, r1cs_sha256:, vkey: ABSENT)
      raise ArgumentError, 'circuitProvenance: bad circuit id or hash' if !h64?(source_sha256) || !h64?(r1cs_sha256) || circuit == ''

      { 'circuit' => circuit, 'sourceSha256' => source_sha256, 'r1csSha256' => r1cs_sha256, 'vkId' => vk_id(vkey) }
    end

    # nil when the record is for this circuit, these sources (and constraint system, when pinned) and this key, else the reason.
    def check_circuit_provenance(prov, circuit:, source_sha256:, vkey:, r1cs_sha256: ABSENT)
      return 'not a provenance record' unless prov.is_a?(Hash) || prov.is_a?(Array)
      return 'record is for another circuit' unless same?(member(prov, 'circuit'), circuit)
      return 'circuit sources differ from the pinned version' unless same?(member(prov, 'sourceSha256'), source_sha256)

      r1cs = member(prov, 'r1csSha256')
      return 'constraint system differs' if !r1cs.is_a?(String) || !r1cs.valid_encoding? || !r1cs.match?(H64) || (!r1cs_sha256.equal?(ABSENT) && !same?(r1cs, r1cs_sha256))
      return 'verifying key is not the recorded one' unless same?(member(prov, 'vkId'), vk_id(vkey))

      nil
    end

    # Hex SHA-256 of the canonical JSON of a transcript.
    def transcript_sha256(transcript) = Digest::SHA256.hexdigest(AtlasPca.canon_bytes(transcript))

    # nil when the transcript is a well-formed version-1 ceremony record, else the first reason it is not: at least
    # max(2, min_contributions, its own minContributions) contributions, each indexed in order, named once, with a fresh key that
    # chains from the previous one; a random beacon (2^10..2^63 iterations) applied after the last contribution whose output is
    # the final key; a verifying-key id. `circuit` / `r1cs_sha256` pin what it must be for.
    def check_transcript(transcript, min_contributions: nil, r1cs_sha256: ABSENT, circuit: ABSENT)
      x = transcript
      return 'not a version-1 transcript' unless x.is_a?(Hash) && x['version'].is_a?(Numeric) && x['version'] == 1
      return 'no circuit id' unless x['circuit'].is_a?(String) && !x['circuit'].empty?
      return 'transcript is for another circuit' if !circuit.equal?(ABSENT) && !same?(x['circuit'], circuit)
      return 'unknown curve' unless %w[bn128 bls12-381].include?(x['curve'])

      %w[r1csSha256 ptauSha256 initZkeySha256].each { |k| return "#{k} is not a SHA-256" unless h64?(x[k]) }
      return 'transcript is for a different constraint system' if !r1cs_sha256.equal?(ABSENT) && !same?(x['r1csSha256'], r1cs_sha256)

      min = [2, min_contributions.nil? ? 2 : min_contributions, safe_int?(x['minContributions']) ? x['minContributions'] : 2].max
      cs = x['contributions']
      return "fewer than #{Predicates.js_number_string(min)} contributions" unless cs.is_a?(Array) && cs.length >= min

      names = {}
      keys = {}
      prev = x['initZkeySha256']
      cs.each_with_index do |c, i|
        idx = member(c, 'index')
        in_order = idx.is_a?(Numeric) && idx == i && !(idx.is_a?(Float) && idx.zero? && (1.0 / idx).negative?)
        return "contribution #{i} is malformed" unless c.is_a?(Hash) && in_order && c['name'].is_a?(String) && !c['name'].empty?
        return "contribution #{i} does not chain from the previous key" if !h64?(c['zkeySha256']) || !same?(c['prevZkeySha256'], prev)

        key = c['zkeySha256']
        return "contribution #{i} repeats a name or key" if names.key?(c['name']) || (key.is_a?(String) && keys.key?(key))

        names[c['name']] = true
        keys[key] = true if key.is_a?(String)
        prev = key
      end
      b = x['beacon']
      exp = member(b, 'iterationsExp')
      return 'no valid random beacon' unless b.is_a?(Hash) && h64?(b['hashHex']) && safe_int?(exp) && exp >= 10 && exp <= 63
      return 'beacon is not applied after the last contribution' if !same?(b['prevZkeySha256'], prev) || !h64?(b['zkeySha256'])
      return 'final key is not the beacon output' unless same?(x['finalZkeySha256'], b['zkeySha256'])
      return 'no verifying-key id' unless x['vkId'].is_a?(String) && x['vkId'].valid_encoding? && x['vkId'].match?(VK_ID)

      nil
    end

    # 'multi-party' only when `evidence` ({'transcript', 'sha256', 'r1csSha256'?, 'circuit'?}) carries a well-formed transcript
    # with that pinned SHA-256 that names this verifying key; anything else, including any error, is 'single-party'.
    def ceremony_of(vkey, evidence = nil)
      return 'single-party' unless (vkey.is_a?(Hash) || vkey.is_a?(Array)) && evidence.is_a?(Hash)

      t = evidence['transcript']
      pins = {}
      pins[:r1cs_sha256] = evidence['r1csSha256'] if evidence.key?('r1csSha256')
      pins[:circuit] = evidence['circuit'] if evidence.key?('circuit')
      return 'single-party' unless check_transcript(t, **pins).nil?
      return 'single-party' unless same?(transcript_sha256(t), evidence['sha256']) && same?(t['vkId'], vk_id(vkey))

      'multi-party'
    rescue StandardError, SystemStackError
      'single-party'
    end
  end
end
