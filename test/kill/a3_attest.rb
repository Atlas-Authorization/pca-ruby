# frozen_string_literal: true
# Exact-outcome kill tests for lib/atlas_pca/attest.rb and attest/*.rb: every row of the shared attestation-evidence-vectors.json
# (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, GCP Confidential Space, NVIDIA SPDM + the strict X.509 readers), one test per vendor,
# plus pinned outcomes of the JS-faithful helpers. The oracle host has the committed corpus (the flagship generates it).
require 'atlas_pca/attest'
module MutationKill
  module AttestRows
    module_function
    CONF = File.expand_path('../../conformance', __dir__)
    def doc
      @doc ||= begin
        require 'json'
        JSON.parse(File.read(File.join(ENV['PCA_CONFORMANCE_DIR'] || CONF, 'attestation-evidence-vectors.json'), encoding: 'UTF-8'))
      end
    end

    def hydrate(x, b)
      case x
      when Array then x.map { |e| hydrate(e, b) }
      when Hash then x.keys == ['$blob'] ? b.fetch(x['$blob']) : x.to_h { |k, v| [k, hydrate(v, b)] }
      else x
      end
    end

    def same?(got, want)
      want = want.dup
      if want.delete('reason_match') == 'prefix'
        prefix = want.delete('reason_prefix')
        return got['reason'].is_a?(String) && got['reason'].start_with?(prefix) && got.reject { |k, _| k == 'reason' } == want.reject { |k, _| k == 'reason' }
      end
      got == want
    end

    def vendor_ok?(vendor)
      doc['attestation_vectors'].select { |r| r['vendor'] == vendor }.all? do |r|
        h = hydrate(r, doc['blobs'])
        got = begin
          AtlasPca::Attest.run_attestation_vector(h)
        rescue StandardError, SystemStackError
          nil
        end
        !got.nil? && same?(got, h['expect'])
      end
    end

    def x509_ok?
      doc['x509_vectors'].all? { |r| AtlasPca::Attest.run_x509_vector(r['fn'], r['input']) == r['expect'] }
    end
  end

  %w[amd-sev-snp intel-tdx-dcap azure-maa gcp-confidential-space nvidia-gpu-spdm].each do |v|
    t("attest: #{v} evidence rows") { AttestRows.vendor_ok?(v) }
  end
  t('attest: strict X.509 / DER reader rows') { AttestRows.x509_ok? }
  t('attest: helpers (binding, node base64, JSON errors, JWS, hex claims)') do
    c = AtlasPca::Attest::Common
    b = { 'holder_pub' => 'h', 'grant_ref' => 'g', 'epoch' => 1, 'nonce' => 'n' }
    c.attestation_binding(b).bytesize == 64 && c.attestation_binding(b) == c.attestation_binding({ 'holderPub' => 'h', 'grantRef' => 'g', 'epoch' => 1, 'nonce' => 'n' }) &&
      c.attestation_challenge_sha256(b).bytesize == 32 &&
      ['holder_pub', 'grant_ref', 'nonce'].all? { |k| (c.attestation_binding(b.merge(k => '')) rescue $!.message) == "binding: #{{ 'holder_pub' => 'holderPub', 'grant_ref' => 'grantRef', 'nonce' => 'nonce' }[k]} required" } &&
      (c.attestation_binding(b.merge('epoch' => -1)) rescue $!.message) == 'binding: epoch must be a non-negative safe integer' &&
      c.node_b64decode('AQID') == "\x01\x02\x03".b && c.node_b64decode('AQ-_=junk') == c.node_b64decode('AQ+/') && c.node_b64decode('A') == ''.b &&
      (c.js_json_loads('') rescue $!.message) == 'Unexpected end of JSON input' &&
      (c.js_json_loads('not json') rescue $!.message) == %(Unexpected token 'o', "not json" is not valid JSON) &&
      (c.js_json_loads('{"a":1} x') rescue $!.message) == 'Unexpected non-whitespace character after JSON at position 8' &&
      c.js_json_loads('{"a":[1,2]}') == { 'a' => [1, 2] } &&
      c.decode_claim_bytes('0xAbCd') == "\xAB\xCD".b && c.decode_claim_bytes('QUJD') == 'ABC'.b && c.decode_claim_bytes('') .nil? &&
      c.js_number(' 0x10 ') == 16.0 && c.js_number('').zero? && c.js_number('1e3') == 1000.0 && c.js_number('abc').nan? &&
      c.big_int('12') == 12 && (c.big_int('1.5') rescue $!.message) == 'Cannot convert 1.5 to a BigInt' &&
      c.js_str(nil) == 'undefined' && c.js_str(5.0) == '5' && c.js_str(true) == 'true' &&
      (c.parse_jws('a.b', 'f') rescue $!.message) == 'f: a compact JWS has exactly three dot-separated parts' &&
      (c.parse_jws('', 'f') rescue $!.message) == 'f: empty token' && c.hex?('0aFf') && !c.hex?('0af') &&
      c.transform_binding('x', 'sha256').bytesize == 32 && c.transform_binding('x', 'sha512').bytesize == 64 && c.transform_binding('x', nil) == 'x'
  end
  t('attest: DER readers pin exact errors and CA role messages') do
    d = AtlasPca::Attest::Der
    err = lambda do |&f|
      f.call
      nil
    rescue StandardError => e
      e.message
    end
    err.call { d.read_tlv("\x30".b, 0) } == 'DER: truncated header' && err.call { d.read_tlv("\x1f\x00".b, 0) } == 'DER: multi-byte tags are not supported' &&
      err.call { d.read_tlv("\x30\x81\x05".b, 0) } == 'DER: non-minimal length (long form below 128)' && err.call { d.read_tlv("\x30\x05\x00".b, 0) } == 'DER: element overruns its parent' &&
      d.parse_der_time(0x17, '260101000000Z') == 1_767_225_600_000 && d.parse_der_time(0x17, '260231000000Z').nil? && d.parse_der_time(0x18, '20260101000000Z') == 1_767_225_600_000 &&
      d.parse_der_time(0x18, '2026010100000Z').nil? && d.days_from_civil(1970, 1, 1).zero? && d.days_in_month(2024, 2) == 29 && d.days_in_month(1900, 2) == 28
  end
end
