# frozen_string_literal: true

# Replays the TS-reference oracle of the pure SEV-SNP helpers (test-data/ref-sevsnp-helpers.json.gz, 248 cases): hex, PEM splitting, the full
# report parser, the P-384 key and the compact signature, the report signature, the policy gate, the default identity, the VCEK extension
# binding, the certificate helpers and the KDS VCEK fetch over an injected transport. Every fn has a handler and the totals are asserted.
# Encodings: {"$bytes": b64url}; {"$bigint": "<decimal>"} a u64 (a policy minimum is an Attest::BigU64, as the verifier takes it). A reason
# after "VCEK extensions malformed:" carries the DER reader's own text, so only the prefix is compared. The chain verifier and the genuine
# report path (RSA-4096 roots) are replayed with the real Milan / Genoa chains of the EAT corpus.
require_relative 'support/ref_oracle'
require 'atlas_pca/attest'
require 'minitest/autorun'

class TestRefSevsnpHelpers < Minitest::Test
  AM = AtlasPca::Attest::Amd
  CM = AtlasPca::Attest::Common
  BY_FN = Ref.load('sevsnp-helpers')
  NUM = { 'NaN' => Float::NAN, 'Infinity' => Float::INFINITY, '-Infinity' => -Float::INFINITY }.freeze
  MALFORMED = 'VCEK extensions malformed:'

  def self.conv(v)
    case v
    when Hash
      return AtlasPca::Attest::BigU64.new(Integer(v['$bigint'], 10)) if v.size == 1 && v.key?('$bigint')
      return NUM.fetch(v['$num']) if v.size == 1 && v.key?('$num')

      v.transform_values { |x| conv(x) }
    when Array then v.map { |x| conv(x) }
    else v
    end
  end

  def self.by(v) = { '$bytes' => Ref.b64e(v) }
  def self.big(v) = { '$bigint' => v.to_s }

  def self.parsed(b)
    r = AM.parse_sev_snp_report(b)
    { 'version' => r['version'], 'guest_svn' => r['guest_svn'], 'policy' => big(r['policy']), 'family_id' => by(r['family_id']),
      'image_id' => by(r['image_id']), 'vmpl' => r['vmpl'], 'signature_algo' => r['signature_algo'], 'current_tcb' => big(r['current_tcb']),
      'platform_info' => big(r['platform_info']), 'report_data' => by(r['report_data']), 'measurement' => by(r['measurement']),
      'host_data' => by(r['host_data']), 'id_key_digest' => by(r['id_key_digest']), 'author_key_digest' => by(r['author_key_digest']),
      'report_id' => by(r['report_id']), 'report_id_ma' => by(r['report_id_ma']), 'reported_tcb' => big(r['reported_tcb']),
      'cpuid_fam_id' => r['cpuid_fam_id'], 'cpuid_mod_id' => r['cpuid_mod_id'], 'cpuid_step' => r['cpuid_step'], 'chip_id' => by(r['chip_id']),
      'committed_tcb' => big(r['committed_tcb']), 'current_version' => r['current_version'], 'committed_version' => r['committed_version'],
      'launch_tcb' => big(r['launch_tcb']), 'launch_mit_vector' => big(r['launch_mit_vector']), 'current_mit_vector' => big(r['current_mit_vector']),
      'signature' => { 'r' => by(r['sig_r']), 's' => by(r['sig_s']) }, 'signed_len' => r['signed'].bytesize,
      'signed_sha256' => Digest::SHA256.hexdigest(r['signed']), 'raw_len' => r['raw'].bytesize }
  end

  def self.fetch_vcek(chip, tcb, op)
    opts = { product: op['product'], base_url: op['baseUrl'] }
    AM.fetch_vcek_from_kds(chip, tcb.v, fetch: false, **opts) if op['noFetch'] # no transport at all: refused
    seen = []
    transport = lambda do |url|
      seen << url
      { 'ok' => (200..299).cover?(op['status']), 'status' => op['status'], 'body' => op['body'] }
    end
    bytes = AM.fetch_vcek_from_kds(chip, tcb.v, fetch: transport, **opts)
    { 'url' => seen.first, 'bytes' => by(bytes) }
  end

  HANDLERS = {
    'toHex' => ->(b) { CM.to_hex(b) },
    'splitPemCertificates' => ->(pem) { AM.split_pem_certificates(pem) },
    'parseReport' => ->(b) { parsed(b) },
    'ecdsaP384PublicKey' => ->(b) { { 'point' => by(AM.ecdsa_p384_public_key(b).point) } },
    'signatureToCompact' => ->(sig) { by(AM.sev_snp_signature_to_compact(sig)) },
    'verifyReportSignature' => ->(b, k) { AM.verify_sev_snp_report_signature(AM.parse_sev_snp_report(b), AM.ecdsa_p384_public_key(k)) },
    'checkPolicy' => ->(b, pol) { AM.check_sev_snp_policy(AM.parse_sev_snp_report(b), pol) },
    'deriveIdentity' => ->(b, w) { AM.make_default_derive_identity(w).call(AM.parse_sev_snp_report(b)) },
    'fetchVcek' => ->(chip, tcb, op) { fetch_vcek(chip, tcb, op) },
    'extractTbsCertificate' => ->(c) { by(AM.extract_tbs_certificate(c)) },
    'extractVcekPublicKey' => lambda { |c|
      r = AM.extract_vcek_public_key(c)
      { 'point' => by(r['key'].point), 'tbs' => by(r['tbs']) }
    },
    'checkVcekReportBinding' => ->(tbs, rep) { AM.check_vcek_report_binding(tbs, AM.parse_sev_snp_report(rep)) },
    'constants' => lambda {
      { 'SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384' => AM::SIG_ALGO_ECDSA_P384_SHA384, 'SEV_SNP_POLICY_DEBUG_BIT' => big(AM::POLICY_DEBUG_BIT),
        'AMD_MILAN_ARK_SPKI_SHA384' => AM::ARK_SPKI_SHA384['milan'] }
    }
  }.freeze

  TOTALS = { 'toHex' => 4, 'splitPemCertificates' => 15, 'parseReport' => 17, 'ecdsaP384PublicKey' => 11, 'signatureToCompact' => 10,
             'verifyReportSignature' => 13, 'checkPolicy' => 57, 'deriveIdentity' => 8, 'fetchVcek' => 14, 'extractTbsCertificate' => 16,
             'extractVcekPublicKey' => 7, 'checkVcekReportBinding' => 75, 'constants' => 1 }.freeze

  def self.same?(got, out)
    return got.is_a?(String) && got.start_with?(MALFORMED) if out.is_a?(String) && out.start_with?(MALFORMED)

    Ref.canon(got) == Ref.canon(out)
  end

  def test_every_fn_of_the_corpus_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 248, BY_FN.values.sum(&:length)
  end

  HANDLERS.each do |fn, handler|
    define_method("test_replay_#{fn}") do
      k = self.class
      ran = Ref.run(self, BY_FN.fetch(fn), ->(*args) { handler.call(*args.map { |a| k.conv(a) }) }, compare: ->(got, out, _c) { k.same?(got, out) })
      assert_equal TOTALS.fetch(fn), ran
    end
  end
end
