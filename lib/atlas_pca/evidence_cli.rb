# frozen_string_literal: true

require 'json'
require_relative 'evidence_verify'

# `pca-evidence`: the standalone replay verifier (port of cli.ts of @atlasauth/pca-evidence).
#
#   ruby -I lib -r atlas_pca/evidence_cli -e 'exit AtlasPca::EvidenceCli.main(ARGV)' -- verify <bundle.json> [--trust trust.json] [--json] [--allow-unpinned]
#   ... digest <bundle.json>
#
# Exit codes: 0 consistent AND attributed (every signing session-root key is pinned in `principals`; unverified findings are listed but
# do not fail); 1 at least one finding failed (wins over 3); 2 usage or parse error (including a malformed trust file); 3 consistent but
# NOT attributed (no pinned principal keys: the bundle may be fabricated by whoever made its keys; `--allow-unpinned` exits 0 and prints
# the keys to verify out of band). The trust file is JSON; ports (callables) cannot come from JSON: artifacts that need one are
# reported as unverified.
module AtlasPca
  module EvidenceCli
    USAGE = "usage: pca-evidence verify <bundle.json> [--trust trust.json] [--json] [--allow-unpinned]\n       pca-evidence digest <bundle.json>"
    TRUST_KEYS = %w[siteKeys principals sessionRootDigest minTier jitTier typedValues credentials canaryLabels oracleKeys judges labelKeys anchorGuardian acc].freeze

    module_function

    def read_json(path) = AtlasPca.parse_json(File.read(path, encoding: 'UTF-8'))

    # Runs the command line; returns the exit code. out / err are injectable callables.
    def main(argv, out = ->(s) { puts s }, err = ->(s) { warn s })
      cmd, *rest = argv.to_a
      unless %w[verify digest].include?(cmd)
        err.call(USAGE)
        return 2
      end
      file = nil
      trust_file = nil
      json = false
      allow_unpinned = false
      i = 0
      while i < rest.length
        a = rest[i]
        if a == '--json'
          json = true
        elsif a == '--allow-unpinned' && cmd == 'verify'
          allow_unpinned = true
        elsif a == '--trust' && cmd == 'verify'
          i += 1
          trust_file = rest[i]
          if trust_file.nil?
            err.call(USAGE)
            return 2
          end
        elsif !a.start_with?('--') && file.nil?
          file = a
        else
          err.call(USAGE)
          return 2
        end
        i += 1
      end
      if file.nil?
        err.call(USAGE)
        return 2
      end
      trust = {}
      begin
        bundle = read_json(file)
        unless trust_file.nil?
          t = read_json(trust_file)
          raise 'trust file must be a JSON object' unless t.is_a?(Hash)

          t.each_key { |k| raise %(unknown trust member "#{k}") unless TRUST_KEYS.include?(k) }
          ae = Evidence.acc_trust_error(t.fetch('acc', EvidenceVerify::UNDEF))
          raise ae if ae

          pe = Evidence.principals_trust_error(t.fetch('principals', EvidenceVerify::UNDEF))
          raise pe if pe

          trust = t
        end
      rescue StandardError => e
        err.call("pca-evidence: #{e.message}")
        return 2
      end
      if cmd == 'digest'
        bad = Evidence.bundle_shape_error(bundle)
        if bad
          err.call("pca-evidence: #{bad}")
          return 2
        end
        out.call(Evidence.evidence_digest(bundle))
        return 0
      end
      report = EvidenceVerify.verify_evidence_bundle(bundle, trust)
      unattributed = report['consistent'] && !report['attributed']
      keys = report['summary']['attribution']['keys_to_check']
      if json
        out.call(JSON.pretty_generate(report))
      else
        verdict = report['ok'] ? 'OK' : (unattributed ? 'CONSISTENT BUT NOT ATTRIBUTED' : 'FAILED')
        lines = ["bundle #{report['digest'] || '(malformed)'}: #{verdict}#{report['complete'] ? '' : ' (incomplete: some artifacts not verified here)'}"]
        report['findings'].each { |x| lines << "[#{x['status']}] #{x['code']}#{x['refs'].empty? ? '' : " #{x['refs'].join(' ')}"}: #{x['text']}" }
        lines << 'Proven:'
        report['summary']['proven'].each { |s| lines << "  - #{s}" }
        lines << 'Not proven:'
        report['summary']['not_proven'].each { |s| lines << "  - #{s}" }
        lines << "report #{report['report_digest']}"
        out.call(lines.join("\n"))
      end
      return 1 unless report['consistent']

      if unattributed
        if allow_unpinned
          err.call("pca-evidence: principal keys to verify out of band: #{keys.join(', ')}")
          return 0
        end
        err.call('pca-evidence: the bundle is internally consistent but NOT attributed to any known principal (no pinned "principals" in the trust file). ' \
                 "Keys to verify out of band: #{keys.join(', ')}. Pass --allow-unpinned to accept anyway.")
        return 3
      end
      report['ok'] ? 0 : 1
    end
  end
end
