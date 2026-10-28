# frozen_string_literal: true

# Vendor hardware-attestation verifiers for agent passports and PCActns, native counterpart of the vendor verifiers of
# @atlasauth/pca (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, GCP Confidential Space, NVIDIA GPU SPDM).
#
#   require 'atlas_pca/attest'
#   v = AtlasPca::Attest.verifier_from_config('amd-sev-snp', { 'family' => 'genoa', 'binding' => 'report-data',
#                                                              'policy' => { 'measurements' => [...] } })
#   AtlasPca.verify_passport(signed, issuers, now_ms, revoked: ..., default_verifier: v)
#
# `verifier_from_config(vendor, config)` builds a verifier from a JSON-serialisable configuration (the same schema the
# language-neutral conformance vectors use). The verifier's `verify(document, expected, now_ms)` answers
# {'ok', 'bound', 'reason', 'measured', 'hostAsserted'} and fails CLOSED: a missing pin, an empty measurement allowlist, an
# unverifiable chain or an unbound quote is `ok: false` with a reason, never a pass. Evidence is resolved by
# `resolve_evidence.call(document)` (default: document['evidence']) and is the wire object of the vendor: bytes as standard
# base64 strings (raw binary Strings are accepted too), PEM and JSON documents as strings. Needs only OpenSSL (stdlib).
require_relative 'attest/common'
require_relative 'attest/der'
require_relative 'attest/cert'
require_relative 'attest/amd'
require_relative 'attest/azure'
require_relative 'attest/gcp'
require_relative 'attest/intel'
require_relative 'attest/nvidia'

module AtlasPca
  module Attest
    VENDORS = %w[amd-sev-snp intel-tdx-dcap azure-maa gcp-confidential-space nvidia-gpu-spdm].freeze
    MISSING = Object.new.freeze

    module_function

    def attestation_binding(exp) = Common.attestation_binding(exp)

    def unb64(v)
      return v.b if v.is_a?(String) && v.encoding == Encoding::BINARY
      return Common.node_b64decode(v) if v.is_a?(String)

      raise JsTypeError, 'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an ' \
                         "Array-like Object. Received #{v.nil? ? 'null' : v.equal?(MISSING) ? 'undefined' : "type #{v.class.name.downcase}"}"
    end

    def opt_bytes(v)
      return Common.node_b64decode(v) if v.is_a?(String)

      nil
    end

    # The wire evidence of `vendor` as the verifier consumes it (base64 strings decoded to bytes); nil when there is none.
    def evidence_for(vendor, ev)
      return nil if ev.nil?

      out = {}
      case vendor
      when 'amd-sev-snp'
        out['report'] = unb64(ev['report']) if ev.key?('report')
        out['vcekDer'] = unb64(ev['vcekDer']) if ev.key?('vcekDer')
        out['askArkPem'] = ev['askArkPem'] if ev.key?('askArkPem')
        rd = opt_bytes(ev['runtimeData'])
        out['runtimeData'] = rd unless rd.nil?
      when 'intel-tdx-dcap'
        out['quote'] = unb64(ev['quote']) if ev.key?('quote')
        rd = opt_bytes(ev['runtimeData'])
        out['runtimeData'] = rd unless rd.nil?
        c = ev['collateral']
        if c.is_a?(Hash)
          out['collateral'] = {
            'tcbInfoJson' => c['tcbInfoJson'], 'tcbInfoIssuerChainPem' => c['tcbInfoIssuerChainPem'],
            'qeIdentityJson' => c['qeIdentityJson'], 'qeIdentityIssuerChainPem' => c['qeIdentityIssuerChainPem'],
            'pckCrlDer' => unb64(c.fetch('pckCrlDer', MISSING)), 'rootCrlDer' => unb64(c.fetch('rootCrlDer', MISSING))
          }
        end
      when 'nvidia-gpu-spdm'
        out['evidence'] = unb64(ev['evidence']) if ev.key?('evidence')
        out['certChainPem'] = ev['certChainPem'] if ev.key?('certChainPem')
        c = ev['collateral']
        if c.is_a?(Hash)
          bundle = { 'driverRimXml' => c['driverRimXml'], 'vbiosRimXml' => c['vbiosRimXml'] }
          bundle['crls'] = c['crls'].map { |x| unb64(x) } if c['crls'] && !c['crls'].empty?
          bundle['ocsp'] = c['ocsp'].map { |x| unb64(x) } if c['ocsp'] && !c['ocsp'].empty?
          out['collateral'] = bundle
        end
      when 'azure-maa', 'gcp-confidential-space'
        out['token'] = ev['token'] if ev.key?('token')
        out['jwks'] = ev['jwks'] if ev.key?('jwks')
      else
        raise AttestConstructError, "unknown attestation vendor #{Common.js_str(vendor)}"
      end
      out
    end

    # `identity_overrides`: after a successful verification the keys of the override replace the same keys of `measured`.
    class WithIdentity
      def initialize(inner, overrides)
        @inner = inner
        @ov = overrides
      end

      def verify(document, expected, now_ms)
        r = @inner.verify(document, expected, now_ms)
        return r unless r['ok'] && r['measured']

        r.merge('measured' => r['measured'].merge(@ov))
      end
    end

    def present(config, *keys) = keys.each_with_object({}) { |k, h| h[k] = config[k] if config.key?(k) }

    # Build the verifier of `vendor` from a JSON-serialisable `config`. Raises AttestConstructError when the configuration is
    # refused (accept-all, a missing pin or allowlist, an unknown mode).
    def verifier_from_config(vendor, config, resolve_evidence = nil)
      raise AttestConstructError, "unknown attestation vendor #{Common.js_str(vendor)}" unless VENDORS.include?(vendor)
      raise AttestConstructError, 'verifier_from_config: config must be an object' unless config.is_a?(Hash)

      resolve = resolve_evidence || ->(doc) { doc.is_a?(Hash) ? doc['evidence'] : nil }
      resolved = ->(doc) { evidence_for(vendor, resolve.call(doc)) }
      case vendor
      when 'amd-sev-snp'
        opts = present(config, 'family', 'binding', 'policy', 'clockSkewMs', 'trustAnchorArkSpkiSha384')
        opts['resolve_evidence'] = resolved
        v = AmdSnpVerifier.new(opts)
      when 'azure-maa'
        opts = present(config, 'trustedIssuers', 'trustAnchors', 'policy', 'clockSkewMs')
        opts['resolve_evidence'] = resolved
        v = AzureMaaVerifier.new(opts)
      when 'intel-tdx-dcap'
        opts = present(config, 'binding', 'policy', 'trustAnchorRootCaSpkiSha256', 'allowMissingCollateral')
        opts['resolve_evidence'] = resolved
        v = IntelDcapVerifier.new(opts)
      when 'nvidia-gpu-spdm'
        col = config['collateral']
        pol = config['policy'].is_a?(Hash) ? config['policy'] : {}
        nv = { 'rootSpkiSha256' => config['rootSpkiSha256'],
               'policy' => { 'measurements' => pol['measurements'].nil? ? {} : pol['measurements'] },
               'resolve_evidence' => resolved }
        nv['policy']['leafSubjectIncludes'] = pol['leafSubjectIncludes'] unless pol['leafSubjectIncludes'].nil?
        unless col.nil? || col == false
          hook_opts = col.is_a?(Hash) ? present(col, 'revocation', 'requireCrls', 'requireCrlIssuers', 'firmware') : {}
          hook_opts['rimRootSpkiSha256'] = col.is_a?(Hash) ? col['rimRootSpkiSha256'] : nil
          hook_opts['resolve'] = ->(_ids, evidence) { (evidence || {})['collateral'] }
          nv['postVerify'] = NvidiaCollateralHook.new(hook_opts)
        end
        v = NvidiaSpdmVerifier.new(nv)
      when 'gcp-confidential-space'
        opts = present(config, 'trustedIssuers', 'trustAnchors', 'policy', 'clockSkewMs')
        opts['resolve_evidence'] = resolved
        v = GcpConfidentialSpaceVerifier.new(opts)
      else
        raise AttestConstructError, "unknown attestation vendor #{Common.js_str(vendor)}"
      end
      ov = config['identity_overrides']
      ov && !ov.empty? ? WithIdentity.new(v, ov) : v
    end

    # Run one x509 unit row of the vectors: {'ok' => true, 'value' => ...} or {'ok' => false, 'error' => ...} (the exact reader message).
    def run_x509_vector(fn, inp)
      b = ->(x) { Common.node_b64decode(x) }
      case fn
      when 'read_cert_role_info' then { 'ok' => true, 'value' => Der.read_cert_role_info(b.call(inp['cert'])) }
      when 'parse_cert_extensions', 'parse_tbs_extensions'
        m = fn == 'parse_cert_extensions' ? Der.parse_cert_extensions(b.call(inp['cert'])) : Der.parse_tbs_extensions(b.call(inp['tbs']))
        { 'ok' => true, 'value' => m.map { |oid, e| { 'oid' => oid, 'critical' => e.critical, 'value' => e.value.unpack1('H*') } } }
      when 'tbs_of_certificate'
        { 'ok' => true, 'value' => Base64.strict_encode64(Der.tbs_of_certificate(b.call(inp['cert']))) }
      when 'unrecognised_critical_extension'
        { 'ok' => true, 'value' => Der.unrecognised_critical_extension(b.call(inp['cert']), inp['recognised']) }
      when 'check_chain_roles' then { 'ok' => true, 'value' => Der.check_chain_roles(inp['chain'].map { |x| b.call(x) }) }
      when 'der_validity_ms'
        lo, hi = Der.der_validity_ms(b.call(inp['cert']))
        { 'ok' => true, 'value' => { 'from' => lo, 'to' => hi } }
      when 'parse_der_time' then { 'ok' => true, 'value' => Der.parse_der_time(inp['tag'], inp['text']) }
      else { 'ok' => false, 'error' => "unknown x509 function #{fn}" }
      end
    rescue DerError, JsTypeError => e
      { 'ok' => false, 'error' => e.message }
    end

    # Run one (hydrated) vector row {vendor, config, evidence, now, expected_binding} through the native verifier.
    def run_attestation_vector(row)
      ev = row['evidence']
      begin
        verifier = verifier_from_config(row['vendor'], row['config'], ->(_doc) { ev })
      rescue StandardError => e # the factory refused the configuration
        return { 'construct_error' => e.message }
      end
      verifier.verify({}, row['expected_binding'], row['now'])
    end
  end
end
