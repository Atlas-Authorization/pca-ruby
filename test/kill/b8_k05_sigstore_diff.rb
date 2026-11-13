# frozen_string_literal: true
require 'base64'
require 'atlas_pca/sigstore_bundle'
# k05 offline Sigstore bundle verification (sigstore_bundle.rb, opt-in) against pca-attest-eat sigstore.ts: test-data/
# k05-sigstore.json.gz (tools/pca-audit/k05-oracles/sigstore-oracle.mts). Every trusted root is a parseTrustedRoot case (its
# summary compared); other cases name one as {"$root": id}, parsed here from the same JSON. Token / data / payload args are
# standard base64. A refusal's detail is compared exactly, except a reference "fail closed: <exception text>" (the host
# language's own exception message): there the Ruby detail must also be a fail-closed one. @suspect cases are reported only.
module MutationKill
  module K05Sigstore
    module_function

    def docs
      @docs ||= begin
        d = {}
        add = ->(c) { d[c['name'].sub(%r{\A[^/]+/}, '')] = c['args'][0] if c['fn'].start_with?('parseTrustedRoot') }
        if (g = K05::CACHE['k05-sigstore.json.gz'])
          g.each_value { |cs| cs.each(&add) }
        else
          K05.stream('k05-sigstore.json.gz', &add)
        end
        d
      end
    end

    def roots(ref)
      raise ArgumentError, 'bad root ref' unless ref.is_a?(Hash) && docs.key?(ref['$root'])

      AtlasPca.parse_trusted_root(docs[ref['$root']])
    end

    def summary(r)
      lg = ->(l) { { 'keyId' => Base64.strict_encode64(l.key_id), 'start' => l.valid.start, 'end' => l.valid.end_.to_f.finite? ? l.valid.end_ : nil, 'v2' => l.v2_name } }
      ca = ->(c) { { 'chain' => c.chain.length, 'start' => c.valid.start, 'end' => c.valid.end_.to_f.finite? ? c.valid.end_ : nil } }
      { 'tlogs' => r.tlogs.map(&lg), 'ctlogs' => r.ctlogs.map(&lg), 'cas' => r.cas.map(&ca), 'tsas' => r.tsas.map(&ca) }
    end

    def core(r) = r[:ok] ? { 'ok' => true, 'core' => r[:core] } : { 'ok' => false, 'code' => r[:code], 'detail' => r[:detail] }

    FNS = {
      'parseTrustedRoot' => ->(a, _) { summary(AtlasPca.parse_trusted_root(a[0])) },
      'verifySigstoreBundleCore' => ->(a, _) { core(AtlasPca.verify_sigstore_bundle_core(a[0], roots(a[1]))) },
      'verifySigstoreBundle' => ->(a, _) { AtlasPca.verify_sigstore_bundle(a[0], roots(a[1])) },
      'verifyRfc3161' => ->(a, _) { AtlasPca::SigstoreBundle.verify_rfc3161(Base64.decode64(a[0]), Base64.decode64(a[1]), roots(a[2]).tsas) },
      'dssePae' => ->(a, _) { { '$bytes' => AtlasPca.b64e(AtlasPca::SigstoreBundle.dsse_pae(a[0], Base64.decode64(a[1]))) } }
    }.freeze
    FAIL_CLOSED = 'fail closed: '
    CMP = {
      default: lambda do |got, out, c|
        got = K05.strkeys(got)
        if out.is_a?(Hash) && out['ok'] == false && out['detail'].is_a?(String) && out['detail'].start_with?(FAIL_CLOSED) &&
           got.is_a?(Hash) && got['detail'].is_a?(String) && got['detail'].start_with?(FAIL_CLOSED)
          got = got.merge('detail' => out['detail'])
        end
        K05::EXACT.call(got, out, c)
      end
    }.freeze
    SPEC = K05::Spec.new(file: 'k05-sigstore.json.gz', libs: %w[sigstore_bundle.rb], fns: FNS, cmp: CMP, title: 'sigstore')
  end
  K05.register(K05Sigstore::SPEC, K05Sigstore::FNS.keys)
  MutationKill.t('k05 sigstore differential (TS oracle): @suspect report') do
    next true if DiffUtil.skip?('sigstore_bundle.rb')

    K05.report_suspects(K05Sigstore::SPEC)
    true
  end
end
