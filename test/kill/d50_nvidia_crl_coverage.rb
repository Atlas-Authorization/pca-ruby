# frozen_string_literal: true

# NVIDIA CRL coverage default (PCA 0.5, user-approved fail-open fix): by default every non-root chain certificate that names a CRL
# distribution point must be covered by a verified CRL from its own issuer; before, ANY one fresh CRL satisfied the check, so a
# prover who supplied only the root's CRL never had its device / intermediate certificates checked. Reference:
# packages/pca/src/attest-nvidia-rim.ts (checkNvidiaChainRevocation, requireCrlFor). Certificates are built here (P-384, generated
# at load) with the helpers of c13_attest_nvidia.rb; every AtlasPca reference is resolved at call time.
# (c13_attest_nvidia.rb and c07_attest_common.rb are loaded before this file: alphabetical order)

module MutationKill
  module D50
    module_function

    def run? = C13.run?

    CDP = 'URI:http://crl.example.test/nvidia.crl'
    LEAF = 'GPU GH100 CDP leaf'
    ICA = 'NVIDIA CDP ICA'
    ROOT = 'NVIDIA CDP Root'

    def cdp(critical = false) = C13.ext('crlDistributionPoints', CDP, critical)

    # leaf <- ica <- root, the leaf and the ica naming a CDP
    def chain_cdp = @chain_cdp ||= [C13.cert(LEAF, ICA, C13.leaf_exts + [cdp]), C13.cert(ICA, ROOT, C13.ca_exts + [cdp]), C13.cert(ROOT, ROOT, C13.ca_exts)].map { |x| C13.lib_cert(x) }
    # leaf (CDP) <- ica (no CDP) <- root
    LEAF2 = 'GPU GH100 mixed leaf'
    ICA2 = 'NVIDIA mixed ICA'
    ROOT2 = 'NVIDIA mixed Root'
    def chain_mixed = @chain_mixed ||= [C13.cert(LEAF2, ICA2, C13.leaf_exts + [cdp]), C13.cert(ICA2, ROOT2, C13.ca_exts), C13.cert(ROOT2, ROOT2, C13.ca_exts)].map { |x| C13.lib_cert(x) }

    def check(chain, crls, *rest) = C13.nv.check_nvidia_chain_revocation(chain, crls, C13::NOW, *rest)
    def subj(cert) = cert.subject.gsub("\n", ', ')
    def miss(cert) = { 'ok' => false, 'reason' => "no verified CRL from the issuer of chain certificate '#{subj(cert)}'" }
    def ok(n) = { 'ok' => true, 'verifiedCrls' => n }
    def bad_index(i) = { 'ok' => false, 'reason' => "requireCrlFor index #{i} is not a non-root chain certificate" }
  end

  c = D50

  t('d50 nvidia: the default demands a CRL from the issuer of every chain certificate that names a CDP') do
    next true unless c.run?

    ch = c.chain_cdp
    root_crl = C13.crl(c::ROOT)
    ica_crl = C13.crl(c::ICA)
    C13.chk('the CDP is seen on the leaf and the ica, not the root', ch.map { |x| C13.nv.crl_distribution_point?(x) }, [true, true, false])
    # the exploit: only the root's CRL; the leaf and the ica were never checked
    C13.chk('root CRL only: the leaf has no CRL from its issuer', c.check(ch, [root_crl]), c.miss(ch[0]))
    C13.chk('root CRL only, default stated', c.check(ch, [root_crl], nil, 'cdp'), c.miss(ch[0]))
    C13.chk('ica CRL only: the ica has no CRL from the root', c.check(ch, [ica_crl]), c.miss(ch[1]))
    C13.chk('ica and root CRLs cover both', c.check(ch, [ica_crl, root_crl]), c.ok(2))
    C13.chk('order of the CRLs does not matter', c.check(ch, [root_crl, ica_crl]), c.ok(2))
    # unchanged: a revoked certificate still fails, a stale or foreign CRL still fails
    leaf_serial = C13.serial(c::LEAF)
    C13.chk('revoked leaf on the ica CRL', c.check(ch, [C13.crl(c::ICA, revoked: [leaf_serial]), root_crl]),
            { 'ok' => false, 'reason' => "chain certificate '#{c.subj(ch[0])}' is revoked" })
    C13.chk('stale ica CRL is rejected before coverage', c.check(ch, [C13.crl(c::ICA, nxt: 1_790_000_000), root_crl]),
            { 'ok' => false, 'reason' => 'CRL #0 rejected: CRL is stale (nextUpdate passed)' })
    # requireIssuers is additive: it is checked first, the coverage after it
    C13.chk('requireIssuers first', c.check(ch, [root_crl], ['Nobody']), { 'ok' => false, 'reason' => "no verified CRL issued by a certificate matching 'Nobody'" })
    C13.chk('requireIssuers met, coverage still demanded', c.check(ch, [root_crl], ['Root']), c.miss(ch[0]))
    true
  end

  t('d50 nvidia: all, none, an index list, and a chain without a CDP') do
    next true unless c.run?

    m = c.chain_mixed
    ica_crl = C13.crl(c::ICA2)
    root_crl = C13.crl(c::ROOT2)
    C13.chk('mixed chain: the CDP is on the leaf only', m.map { |x| C13.nv.crl_distribution_point?(x) }, [true, false, false])
    C13.chk('cdp: the ica CRL covers the leaf, the ica names no CDP', c.check(m, [ica_crl], nil, 'cdp'), c.ok(1))
    C13.chk('cdp is the default', c.check(m, [ica_crl]), c.ok(1))
    C13.chk('all: the ica has no CRL from the root', c.check(m, [ica_crl], nil, 'all'), c.miss(m[1]))
    C13.chk('all met', c.check(m, [ica_crl, root_crl], nil, 'all'), c.ok(2))
    C13.chk('none demands nothing', c.check(m, [root_crl], nil, 'none'), c.ok(1))
    C13.chk('root CRL only under cdp still misses the leaf', c.check(m, [root_crl]), c.miss(m[0]))
    C13.chk('index list met', c.check(m, [ica_crl], nil, [0]), c.ok(1))
    C13.chk('index list names an uncovered cert', c.check(m, [ica_crl], nil, [0, 1]), c.miss(m[1]))
    C13.chk('empty index list demands nothing', c.check(m, [root_crl], nil, []), c.ok(1))
    [[5, 5], [2, 2], [-1, -1], [3, 3]].each do |i, shown|
      C13.chk("index #{i} is not a non-root certificate", c.check(m, [ica_crl, root_crl], nil, [i]), c.bad_index(shown))
    end
    C13.chk('a float index is refused', c.check(m, [ica_crl], nil, [0.0]), c.bad_index(0.0))
    C13.chk('a string index is refused', c.check(m, [ica_crl], nil, ['0']), c.bad_index('0'))
    C13.chk('the first bad index decides', c.check(m, [ica_crl], nil, [0, 7, 9]), c.bad_index(7))
    # a CDP-less chain (the existing fixtures): nothing is demanded by the default
    plain = C13.chain3.map { |x| C13.lib_cert(x) }
    C13.chk('no CDP anywhere: the default demands nothing beyond the old checks', c.check(plain, [C13.crl(C13::ROOT)]), c.ok(1))
    C13.chk('no CDP anywhere: all still demands', c.check(plain, [C13.crl(C13::ROOT)], nil, 'all'), c.miss(plain[0]))
    true
  end

  t('d50 nvidia: the hook validates requireCrlFor and passes it only when CRLs are required') do
    next true unless c.run?

    n = C13.nv
    leaf = Struct.new(:subject)
    ids = { 'chip' => 'GH100', 'driver' => 'D', 'vbios' => 'V', 'driverVersion' => '595.71.05', 'vbiosVersion' => '96.00.9f.00.04' }
    okd = { 'ok' => true, 'rim' => { 'product' => 'GH100', 'version' => '595.71.05', 'golden' => { d: 1 } } }
    okv = { 'ok' => true, 'rim' => { 'product' => 'GH100', 'version' => '96.00.9F.00.04', 'golden' => { v: 1 } } }
    run = lambda do |opts, crls: nil|
      seen = []
      bundle = { 'driverRimXml' => 'DX', 'vbiosRimXml' => 'VX' }
      bundle = bundle.merge('crls' => crls) if crls
      stubs = { nvidia_rim_ids_for_report: ->(_r) { ids }, verify_nvidia_rim: ->(x, _p, _t) { x == 'DX' ? okd : okv },
                compare_report_to_rims: ->(_r, _d, _v) { { 'ok' => true } },
                check_nvidia_chain_revocation: ->(_ch, _cr, _now, _req, rf) { seen << rf; { 'ok' => true } } }
      MutationKill::Seam.with(n, stubs) do
        MutationKill::Seam.with(C13.a::Ocsp, { check_nvidia_chain_ocsp: ->(_ch, _o, _now) { { 'ok' => true } } }) do
          h = C13.a::NvidiaCollateralHook.new({ 'rimRootSpkiSha256' => ['p'], 'resolve' => ->(*) { bundle } }.merge(opts))
          r = h.call({ 'report' => :rep, 'leaf' => leaf.new('CN=NVIDIA GH100 Device'), 'chain' => :chain, 'nowMs' => C13::NOW, 'evidence' => :ev })
          [r, seen]
        end
      end
    end
    C13.chk('default is cdp', run.call({}), [nil, ['cdp']])
    C13.chk('all passed on', run.call({ 'requireCrlFor' => 'all' }), [nil, ['all']])
    C13.chk('list passed on', run.call({ 'requireCrlFor' => [0, 1] }), [nil, [[0, 1]]])
    C13.chk('both mode passes it', run.call({ 'revocation' => 'both', 'requireCrlFor' => 'all' }), [nil, ['all']])
    C13.chk('explicit crl mode passes it', run.call({ 'revocation' => 'crl', 'requireCrlFor' => 'all' }), [nil, ['all']])
    # CRLs supplied but not required: the supplied ones are enforced, no coverage is demanded
    C13.chk('ocsp mode with CRLs supplied: none', run.call({ 'revocation' => 'ocsp', 'requireCrlFor' => 'all' }, crls: ['c']), [nil, ['none']])
    C13.chk('requireCrls false with CRLs supplied: none', run.call({ 'requireCrls' => false, 'requireCrlFor' => 'all' }, crls: ['c']), [nil, ['none']])
    C13.chk('ocsp mode without CRLs: the CRL check does not run', run.call({ 'revocation' => 'ocsp' }), [nil, []])
    ce = ->(v) { C13.err_of { C13.a::NvidiaCollateralHook.new({ 'rimRootSpkiSha256' => ['p'], 'requireCrlFor' => v }) } }
    cls = 'AtlasPca::Attest::AttestConstructError'
    C13.chk('nil is the default', ce.call(nil), nil)
    C13.chk('cdp, all and index lists construct', [ce.call('cdp'), ce.call('all'), ce.call([]), ce.call([0, 3])], [nil, nil, nil, nil])
    C13.chk('none is not an option value', ce.call('none'), [cls, "nvidiaCollateralHook: malformed requireCrlFor 'none'"])
    C13.chk('a string', ce.call('x'), [cls, "nvidiaCollateralHook: malformed requireCrlFor 'x'"])
    C13.chk('a negative index', ce.call([0, -1]), [cls, "nvidiaCollateralHook: malformed requireCrlFor '0,-1'"])
    C13.chk('a float index', ce.call([1.5]), [cls, "nvidiaCollateralHook: malformed requireCrlFor '1.5'"])
    C13.chk('a number', ce.call(1), [cls, "nvidiaCollateralHook: malformed requireCrlFor '1'"])
    C13.chk('false is malformed', ce.call(false), [cls, "nvidiaCollateralHook: malformed requireCrlFor 'false'"])
    true
  end

  t('d50 nvidia: the verifier config forwards requireCrlFor to the hook') do
    f = ENV['MUT_FILE']
    next true unless f.nil? || f.empty? || %w[nvidia.rb attest.rb].include?(f)

    C07.stubbed do |seen|
      seen.clear
      C07.att.verifier_from_config('nvidia-gpu-spdm', { 'rootSpkiSha256' => ['ab'], 'collateral' => { 'rimRootSpkiSha256' => ['r'], 'requireCrlFor' => 'all' } })
      C13.chk('requireCrlFor forwarded', seen[:NvidiaCollateralHook].first.reject { |k, _| k == 'resolve' }, { 'rimRootSpkiSha256' => ['r'], 'requireCrlFor' => 'all' })
      seen.clear
      C07.att.verifier_from_config('nvidia-gpu-spdm', { 'rootSpkiSha256' => ['ab'], 'collateral' => { 'rimRootSpkiSha256' => ['r'] } })
      C13.chk('absent stays absent (the hook defaults to cdp)', seen[:NvidiaCollateralHook].first.reject { |k, _| k == 'resolve' }, { 'rimRootSpkiSha256' => ['r'] })
    end
    true
  end
end
