# frozen_string_literal: true

# PCA 0.5 hardening H9 / H10 / H11: vendor verifier configuration is typed. A present non-null value of the wrong type is a
# constructor error, never silently read as "no policy" (NVIDIA collateral / firmware / leafSubjectIncludes / deny lists /
# requireCrlIssuers, the policy allowlists of AMD / Intel / Azure, Intel policy.collateral). H12 (Intel non-object
# evidence.collateral under allowMissingCollateral) is already refused by the Ruby verifier (c11 pins it).

module MutationKill
  module E03
    module_function

    GATE = %w[nvidia.rb amd.rb intel.rb azure.rb attest.rb].freeze

    def skip?
      f = ENV['MUT_FILE']
      !(f.nil? || f.empty? || GATE.include?(f))
    end

    def a
      AtlasPca::Attest
    end

    # [class name, message] of the constructor error, nil when the block builds
    def err
      yield
      nil
    rescue StandardError => e
      [e.class.name, e.message]
    end

    CLS = 'AtlasPca::Attest::AttestConstructError'

    def refused(msg)
      [CLS, msg]
    end
    M96 = ('ab' * 48).freeze
  end

  t('e03 H9 nvidia: collateral must be an object (nil / false build, {} reaches the hook pin check)') do
    next true if E03.skip?

    a = E03.a
    cfg = ->(col) { { 'rootSpkiSha256' => ['ab'], 'policy' => { 'measurements' => { '1' => 'aa' } }, 'collateral' => col } }
    want = E03.refused('createNvidiaSpdmVerifier: collateral must be an object')
    ok = ['required', 5, [], true].all? { |col| E03.err { a.verifier_from_config('nvidia-gpu-spdm', cfg.call(col)) } == want }
    ok && [nil, false].all? { |col| E03.err { a.verifier_from_config('nvidia-gpu-spdm', cfg.call(col)) }.nil? } &&
      E03.err { a.verifier_from_config('nvidia-gpu-spdm', cfg.call({})) } == E03.refused('nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root')
  end

  t('e03 H9 nvidia: collateral.firmware must be an object, through the config and the hook') do
    next true if E03.skip?

    a = E03.a
    want = E03.refused('nvidiaCollateralHook: firmware must be an object')
    cfg = ->(fw) { { 'rootSpkiSha256' => ['ab'], 'policy' => { 'measurements' => { '1' => 'aa' } }, 'collateral' => { 'rimRootSpkiSha256' => ['p'], 'firmware' => fw } } }
    hook = ->(fw) { a::NvidiaCollateralHook.new({ 'rimRootSpkiSha256' => ['p'], 'firmware' => fw }) }
    ['x', 5, [], true].all? do |fw|
      E03.err { a.verifier_from_config('nvidia-gpu-spdm', cfg.call(fw)) } == want && E03.err { hook.call(fw) } == want &&
        E03.err { a::Nvidia.compile_firmware_policy(fw) } == want
    end && [nil, false, {}].all? { |fw| E03.err { hook.call(fw) }.nil? }
  end

  t('e03 H9 nvidia: firmware minimum versions are strings that parse') do
    next true if E03.skip?

    n = E03.a::Nvidia
    m = ->(k, v) { E03.err { n.compile_firmware_policy({ k => v }) } }
    m.call('minDriverVersion', 535) == E03.refused("nvidiaCollateralHook: malformed minDriverVersion '535'") &&
      m.call('minVbiosVersion', 5) == E03.refused("nvidiaCollateralHook: malformed minVbiosVersion '5'") &&
      m.call('minDriverVersion', 'x') == E03.refused("nvidiaCollateralHook: malformed minDriverVersion 'x'") &&
      m.call('minDriverVersion', '535.104').nil? && m.call('minVbiosVersion', '96.00.9f').nil? && m.call('minDriverVersion', '').nil?
  end

  t('e03 H9 nvidia: deny lists are arrays of strings that parse') do
    next true if E03.skip?

    n = E03.a::Nvidia
    m = ->(k, v) { E03.err { n.compile_firmware_policy({ k => v }) } }
    m.call('denyDriverVersions', ['535.1', 5]) == E03.refused("nvidiaCollateralHook: malformed denyDriverVersions entry '5'") &&
      m.call('denyVbiosVersions', ['96', 7]) == E03.refused("nvidiaCollateralHook: malformed denyVbiosVersions entry '7'") &&
      m.call('denyDriverVersions', '535.1') == E03.refused('nvidiaCollateralHook: denyDriverVersions must be an array') &&
      m.call('denyVbiosVersions', 'x') == E03.refused('nvidiaCollateralHook: denyVbiosVersions must be an array') &&
      m.call('denyDriverVersions', { 'a' => '1' }) == E03.refused('nvidiaCollateralHook: denyDriverVersions must be an array') &&
      m.call('denyDriverVersions', ['535.1']).nil? && m.call('denyVbiosVersions', []).nil? && m.call('denyDriverVersions', nil).nil?
  end

  t('e03 H9 nvidia: requireCrlIssuers lists only strings (the requireCrlFor check of the hook is kept)') do
    next true if E03.skip?

    a = E03.a
    h = ->(o) { E03.err { a::NvidiaCollateralHook.new({ 'rimRootSpkiSha256' => ['p'] }.merge(o)) } }
    want = E03.refused('nvidiaCollateralHook: requireCrlIssuers must list only strings')
    h.call({ 'requireCrlIssuers' => 'NVIDIA GH100' }) == want && h.call({ 'requireCrlIssuers' => ['A', 1] }) == want &&
      h.call({ 'requireCrlIssuers' => [nil] }) == want && h.call({ 'requireCrlIssuers' => {} }) == want &&
      h.call({ 'requireCrlIssuers' => ['A', 'B'] }).nil? && h.call({ 'requireCrlIssuers' => [] }).nil? && h.call({ 'requireCrlIssuers' => nil }).nil? &&
      h.call({ 'requireCrlFor' => 'bogus' }) == E03.refused("nvidiaCollateralHook: malformed requireCrlFor 'bogus'")
  end

  t('e03 H9 nvidia: policy.leafSubjectIncludes must be a string') do
    next true if E03.skip?

    a = E03.a
    v = ->(inc) { E03.err { a::NvidiaSpdmVerifier.new({ 'rootSpkiSha256' => ['ab'], 'policy' => { 'measurements' => { '1' => 'aa' }, 'leafSubjectIncludes' => inc } }) } }
    want = E03.refused('createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string')
    [5, [], ['GPU'], true, {}].all? { |inc| v.call(inc) == want } && ['GPU', '', nil].all? { |inc| v.call(inc).nil? } &&
      E03.err { a.verifier_from_config('nvidia-gpu-spdm', { 'rootSpkiSha256' => ['ab'], 'policy' => { 'measurements' => { '1' => 'aa' }, 'leafSubjectIncludes' => 5 } }) } == want
  end

  t('e03 H10 amd: policy.measurements / hostData / chipIds are arrays of strings') do
    next true if E03.skip?

    a = E03.a
    v = ->(pol) { E03.err { a::AmdSnpVerifier.new({ 'family' => 'genoa', 'binding' => 'report-data', 'policy' => { 'measurements' => ['aa'] }.merge(pol) }) } }
    ok = %w[hostData chipIds].all? do |k|
      msg = E03.refused("createAmdSnpVerifier: policy.#{k} must be an array of strings")
      ['aa', ['aa', 1], 5, {}, false].all? { |x| v.call({ k => x }) == msg } && [['aa'], [], nil].all? { |x| v.call({ k => x }).nil? }
    end
    ok && v.call({ 'measurements' => ['aa', 1] }) == E03.refused('createAmdSnpVerifier: policy.measurements must be an array of strings') && v.call({}).nil?
  end

  t('e03 H10 intel: policy.fmspcs / rtmrs are arrays of strings') do
    next true if E03.skip?

    a = E03.a
    v = ->(pol) { E03.err { a::IntelDcapVerifier.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [E03::M96] }.merge(pol) }) } }
    %w[fmspcs rtmrs].all? do |k|
      msg = E03.refused("createIntelDcapVerifier: policy.#{k} must be an array of strings")
      ['aa', ['aa', 1], 5, {}, false, ''].all? { |x| v.call({ k => x }) == msg } && [['aa'], [], nil].all? { |x| v.call({ k => x }).nil? }
    end
  end

  t('e03 H10 azure: every allowlist is an array of strings') do
    next true if E03.skip?

    a = E03.a
    v = lambda do |pol|
      E03.err { a::AzureMaaVerifier.new({ 'trustedIssuers' => ['https://i'], 'trustAnchors' => { 'rootSpkiSha256' => ['aa'] }, 'policy' => { 'sevSnpMeasurements' => ['ab'] }.merge(pol) }) }
    end
    ok = %w[tdxMrtds sevSnpHostData tdxRtmrs tdxAllowedTcbStatuses].all? do |k|
      msg = E03.refused("createAzureMaaVerifier: policy.#{k} must be an array of strings")
      ['aa', ['aa', 1], 5, {}, false].all? { |x| v.call({ k => x }) == msg } && [['aa'], [], nil].all? { |x| v.call({ k => x }).nil? }
    end
    ok && v.call({ 'sevSnpMeasurements' => ['ab', 2], 'tdxMrtds' => ['cd'] }) == E03.refused('createAzureMaaVerifier: policy.sevSnpMeasurements must be an array of strings') &&
      v.call({}).nil?
  end

  t('e03 H11 intel: policy.collateral must be an object') do
    next true if E03.skip?

    a = E03.a
    v = ->(col) { E03.err { a::IntelDcapVerifier.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [E03::M96], 'collateral' => col } }) } }
    want = E03.refused('createIntelDcapVerifier: policy.collateral must be an object')
    ['x', 5, [], true, false, 0, ''].all? { |col| v.call(col) == want } &&
      [nil, {}, { 'minTcbEvaluationDataNumber' => 7 }].all? { |col| v.call(col).nil? } &&
      E03.err { a::IntelDcapVerifier.new({ 'binding' => 'report-data', 'policy' => { 'mrtds' => [E03::M96] } }) }.nil?
  end
end
