# frozen_string_literal: true
# The strict chain profile (x509-strict.ts:266) at every chain site: attest-azure-maa.ts:395, :411, attest-gcp-confidential-space.ts:384,
# attest-nvidia-spdm.ts:224. Certificates are built here (P-384, valid at NOW); no vector carries a role violation under a real root.
require 'atlas_pca/attest'
module MutationKill
  module StrictChain
    module_function

    NOW = 1_800_000_000_000
    # resolved per call: the oracle reloads the library for each mutant
    def a = AtlasPca::Attest

    def key(n) = (@keys ||= {})[n] ||= OpenSSL::PKey::EC.generate('secp384r1')
    def ext(sn, v, critical = true) = OpenSSL::X509::ExtensionFactory.new.create_extension(sn, v, critical)
    def crit(oid = '1.2.3.4') = OpenSSL::X509::Extension.new(oid, OpenSSL::ASN1::Null.new(nil).to_der, true)
    def ca(v = 'CA:TRUE') = ext('basicConstraints', v)
    def ku(v = 'keyCertSign,cRLSign') = ext('keyUsage', v)

    def cert(name, signer, exts)
      c = OpenSSL::X509::Certificate.new
      c.version = 2
      c.serial = OpenSSL::BN.new(name.sum + 1)
      c.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
      c.issuer = OpenSSL::X509::Name.parse("/CN=#{signer}")
      c.public_key = key(name)
      c.not_before = Time.at(1_700_000_000)
      c.not_after = Time.at(1_900_000_000)
      exts.each { |e| c.add_extension(e) }
      c.sign(key(signer), OpenSSL::Digest.new('SHA384'))
    end

    # [leaf, intermediate, root], each DER, leaf first
    def chain(leaf: [ca('CA:FALSE')], inter: [ca, ku], root: [ca, ku])
      [cert('leaf', 'inter', leaf), cert('inter', 'root', inter), cert('root', 'root', root)]
    end

    def der(certs) = certs.map(&:to_der)
    def b64(certs) = der(certs).map { |d| [d].pack('m0') }
    def spki(c) = a::Cert.new(c.to_der).spki_sha('sha256')
    def pem(certs) = certs.map(&:to_pem).join("\n")
    def azure(certs, anchors) = a::Azure.verify_x5c_chain(b64(certs), anchors, NOW)
    def gcp(certs) = a::Gcp.verify_jwk_x5c_chain(b64(certs), { 'trustedKeySpki' => [spki(certs[-1])] }, NOW, 0)
    def nvidia(certs) = a::Nvidia.verify_nvidia_device_chain(pem(certs), [a::Cert.new(certs[-1].to_der).spki_sha256], NOW)
  end

  t('strict_chain_error: every role and critical-extension refusal, first one wins, with the reference text') do
    s = StrictChain
    e = ->(**kw) { AtlasPca::Attest::Der.strict_chain_error(s.der(s.chain(**kw))) }
    e.().nil? &&
      e.(leaf: [s.ca('CA:FALSE'), s.ext('extendedKeyUsage', 'serverAuth')]).nil? &&
      e.(leaf: [s.ca]) == 'leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)' &&
      e.(inter: [s.ca('CA:FALSE'), s.ku]) == 'issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)' &&
      e.(inter: [s.ku]) == 'issuer certificate at depth 1 has no BasicConstraints (not a CA)' &&
      e.(inter: [s.ca, s.ku('digitalSignature')]) == 'issuer certificate at depth 1 keyUsage lacks keyCertSign' &&
      e.(root: [s.ca('CA:TRUE,pathlen:0'), s.ku]) == 'issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)' &&
      e.(leaf: [s.ca('CA:FALSE'), s.crit]) == 'certificate at depth 0 has an unrecognised critical extension 1.2.3.4' &&
      e.(inter: [s.ca, s.ku, s.crit]) == 'certificate at depth 1 has an unrecognised critical extension 1.2.3.4' &&
      e.(root: [s.ca, s.ku, s.crit]) == 'certificate at depth 2 has an unrecognised critical extension 1.2.3.4' &&
      e.(leaf: [s.ca, s.crit]).start_with?('leaf certificate asserts') &&
      AtlasPca::Attest::Der.strict_chain_error(['junk'.b]).start_with?('certificate extension parse failed: ') &&
      AtlasPca::Attest::Der.strict_chain_error([s.der(s.chain)[0], 'junk'.b]).start_with?('certificate extension parse failed: ')
  end

  t('strict_chain_error: a critical extension only the chain profile accepts (EKU) is still refused by the PCK default') do
    s = StrictChain
    d = s.cert('leaf', 'inter', [s.ext('extendedKeyUsage', 'serverAuth')]).to_der
    AtlasPca::Attest::Der.unrecognised_critical_extension(d) == '2.5.29.37' && AtlasPca::Attest::Der.unrecognised_critical_extension(d, AtlasPca::Attest::Der::CHAIN_CRITICAL_OK).nil?
  end

  t('MAA x5c: the profile runs on the slice up to an in-chain anchor; a chain to an external root is checked whole') do
    s = StrictChain
    root_pin = ->(c) { { 'rootSpkiSha256' => [s.spki(c[-1])] } }
    good = s.chain
    bad = s.chain(inter: [s.ca('CA:FALSE'), s.ku])
    wbad = 'x5c chain profile: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)'
    # above the anchor nothing is read: a root with a bad role above a pinned intermediate does not matter
    high = s.chain(root: [s.ca('CA:FALSE')])
    ext_root = { 'rootCertsPem' => [good[2].to_pem] }
    s.azure(good, root_pin.(good))['ok'] == true && s.azure(bad, root_pin.(bad)) == { 'ok' => false, 'reason' => wbad } &&
      s.azure(high, { 'rootSpkiSha256' => [s.spki(high[1])] })['ok'] == true && s.azure(high, root_pin.(high))['ok'] == false &&
      s.azure(good[0, 2], ext_root)['ok'] == true &&
      s.azure(bad[0, 2], ext_root) == { 'ok' => false, 'reason' => wbad } &&
      s.azure(s.chain(leaf: [s.crit])[0, 2], ext_root)['reason'] == 'x5c chain profile: certificate at depth 0 has an unrecognised critical extension 1.2.3.4'
  end

  t('GCP x5c: the profile runs before the anchors, so a pinned key in a bad chain is refused') do
    s = StrictChain
    s.gcp(s.chain).nil? &&
      s.gcp(s.chain(inter: [s.ca('CA:FALSE'), s.ku])) == 'x5c chain profile: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)' &&
      s.gcp(s.chain(leaf: [s.ca])) == 'x5c chain profile: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)' &&
      s.gcp(s.chain(root: [s.ca, s.ku, s.crit])) == 'x5c chain profile: certificate at depth 2 has an unrecognised critical extension 1.2.3.4'
  end

  t('GCP: a JWK key beside a genuine x5c chain must be the leaf key, under either anchor kind (TS 365d0e8ec)') do
    s = StrictChain
    good = s.chain
    jwk = lambda do |k|
      pt = k.public_key.to_octet_string(:uncompressed)
      enc = ->(b) { [b].pack('m0').tr('+/', '-_').delete('=') }
      { 'kid' => 'k', 'kty' => 'EC', 'crv' => 'P-384', 'x' => enc.(pt[1, 48]), 'y' => enc.(pt[49, 48]), 'x5c' => s.b64(good) }
    end
    res = ->(j, a) { s.a::Gcp.resolve_trusted_signing_key({ 'kid' => 'k', 'alg' => 'ES384' }, { 'keys' => [j] }, a, s::NOW, 0) }
    forged = jwk.(s.key('attacker'))
    honest = jwk.(s.key('leaf'))
    why = 'signing key not trusted: the JWK key is not the key of its x5c leaf'
    [{ 'rootCertsPem' => [good[2].to_pem] }, { 'trustedKeySpki' => [s.spki(good[2])] }].all? do |a|
      res.(forged, a) == { 'reason' => why } && res.(honest, a).key?('key') && !res.(honest, a).key?('reason') &&
        res.({ 'kid' => 'k', 'x5c' => s.b64(good) }, a).key?('key')
    end
  end

  t('NVIDIA device chain: the profile runs after the links, before the root pin') do
    s = StrictChain
    n = ->(**kw) { s.nvidia(s.chain(**kw)) }
    n.()['ok'] == true &&
      n.(leaf: [s.ca])['reason'] == 'device chain profile: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)' &&
      n.(inter: [s.ca, s.ku('digitalSignature')])['reason'] == 'device chain cert #1 issues a certificate but is not a CA' && # x509.ca is false without keyCertSign
      n.(root: [s.ca('CA:TRUE,pathlen:0'), s.ku])['reason'] == 'device chain profile: issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)' &&
      n.(leaf: [s.crit])['reason'] == 'device chain profile: certificate at depth 0 has an unrecognised critical extension 1.2.3.4' &&
      AtlasPca::Attest::Nvidia.verify_nvidia_device_chain(s.pem(s.chain(leaf: [s.crit])), [], s::NOW)['reason'].start_with?('device chain profile:')
  end

  t('NVIDIA firmware policy: {} is a policy (an unparseable reported version is refused), only nil / false are none') do
    c = ->(fw) { AtlasPca::Attest::Nvidia.compile_firmware_policy(fw) }
    ids = { 'driverVersion' => 'x', 'vbiosVersion' => '1' }
    c.({}).call(ids) == "driver version 'x' in the GPU report is not parseable" && c.(nil).call(ids).nil? && c.(false).call(ids).nil?
  end
end
