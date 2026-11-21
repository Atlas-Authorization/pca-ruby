# frozen_string_literal: true

# Replays the TS-reference oracle of the NVIDIA GPU confidential-computing attestation modules (test-data/ref-attest-nvidia.json.gz, 467 cases, and
# ref-attest-nvidia-rim.json.gz, 163 cases: the same generator): the SPDM transcript parse (the real H100 / own H100 / two GB100 captures with
# byte-level mutations and forged transcripts), the device chain (the real chains and forged PKIs), the report signature, the PCA challenge, RIM
# verification (XMLDSig over C14N 1.1, 108 variants), the RIM ids and golden comparison, CRL revocation, the collateral hook, the OCSP request,
# response and chain policy, the ASN.1 time check and the guarded fetch helpers over a scripted transport. Every fn has a handler and the totals are
# asserted. Encodings: {"$blob": id} a string over 400 characters held in the corpus's blob table (hydrated in the arguments AND the results);
# {"$bytes": b64url}; a certificate is summarised as {subject, issuer, serial, notBefore, notAfter, spkiSha256, rawSha256, ca}; a RIM as {tagId, product,
# version, golden (ascending index), signerSubject}. A reason with the platform's own text ('error:...' from OpenSSL, 'OCSP response rejected: ...')
# compares by presence only.
require_relative 'support/ref_oracle'
require 'atlas_pca/attest_nvidia'
require 'minitest/autorun'

class TestRefAttestNvidia < Minitest::Test
  N = AtlasPca::AttestNvidia
  LIB = /\Aerror:[0-9A-Fa-f]{8}:|\AThe first argument|\AOCSP response rejected:|\ARIM: verification error \(fail closed\): (?:\[xmldom|Cannot read properties)/

  def self.load(name)
    txt = Zlib::GzipReader.open(File.join(Ref::DATA, "ref-#{name}.json.gz"), &:read).force_encoding('UTF-8')
    d = AtlasPca::JsonParser.new(txt, true, true, json_text: true).parse_document
    blobs = d['blobs']
    hyd = lambda do |x|
      case x
      when Array then x.map { |e| hyd.call(e) }
      when Hash then x.keys == ['$blob'] ? blobs.fetch(x['$blob']) : x.to_h { |k, v| [k, hyd.call(v)] }
      else x
      end
    end
    cases = d['cases'].map { |c| c.merge('args' => hyd.call(c['args']), 'out' => hyd.call(c['out'])) }
    Ref.unseed({ 'cases' => cases })['cases'].group_by { |c| c['fn'] }
  end

  BY_FN = load('attest-nvidia')
  RIM_BY_FN = load('attest-nvidia-rim')

  def self.by(v) = { '$bytes' => Ref.b64e(v) }
  def self.sha(b) = Digest::SHA256.hexdigest(b)
  def self.summary(c) = N.cert_summary(c)

  def self.report_summary(r)
    rq = r['request']
    { 'request' => { 'version' => rq['version'], 'code' => rq['code'], 'param1' => rq['param1'], 'param2' => rq['param2'], 'nonce' => by(rq['nonce']), 'slot' => rq['slot'] },
      'response' => { 'version' => r['response_version'], 'code' => r['response_code'], 'numBlocks' => r['num_blocks'],
                      'measurements' => r['measurements'].map { |m| { 'index' => m['index'], 'valueType' => m['valueType'], 'digest' => by(m['digest']) } },
                      'responderNonce' => by(r['responder_nonce']), 'opaque' => r['opaque'].sort.to_h { |k, v| [k.to_s, by(v)] }, 'signature' => by(r['signature']) },
      'signedBytesLength' => r['signedBytes'].bytesize, 'signedBytesSha256' => sha(r['signedBytes']) }
  end

  def self.rim_summary(rim)
    { 'tagId' => rim['tagId'], 'product' => rim['product'], 'version' => rim['version'], 'golden' => rim['golden'].values.sort_by { |g| g['index'] },
      'signerSubject' => rim['signerSubject'] }
  end

  def self.rim_from(sum) = sum.merge('golden' => sum['golden'].to_h { |g| [g['index'], g] })

  def self.chain_result(pem, pins, now)
    r = N.verify_nvidia_device_chain(pem, pins, now)
    r['ok'] ? { 'ok' => true, 'leaf' => summary(r['leaf']), 'chain' => r['chain'].map { |c| summary(c) } } : r
  end

  def self.rim_result(xml, o)
    r = N.verify_nvidia_rim(xml, rim_root_spki_sha256: o['rimRootSpkiSha256'], now_ms: o['nowMs'])
    r['ok'] ? { 'ok' => true, 'rim' => rim_summary(r['rim']) } : r
  end

  # the scripted transport of a case (the reference's Response stand-in) and its request log
  def self.respond(r)
    raise r['$throws'] if r['$throws']

    body = r['body']
    bytes = if r['bodyBytes'] then r['bodyBytes']
            elsif body.is_a?(Hash) && body.key?('$text') then body['$text'].b
            else JSON.generate(body).b
            end
    status = r.fetch('status', 200)
    { 'ok' => status >= 200 && status < 300, 'status' => status, 'body' => bytes }
  end

  def self.transport(response, log)
    lambda do |url, init|
      entry = { 'url' => url, 'method' => init['method'] || 'GET', 'contentType' => init.dig('headers', 'content-type') }
      entry['bodyBytes'] = init['body'].bytesize if init['body']
      log << entry
      respond(response)
    end
  end

  def self.fetched(c)
    log = []
    out = begin
      { 'ok' => true }.merge(yield(transport(c['response'], log)))
    rescue StandardError => e
      { 'ok' => false, 'error' => e.message }
    end
    out.merge('requests' => log)
  end

  def self.revocation(pem, crls, now, req_issuers, req_for)
    N.check_nvidia_chain_revocation(N.parse_pem_chain(pem), crls, now, req_issuers, req_for)
  end

  def self.ocsp_verify(der, o)
    chain = N.parse_pem_chain(o['chainPem'])
    N.verify_nvidia_ocsp_response(der, cert: chain[o['certIndex']], issuer: chain[o['issuerIndex'] || o['certIndex'] + 1], chain: chain, now_ms: o['nowMs'], max_age_ms: o['maxAgeMs'],
                                       expected_nonce: o['expectedNonce'], clock_skew_ms: o['clockSkewMs'])
  end

  def self.ocsp_chain(pem, responses, now, o)
    N.check_nvidia_chain_ocsp(N.parse_pem_chain(pem), responses, now, require_good: o['requireGood'], max_age_ms: o['maxAgeMs'], clock_skew_ms: o['clockSkewMs'],
                                                                      expected_nonces: o['expectedNonces'])
  end

  def self.collateral(c)
    opts = c['opts'].merge('resolve' => ->(_ids, _ev) { c['bundle'] })
    hook = N.nvidia_collateral_hook(opts)
    chain = N.parse_pem_chain(c['chainPem'])
    { 'value' => hook.call({ 'report' => N.parse_nvidia_spdm_evidence(c['evidence']), 'chain' => chain, 'leaf' => chain[0], 'nowMs' => c['nowMs'],
                             'evidence' => c['evidence'] }) }
  end

  HANDLERS = {
    'constants' => lambda {
      { 'NVIDIA_SPDM_SUITE' => N::NVIDIA_SPDM_SUITE, 'NVIDIA_OPAQUE' => N::NVIDIA_OPAQUE, 'NVIDIA_RIM_BASE_URL' => N::NVIDIA_RIM_BASE_URL,
        'NVIDIA_GH100_CRL_URLS' => N::NVIDIA_GH100_CRL_URLS, 'NVIDIA_GB100_CRL_URLS' => N::NVIDIA_GB100_CRL_URLS, 'NVIDIA_OCSP_URL' => N::NVIDIA_OCSP_URL,
        'NVIDIA_OCSP_DEFAULT_MAX_AGE_MS' => N::NVIDIA_OCSP_DEFAULT_MAX_AGE_MS }
    },
    'parseReport' => ->(b) { report_summary(N.parse_nvidia_spdm_evidence(b)) },
    'formatVbiosVersion' => ->(b) { N.format_vbios_version(b) },
    'spkiSha256Hex' => ->(pem) { N.spki_sha256_hex(pem) },
    'parsePemChain' => ->(pem) { N.parse_pem_chain(pem).map { |c| summary(c) } },
    'verifyDeviceChain' => ->(pem, pins, now) { chain_result(pem, pins, now) },
    'verifySpdmSignature' => ->(ev, pem) { N.verify_nvidia_spdm_signature(N.parse_nvidia_spdm_evidence(ev), N.parse_pem_chain(pem)[0].public_key) },
    'spdmChallenge' => ->(e) { by(N.nvidia_spdm_challenge(e)) },
    'rimIds' => ->(b) { N.nvidia_rim_ids_for_report(N.parse_nvidia_spdm_evidence(b)) },
    'compareReport' => ->(b, d, v) { N.compare_report_to_rims(N.parse_nvidia_spdm_evidence(b), rim_from(d), rim_from(v)) },
    'checkRevocation' => ->(pem, crls, now, iss, req) { revocation(pem, crls, now, iss, req) },
    'fetchRim' => lambda { |c|
      fetched(c) { |f| { 'value' => N.fetch_nvidia_rim(c['id'], fetch: f, base_url: c['baseUrl']) } }
    },
    'fetchCrl' => lambda { |c|
      fetched(c) { |f| { 'value' => by(N.fetch_nvidia_crl(c['url'], fetch: f)) } }
    },
    'ocspRequest' => ->(cert, iss, o) { by(N.build_nvidia_ocsp_request(cert, iss, nonce: o['nonce'], hash: o['hash'])) },
    'ocspUrls' => ->(pem) { N.nvidia_cert_ocsp_urls(AtlasPca::Attest::Cert.from_pem(pem)) },
    'ocspVerify' => ->(der, o) { ocsp_verify(der, o) },
    'ocspChain' => ->(pem, responses, now, o) { ocsp_chain(pem, responses, now, o) },
    'fetchOcsp' => lambda { |c|
      o = c['opts'] || {}
      fetched(c) do |f|
        r = N.fetch_nvidia_ocsp(c['certPem'], c['issuerPem'], fetch: f, url: o['url'], nonce: o['nonce'])
        { 'request' => by(r['request']), 'response' => by(r['response']) }
      end
    },
    'asn1TimesWellFormed' => ->(der) { N.all_asn1_times_well_formed?(der) }
  }.freeze

  RIM_HANDLERS = {
    'verifyRim' => ->(xml, o) { rim_result(xml, o) },
    'collateralHook' => ->(c) { collateral(c) }
  }.freeze

  TOTALS = { 'constants' => 1, 'parseReport' => 66, 'formatVbiosVersion' => 9, 'spkiSha256Hex' => 3, 'parsePemChain' => 12, 'verifyDeviceChain' => 63,
             'verifySpdmSignature' => 15, 'spdmChallenge' => 10, 'rimIds' => 26, 'compareReport' => 26, 'checkRevocation' => 39, 'fetchRim' => 12,
             'fetchCrl' => 4, 'ocspRequest' => 20, 'ocspUrls' => 8, 'ocspVerify' => 81, 'ocspChain' => 30, 'fetchOcsp' => 5, 'asn1TimesWellFormed' => 37 }.freeze
  RIM_TOTALS = { 'verifyRim' => 108, 'collateralHook' => 55 }.freeze

  # a result compares by value; a string the reference took from the platform compares by presence
  def self.same?(got, ref)
    case ref
    when Hash then got.is_a?(Hash) && got.keys.sort == ref.keys.sort && ref.all? { |k, v| same?(got[k], v) }
    when Array then got.is_a?(Array) && got.length == ref.length && ref.each_with_index.all? { |v, i| same?(got[i], v) }
    when String then ref.match?(LIB) || ref.include?('error:0') ? got.is_a?(String) && !got.empty? : got == ref
    else Ref.canon(got) == Ref.canon(ref)
    end
  end

  def test_every_fn_of_both_corpora_has_a_handler_and_the_totals_are_pinned
    assert_equal HANDLERS.keys.sort, BY_FN.keys.sort
    assert_equal TOTALS, BY_FN.transform_values(&:length)
    assert_equal 467, BY_FN.values.sum(&:length)
    assert_equal RIM_HANDLERS.keys.sort, RIM_BY_FN.keys.sort
    assert_equal RIM_TOTALS, RIM_BY_FN.transform_values(&:length)
    assert_equal 163, RIM_BY_FN.values.sum(&:length)
  end

  { BY_FN => HANDLERS, RIM_BY_FN => RIM_HANDLERS }.each do |cases, handlers|
    handlers.each do |fn, handler|
      define_method("test_replay_#{fn}") do
        k = self.class
        Ref.run(self, cases.fetch(fn), ->(*args) { handler.call(*args) }, compare: ->(got, out, _c) { k.same?(Ref.norm(got), Ref.norm(out)) })
      end
    end
  end
end
