# frozen_string_literal: true

# c21: exact-outcome kill tests for lib/atlas_pca/sigstore_bundle.rb, forbid_certificate.rb and refusal_help.rb.
# Expected values come from the TypeScript reference (packages/pca-attest-eat/src/sigstore.ts, packages/pca/src/forbid-certificate.ts,
# packages/pca/src/refusal-help.ts and the shared vectors in packages/pca/conformance/). AtlasPca is dropped and re-evaluated for every
# mutant, so everything under AtlasPca is resolved at CALL time (never cached in a constant, an ivar or a Struct built at load).
require 'timeout'
require 'json'
require 'openssl'
require 'atlas_pca/sigstore_bundle'

module MutationKill
  module C21Sig
    module_function

    INF = Float::INFINITY
    # keys are generated once at load: the mutants only re-evaluate the library
    EC256 = OpenSSL::PKey::EC.generate('prime256v1')
    ED = OpenSSL::PKey.generate_key('ED25519')
    RSA2K = OpenSSL::PKey::RSA.generate(2048)
    JunkKey = Struct.new(:public_to_der)

    def s = AtlasPca::SigstoreBundle
    def skip? = (f = ENV['MUT_FILE']) && !f.empty? && f != 'sigstore_bundle.rb'

    def same?(got, want)
      case want
      when Array then got.is_a?(Array) && got.size == want.size && got.zip(want).all? { |g, w| same?(g, w) }
      when Hash then got.is_a?(Hash) && got.size == want.size && want.all? { |k, v| got.key?(k) && same?(got[k], v) }
      else got == want && got.class == want.class
      end
    end

    # rows: [label, got, want]; true when every row agrees, else raises naming the first mismatches.
    def check(rows)
      bad = rows.reject { |_l, got, want| same?(got, want) }
      return true if bad.empty?

      raise "c21 mismatch: #{bad.first(4).map { |l, g, w| "#{l}: got #{g.inspect[0, 240]} want #{w.inspect[0, 240]}" }.join(' | ')}"
    end

    # the block's value, or [error class, message] when it raises
    def err
      yield
    rescue Exception => e # rubocop:disable Lint/RescueException
      [e.class, e.message]
    end

    # the block's value, or [:fail, message] when it raises the library's Fail, or [error class, message] for any other error
    def fail_msg
      yield
    rescue AtlasPca::SigstoreBundle::Fail => e
      [:fail, e.message]
    rescue Exception => e # rubocop:disable Lint/RescueException
      [e.class, e.message]
    end

    # ---- a tiny DER writer (independent of the library under test)
    def tl(tag, *parts)
      c = parts.map(&:b).join
      n = c.bytesize
      len = if n < 0x80 then [n]
            elsif n < 0x100 then [0x81, n]
            else [0x82, n >> 8, n & 0xff]
            end
      [tag, *len].pack('C*') + c
    end

    def oidb(o) = OpenSSL::ASN1::ObjectId.new(o).to_der
    def int(n) = tl(2, [n].pack('C'))
    def b64(x) = [x].pack('m0')
    def sha(*parts) = OpenSSL::Digest::SHA256.digest(parts.map(&:b).join)
    def ext(oid, value) = tl(0x30, oidb(oid), tl(0x04, value))

    # a certificate-shaped DER carrying only extensions (parse_cert reads structure, never signatures)
    def cert_der(exts) = tl(0x30, tl(0x30, tl(0xa3, tl(0x30, *exts))))
    def pc(*exts) = s.parse_cert(cert_der(exts))

    def slim(r) = { ok: r[:ok], code: r[:code], detail: r[:detail] }.compact

    # ---- the shared sigstore vectors (a plain JSON Hash; AtlasPca objects are built per call)
    def vec_path
      [File.expand_path('../../conformance/sigstore-vectors.json', __dir__),
       File.expand_path('../../conformance/sigstore-vectors.json', __dir__)].find { |p| File.exist?(p) }
    end

    def vectors = (@vectors ||= JSON.parse(File.read(vec_path, encoding: 'UTF-8')))

    def case_of(name)
      cs = vectors['cases'].find { |x| x['name'] == name }
      [Marshal.load(Marshal.dump(cs['bundle'])), AtlasPca.parse_trusted_root(vectors['roots'][cs['roots']])]
    end

    OK_V1 = 'conformance/happy-path-intoto-in-dsse-v3'
    OK_V2 = 'conformance/rekor2-dsse-happy-path'

    def leaf_der_of(bundle) = s.b64(bundle['verificationMaterial']['certificate']['rawBytes'])

    # ---- RFC 3161 token builder
    SHA256_OID = '2.16.840.1.101.3.4.2.1'
    OID_SD = '1.2.840.113549.1.7.2'
    OID_TST = '1.2.840.113549.1.9.16.1.4'
    OID_CT = '1.2.840.113549.1.9.3'
    OID_MD = '1.2.840.113549.1.9.4'
    DATA = 'c21-signature-bytes'
    GEN = 1_704_067_200_000 # 2024-01-01T00:00:00Z

    def tsa_ders
      @tsa_ders ||= begin
        sc = StrictChain
        leaf = sc.cert('c21-tsa', 'c21-tsaroot', [sc.ca('CA:FALSE'), sc.ext('extendedKeyUsage', 'timeStamping')])
        root = sc.cert('c21-tsaroot', 'c21-tsaroot', [sc.ca, sc.ku])
        [leaf.to_der, root.to_der]
      end
    end

    def tsas
      cert = AtlasPca::Attest::Cert
      [s::PinnedCa.new(tsa_ders.map { |d| cert.new(d) }, s::Validity.new(0, INF))]
    end

    def attr(oid, *vals) = tl(0x30, oidb(oid), tl(0x31, *vals))

    # rows of a token: every field can be replaced to reach one refusal
    def token(data: DATA, gen: tl(0x18, '20240101000000Z'), mi_oid: SHA256_OID, imprint: nil, ac: nil, attrs_tag: 0xa0, sig_tag: 0x04,
              nsi: 1, no_si: false, status: nil)
      tb = tl(0x30, int(1), oidb('1.2.3.4'), tl(0x30, tl(0x30, oidb(mi_oid)), tl(0x04, imprint || sha(data))), int(1), gen)
      ac ||= attr(OID_CT, oidb(OID_TST)) + attr(OID_MD, tl(0x04, sha(tb)))
      sig = StrictChain.key('c21-tsa').sign(OpenSSL::Digest.new('SHA256'), tl(0x31, ac))
      si = tl(0x30, int(1), tl(0x30), tl(0x30, oidb(SHA256_OID)), tl(attrs_tag, ac), tl(0x30), tl(sig_tag, sig))
      encap = tl(0x30, oidb(OID_TST), tl(0xa0, tl(0x04, tb)))
      kids = [int(3), tl(0x31, tl(0x30, oidb(SHA256_OID))), encap]
      kids << tl(0x31, *([si] * nsi)) unless no_si
      ci = tl(0x30, oidb(OID_SD), tl(0xa0, tl(0x30, *kids)))
      status.nil? ? ci : tl(0x30, tl(0x30, int(status)), ci)
    end

    def rf(tok, data = DATA, ts = nil) = s.verify_rfc3161(tok, data, ts || tsas)

    # ---- SCT builder (RFC 6962 3.2): a precert leaf whose TBS without the SCT extension is `tbs_b`
    OID_SCT = '1.3.6.1.4.1.11129.2.4.2'

    def dummy_ext = ext('2.5.29.19', tl(0x30))

    def sct_tbs
      @sct_tbs ||= begin
        n = NodeX509
        AtlasPca::Attest::Cert.new(n.cert(n.root, n.up_name, [dummy_ext], n.b(0x33))).tbs_der
      end
    end

    def sct_cert_der(list)
      n = NodeX509
      n.cert(n.root, n.up_name, [dummy_ext, ext(OID_SCT, tl(0x04, list))], n.b(0x33))
    end

    def sct_issuer_der
      n = NodeX509
      n.cert(n.root, n.up_name, [], n.b(0x44))
    end

    LOG_ID = OpenSSL::Digest::SHA256.digest(EC256.public_to_der)
    OTHER_ID = OpenSSL::Digest::SHA256.digest('some other log')

    def sct_list(*scts, tail: ''.b)
      body = scts.map { |x| [x.bytesize].pack('n') + x }.join + tail
      [body.bytesize].pack('n') + body
    end

    def make_sct(ts: 1_700_000_000_000, ext_b: ''.b, log_id: LOG_ID, flip: false)
      issuer = AtlasPca::Attest::Cert.new(sct_issuer_der)
      signed = [0, 0, ts, 1].pack('CCQ>n') + OpenSSL::Digest::SHA256.digest(issuer.spki_der) + [sct_tbs.bytesize].pack('N')[1, 3] + sct_tbs +
               [ext_b.bytesize].pack('n') + ext_b
      sig = EC256.sign(OpenSSL::Digest.new('SHA256'), signed)
      sig = sig.byteslice(0, sig.bytesize - 1) + [sig.getbyte(-1) ^ 1].pack('C') if flip
      "\x00".b + log_id + [ts].pack('Q>') + [ext_b.bytesize].pack('n') + ext_b + "\x04\x03".b + [sig.bytesize].pack('n') + sig
    end

    # a well framed SCT of exactly `n` bytes, version byte `v`
    def raw_sct(n, v) = [v].pack('C') + ('a' * (n - 1))

    def sct_run(list)
      pc = s.parse_cert(sct_cert_der(list))
      issuer = AtlasPca::Attest::Cert.new(sct_issuer_der)
      plog = s::PinnedLog.new(LOG_ID, EC256, s::Validity.new(0, INF), nil)
      roots = Struct.new(:ctlogs).new([plog])
      Timeout.timeout(2) { s.verify_sct(pc, issuer, roots) }
    end

    # ---- a log entry for pinned_log
    def entry(raw, details, key_id, **extra)
      { 'publicKey' => { 'rawBytes' => b64(raw), 'keyDetails' => details,
                         'validFor' => { 'start' => '2020-01-01T00:00:00Z', 'end' => '2030-01-01T00:00:00Z' } },
        'logId' => { 'keyId' => b64(key_id) } }.merge(extra.transform_keys(&:to_s))
    end

    def pkcs1(rsa) = OpenSSL::ASN1.decode(rsa.public_to_der).value[1].value

    # ---- forbid-wins certificates
    class Duck
      def initialize(hash)
        @h = hash
      end

      def [](key)
        @h[key]
      end

      def fetch(key)
        @h.fetch(key)
      end
    end

    class EmptyDuck
      def empty? = true
    end

    def fc(clauses, decision, winner, shadowed = [])
      { 'v' => 1, 'kind' => 'forbid-wins', 'clauses' => clauses, 'decision' => decision, 'winner' => winner, 'shadowed' => shadowed }
    end

    def row(id, kind, value = 'true', signer = nil)
      h = { 'id' => id, 'kind' => kind, 'value' => value }
      h['signer'] = signer if signer
      h
    end

    REFUSAL_TABLE_JSON = <<~'JSON'
      [["authorize_config","The guard was built without a required component, so it refuses every request (fail closed).","Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults.","https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/resource-server-quickstart.md"],["authorize","The guard was built without a required component, so it refuses every request (fail closed).","Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults.","https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/resource-server-quickstart.md"],["operation","The signed action is not the operation this route executes (other verb, resource or params).","Sign the action the route runs, with the same params. If this is a tool server, use one tool-to-action mapping on both sides.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#operation"],["audience","The proof was signed for a different server.","Make the agent sign with the same audience string the server is configured with.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#audience"],["replay","This proof (or an older counter) was already used.","Each action needs a fresh proof. If this is a retry of an action that already ran, use an operation record instead of resending.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay"],["counter_format","The proof carries no valid anti-replay counter.","Build the proof with the agent facade (act) or buildPCActn, which set it.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay"],["plan_root_authorized","The plan the action belongs to was not authorized by the principal.","Use plan: single-step (protect() does) for one-action proofs, or have the principal authorize the committed plan root.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#plan_root_authorized"],["plan_state","The plan is committed but not executable now (not authorized, expired or revoked).","Check the plan state named in the reason and re-authorize or recommit.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#plan_root_authorized"],["revocation","The grant, or the revocation source, refused.","The grant was revoked, or no revocation source is configured. Configure hooks.revocation (protect() does).","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#revocation"],["validity","The proof is outside its validity window.","Check clocks on both sides; request a fresh proof.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#validity"],["grant_ref","The proof does not name a grant this server knows.","Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#grant_ref"],["grant_ref_bound","The proof does not name a grant this server knows.","Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#grant_ref"],["policy","The grant does not permit this action or these parameters (a predicate or limit failed).","Widen the grant if the action is legitimate (the principal signs a new one); otherwise this is the guard working.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#policy"],["delegated_caveats","A caveat added by a delegation refused the action.","The sub-agent was narrowed below this action. Delegate with the caveats you intend.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#policy"],["threshold","The risk needs a co-signature from the principal (step-up).","Collect the co-sign through the step-up flow, or lower the risk the server prices.","https://github.com/Atlas-Authorization/pca/blob/main/docs/concepts/threshold-and-step-up.md"],["risk_inputs","A risk input the server must vouch for was not supplied.","Supply it in the risk option (catalogRisk derives the common ones; protect() uses it).","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#risk_inputs"],["chain","The delegation chain does not verify back to the grant.","Rebuild the chain with delegate()/subAgent(); do not edit a grant or hop after signing.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#chain"],["leaf_signature","The proof signature does not verify.","The proof was altered, or signed by a key that is not the chain leaf.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#chain"],["wire","The proof is not well-formed under the strict wire profile.","Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn }).","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/wire-formats.md"],["malformed","The proof could not be read.","Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn }).","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/wire-formats.md"],["freshness","The consistency token or revocation epoch is stale.","Refresh the token from the guardian and retry.","https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#freshness"],["provenance_flow","The action, or an argument of it, derives from content the principal did not write (a tool result, a page, an unpinned or missing provenance bundle), or the bundle is forged or unreadable.","Present the provenance bundle your pinned mediator recorded (PCA-Provenance header), have the principal confirm the escalation, or run the call from a principal-authorized plan.","https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/prompt-injection-provenance.md"],["undo_window","The action ran under a veto window: the principal can undo it until the window ends.","Report the effect to your undo coordinator and let the window run.","https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/undo-windows.md"],["template","The grant is not an instantiation of a linked policy template.","Mint the grant from the template the server requires.","https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/policy-analysis.md"]]
    JSON
  end

  # ============================================================================================================== sigstore: load
  t('c21 sigstore: Fail is a StandardError and nothing else') do
    next true if C21Sig.skip?

    s = C21Sig.s
    C21Sig.check([['super', s::Fail.superclass, StandardError], ['ancestors', s::Fail.ancestors.include?(StandardError), true]])
  end

  t('c21 sigstore: the requires at the top of sigstore_bundle.rb load what it uses (fresh ruby over the mutated text)') do
    next true unless defined?(MutationKill::C07)

    c07 = MutationKill::C07
    next true if c07.mutating? && !c07.header_changed?('atlas_pca/sigstore_bundle.rb', 28)

    code = <<~'RUBY'
      require 'atlas_pca/sigstore_bundle'
      s = AtlasPca::SigstoreBundle
      puts s.b64('QUJD')
      puts AtlasPca.verify_sigstore_bundle_core({ 'verificationMaterial' => {}, 'mediaType' => 'x' }, nil)[:detail]
      ed = OpenSSL::PKey.generate_key('ED25519')
      spki = ed.public_to_der
      id = s.sha256("rekor.example.com\n", "\x01", spki.byteslice(-32, 32))
      t = { 'publicKey' => { 'rawBytes' => [spki].pack('m0'), 'keyDetails' => 'PKIX_ED25519', 'validFor' => { 'start' => '2020-01-01T00:00:00Z' } },
            'logId' => { 'keyId' => [id].pack('m0') }, 'baseUrl' => 'https://rekor.example.com/' }
      puts s.pinned_log(t, true).v2_name
    RUBY
    out, ok = c07.fresh('atlas_pca/sigstore_bundle.rb', code)
    ok && out == "ABC\nunsupported media type x\nrekor.example.com\n"
  end

  # ============================================================================================================== sigstore: small helpers
  t('c21 sigstore: get and b64 are exact') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    spy = Class.new(String) { def unpack1(*) = raise(ArgumentError, 'seam') }.new('AAAA')
    c.check([
              ['get non-hash', s.get(5, 'a'), nil], ['get array', s.get([1], 'a'), nil], ['get hash', s.get({ 'a' => 1 }, 'a'), 1],
              ['get absent', s.get({}, 'a'), nil], ['obj? hash', s.obj?({}), true], ['obj? array', s.obj?([]), false],
              ['b64', s.b64('QUJD'), 'ABC'], ['b64 empty', s.b64(''), ''], ['b64 pad', s.b64('QQ=='), 'A'],
              ['b64 nil', c.fail_msg { s.b64(nil) }, [:fail, 'not base64']], ['b64 int', c.fail_msg { s.b64(5) }, [:fail, 'not base64']],
              ['b64 length', c.fail_msg { s.b64('QUJ') }, [:fail, 'not base64']], ['b64 char', c.fail_msg { s.b64('Q@JD') }, [:fail, 'not base64']],
              ['b64 mid pad', c.fail_msg { s.b64('QU=D') }, [:fail, 'not base64']], ['b64 decode fault', c.fail_msg { s.b64(spy) }, [:fail, 'not base64']]
            ])
  end

  t('c21 sigstore: date_ms is exact to the millisecond and refuses every impossible date') do
    next true if C21Sig.skip?

    s = C21Sig.s
    good = {
      '2024-03-01T12:34:56Z' => 1_709_296_496_000, '2024-03-01T12:34:56.1Z' => 1_709_296_496_100,
      '2024-03-01T12:34:56.12Z' => 1_709_296_496_120, '2024-03-01T12:34:56.123456789Z' => 1_709_296_496_123,
      '2024-01-01T00:00:00.1234Z' => 1_704_067_200_123, '2024-03-01T12:34:56.005+05:30' => 1_709_276_696_005,
      '2024-03-01T12:34:56.5-03:45' => 1_709_309_996_500, '2024-03-01T12:34:56-00:30' => 1_709_298_296_000,
      '2024-01-01T00:00:00+00:00' => 1_704_067_200_000, '1970-01-01T00:00:00Z' => 0, '2024-02-29T23:59:59Z' => 1_709_251_199_000,
      '2000-02-29T00:00:00Z' => 951_782_400_000, '2024-12-31T23:59:59Z' => 1_735_689_599_000
    }
    bad = ['garbage', '2024-00-10T00:00:00Z', '2024-13-10T00:00:00Z', '2024-01-00T00:00:00Z', '2024-04-31T00:00:00Z', '2024-02-30T00:00:00Z',
           '2023-02-29T00:00:00Z', '1900-02-29T00:00:00Z', '2024-01-01T24:00:00Z', '2024-01-01T00:60:00Z', '2024-01-01T00:00:60Z',
           '2024-01-01T00:00:00', '2024-01-01T00:00:00+0530', '2024-01-01 00:00:00Z']
    C21Sig.check(good.map { |k, v| [k, s.date_ms(k), v] } + bad.map { |k| [k, s.date_ms(k), nil] })
  end

  t('c21 sigstore: validity reads start and end, refusing a missing or malformed one') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    v = s.validity({ 'start' => '2024-01-01T00:00:00Z' })
    w = s.validity({ 'start' => '2024-01-01T00:00:00Z', 'end' => '2024-01-02T00:00:00Z' })
    x = s.validity({ 'start' => '2024-01-01T00:00:00Z', 'end' => 5 })
    miss = [:fail, 'validFor.start missing']
    c.check([
              ['open', [v.start, v.end_], [1_704_067_200_000, Float::INFINITY]], ['closed', [w.start, w.end_], [1_704_067_200_000, 1_704_153_600_000]],
              ['end not a string', [x.start, x.end_], [1_704_067_200_000, Float::INFINITY]],
              ['nil', c.fail_msg { s.validity(nil) }, miss], ['array', c.fail_msg { s.validity([]) }, miss], ['int', c.fail_msg { s.validity(5) }, miss],
              ['empty', c.fail_msg { s.validity({}) }, miss], ['start int', c.fail_msg { s.validity({ 'start' => 5 }) }, miss],
              ['start bad', c.fail_msg { s.validity({ 'start' => 'x' }) }, miss],
              ['end bad', c.fail_msg { s.validity({ 'start' => '2024-01-01T00:00:00Z', 'end' => 'x' }) }, [:fail, 'validFor.end malformed']]
            ])
  end

  t('c21 sigstore: der writes the shortest length form and binary bytes; sha256 joins parts as bytes') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    pre = { 0 => [0], 127 => [127], 128 => [0x81, 0x80], 255 => [0x81, 0xff], 256 => [0x82, 1, 0], 65_535 => [0x82, 0xff, 0xff],
            65_536 => [0x83, 1, 0, 0], 74_565 => [0x83, 1, 0x23, 0x45] }
    rows = pre.map { |n, len| ["len #{n}", s.der(4, 'a' * n), [4, *len].pack('C*') + ('a' * n)] }
    rows << ['binary', s.der(4, 'é').encoding, Encoding::BINARY]
    rows << ['utf8 content', s.der(4, 'é'), "\x04\x02\xC3\xA9".b]
    rows << ['sha256 mixed', s.sha256('é', "\xFF".b), OpenSSL::Digest::SHA256.digest("\xC3\xA9\xFF".b)]
    rows << ['sha256 empty', s.sha256, OpenSSL::Digest::SHA256.digest('')]
    c.check(rows)
  end

  # ============================================================================================================== sigstore: trusted root
  t('c21 sigstore: pinned_log reads ECDSA, RSA and Ed25519 keys and refuses a log id that is not the key hash') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    ec = C21Sig::EC256.public_to_der
    l = s.pinned_log(c.entry(ec, 'PKIX_ECDSA_P256_SHA_256', c.sha(ec)), true)
    rsa = C21Sig::RSA2K
    rsa_spki = rsa.public_to_der
    ent_rsa = c.entry(c.pkcs1(rsa), 'PKCS1_RSA_PKCS1V5', c.sha(rsa_spki))
    r = s.pinned_log(ent_rsa, false)
    ed = C21Sig::ED.public_to_der
    name = 'rekor.example.com'
    ed_id = c.sha("#{name}\n", "\x01", ed.byteslice(-32, 32))
    e = s.pinned_log(c.entry(ed, 'PKIX_ED25519', ed_id, baseUrl: 'https://rekor.example.com/p'), true)
    tab = s.pinned_log(c.entry(ed, 'PKIX_ED25519', ed_id, baseUrl: "https://rekor.exam\tple.com/"), true)
    empty_id = c.sha("\n", "\x01", ed.byteslice(-32, 32))
    sha_msg = [:fail, 'log id is not the SHA-256 of its key']
    note_msg = [:fail, 'log id is not the signed-note key hash of its key']
    mal = [:fail, 'log entry malformed']
    pk = c.entry(ec, 'PKIX_ECDSA_P256_SHA_256', c.sha(ec))
    c.check([
              ['ec id', l.key_id, c.sha(ec)], ['ec key', l.key.public_to_der, ec], ['ec start', l.valid.start, 1_577_836_800_000],
              ['ec end', l.valid.end_, 1_893_456_000_000], ['ec v2', l.v2_name, nil], ['ec class', l.class, s::PinnedLog],
              ['ec wrong id', c.fail_msg { s.pinned_log(c.entry(ec, 'PKIX_ECDSA_P256_SHA_256', 'x' * 32), true) }, sha_msg],
              ['rsa id', r.key_id, c.sha(rsa_spki)], ['rsa key class', r.key.class, OpenSSL::PKey::RSA], ['rsa key', r.key.public_to_der, rsa_spki],
              ['rsa v2', r.v2_name, nil], ['rsa not for transparency', s.pinned_log(ent_rsa, true), nil],
              ['rsa wrong id', c.fail_msg { s.pinned_log(c.entry(c.pkcs1(rsa), 'PKCS1_RSA_PKCS1V5', 'x' * 32), false) }, sha_msg],
              ['ed id', e.key_id, ed_id], ['ed name', e.v2_name, name], ['ed key', e.key.public_to_der, ed],
              ['ed tab removed', tab.v2_name, name], ['ed not for ct', s.pinned_log(c.entry(ed, 'PKIX_ED25519', ed_id, baseUrl: 'https://rekor.example.com/'), false), nil],
              ['ed no url', c.fail_msg { s.pinned_log(c.entry(ed, 'PKIX_ED25519', empty_id), true) }, note_msg],
              ['ed int url', c.fail_msg { s.pinned_log(c.entry(ed, 'PKIX_ED25519', ed_id, baseUrl: 5), true) }, note_msg],
              ['ed wrong id', c.fail_msg { s.pinned_log(c.entry(ed, 'PKIX_ED25519', 'x' * 32, baseUrl: 'https://rekor.example.com/'), true) }, note_msg],
              ['nil', c.fail_msg { s.pinned_log(nil, true) }, mal], ['empty', c.fail_msg { s.pinned_log({}, true) }, mal],
              ['no log id', c.fail_msg { s.pinned_log({ 'publicKey' => pk['publicKey'] }, true) }, mal],
              ['no key', c.fail_msg { s.pinned_log({ 'logId' => pk['logId'] }, true) }, mal],
              ['key not an object', c.fail_msg { s.pinned_log({ 'publicKey' => 1, 'logId' => pk['logId'] }, true) }, mal],
              ['log id not an object', c.fail_msg { s.pinned_log({ 'publicKey' => pk['publicKey'], 'logId' => [] }, true) }, mal]
            ])
  end

  t('c21 sigstore: pinned_chain and parse_trusted_root refuse a malformed entry with their own text') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    bad = [:fail, 'certificate authority entry malformed']
    media = 'application/vnd.dev.sigstore.trustedroot+json;version=0.1'
    c.check([
              ['certs nil', c.fail_msg { s.pinned_chain({ 'certChain' => { 'certificates' => nil } }) }, bad],
              ['certs string', c.fail_msg { s.pinned_chain({ 'certChain' => { 'certificates' => 'x' } }) }, bad],
              ['certs empty', c.fail_msg { s.pinned_chain({ 'certChain' => { 'certificates' => [] } }) }, bad],
              ['no chain', c.fail_msg { s.pinned_chain({}) }, bad],
              ['root media', c.err { s.parse_trusted_root({}) }, [ArgumentError, 'not a trusted root v0.1']],
              ['root nil', c.err { s.parse_trusted_root(nil) }, [ArgumentError, 'not a trusted root v0.1']],
              ['root empty', c.err { s.parse_trusted_root({ 'mediaType' => media }) },
               [ArgumentError, 'a trusted root needs a transparency log and a CA']]
            ])
  end

  # ============================================================================================================== sigstore: DER
  t('c21 sigstore: tlv checks bounds, tags and lengths with the reference refusals') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    f = ->(b, off = 0, lim = nil) { c.fail_msg { (lim ? s.tlv(b.b, off, lim) : s.tlv(b.b, off)).to_a } }
    c.check([
              ['truncated one byte', f.("\x04"), [:fail, 'DER truncated']], ['truncated by limit', f.("\x04\x00\x00", 0, 1), [:fail, 'DER truncated']],
              ['exact fit', f.("\x04\x00", 0, 2), [4, 0, 2, 2]], ['multi-byte tag', f.("\x1f\x00"), [:fail, 'DER multi-byte tag']],
              ['indefinite length', f.("\x04\x80"), [:fail, 'DER length']], ['five length bytes', f.("\x04\x85\x00\x00\x00\x00\x00"), [:fail, 'DER length']],
              ['four length bytes', f.("\x04\x84\x00\x00\x00\x01X"), [4, 0, 6, 7]], ['length bytes missing', f.("\x04\x82\x00"), [:fail, 'DER length']],
              ['length bytes fit exactly', f.("\x04\x81\x00"), [4, 0, 3, 3]], ['overrun', f.("\x04\x05ab"), [:fail, 'DER overrun']],
              ['short form', f.("\x04\x02ab"), [4, 0, 2, 4]], ['offset', f.("\x00\x00\x04\x01a", 2), [4, 2, 4, 5]]
            ])
  end

  t('c21 sigstore: kids walks every child and stops (deadline)') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    seq = c.tl(0x30, c.tl(4, 'a'), c.tl(4, 'b'), c.tl(5))
    ks = Timeout.timeout(2) { s.kids(seq, s.tlv(seq, 0)) }
    c.check([['tags', ks.map(&:tag), [4, 4, 5]], ['starts', ks.map(&:start), [2, 5, 8]], ['ends', ks.map(&:end_), [5, 8, 10]],
             ['none', Timeout.timeout(2) { s.kids(c.tl(0x30), s.tlv(c.tl(0x30), 0)) }, []]])
  end

  t('c21 sigstore: oid decodes arcs, the first two split at 40 and 80, and refuses non-minimal or truncated encodings') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    of = lambda do |body|
      b = c.tl(6, body)
      c.fail_msg { s.oid(b, s.tlv(b, 0)) }
    end
    long = "\x06\x81\x82".b + "\x80\x01".b + ("\x2a".b * 128)
    c.check([
              ['2.5.4.3', of.("\x55\x04\x03"), '2.5.4.3'], ['rsa sha256', of.("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"), '1.2.840.113549.1.1.11'],
              ['first 39', of.("\x27"), '0.39'], ['first 40', of.("\x28"), '1.0'], ['first 79', of.("\x4f"), '1.39'],
              ['first 80', of.("\x50"), '2.0'], ['first 120', of.("\x78"), '2.40'], ['0x80 inside an arc', of.("\x55\x81\x80\x01"), '2.5.16385'],
              ['0x80 after a complete arc', of.("\x55\x80\x01"), [:fail, 'OID arc is not minimally encoded']],
              ['0x80 first', of.("\x80\x01"), [:fail, 'OID arc is not minimally encoded']],
              ['0x80 first after a long length byte', c.fail_msg { s.oid(long, s.tlv(long, 0)) }, [:fail, 'OID arc is not minimally encoded']],
              ['empty', of.(''), [:fail, 'not an OID']], ['nil', c.fail_msg { s.oid('', nil) }, [:fail, 'not an OID']],
              ['wrong tag', c.fail_msg { s.oid("\x04\x01\x00".b, s.tlv("\x04\x01\x00".b, 0)) }, [:fail, 'not an OID']],
              ['ends inside an arc', of.("\x2a\x86"), [:fail, 'OID ends inside an arc']]
            ])
  end

  t('c21 sigstore: utf8_strict and utf8_lossy never touch their argument and keep their exact text') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    a = 'abc'.b
    r1 = s.utf8_strict(a)
    b = "a\xFFb".b
    r2 = s.utf8_lossy(b)
    c2 = 'abc'.b
    s.utf8_lossy(c2)
    c.check([['strict', r1, 'abc'], ['strict keeps encoding', a.encoding, Encoding::BINARY], ['strict utf8', r1.encoding, Encoding::UTF_8],
             ['strict refuses', c.fail_msg { s.utf8_strict("\xFF".b) }, [:fail, 'not UTF-8']], ['lossy', r2, "a�b"],
             ['lossy keeps encoding', b.encoding, Encoding::BINARY], ['lossy ok keeps encoding', c2.encoding, Encoding::BINARY]])
  end

  # ============================================================================================================== sigstore: certificates
  t('c21 sigstore: parse_cert refuses each structural fault with its own text') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    f = ->(der) { c.fail_msg { s.parse_cert(der) } }
    good = c.cert_der([c.ext('2.5.29.17', 'v')])
    p = s.parse_cert(good)
    c.check([
              ['ok oid', p.exts.map(&:oid), ['2.5.29.17']], ['ok value', p.exts.map(&:value), ['v']],
              ['not a sequence', f.(c.tl(4)), [:fail, 'certificate is not one SEQUENCE']],
              ['trailing', f.(good + "\x00".b), [:fail, 'certificate is not one SEQUENCE']],
              ['no tbs', f.(c.tl(0x30)), [:fail, 'no TBSCertificate']], ['tbs not a sequence', f.(c.tl(0x30, c.tl(4))), [:fail, 'no TBSCertificate']],
              ['no extensions', f.(c.tl(0x30, c.tl(0x30))), [:fail, 'no extensions']],
              ['empty wrapper', f.(c.tl(0x30, c.tl(0x30, c.tl(0xa3)))), [:fail, 'extensions malformed']],
              ['wrapper not a sequence', f.(c.tl(0x30, c.tl(0x30, c.tl(0xa3, c.tl(4))))), [:fail, 'extensions malformed']],
              ['empty entry', f.(c.cert_der([c.tl(0x30)])), [:fail, 'extension value is not an OCTET STRING']],
              ['value not an octet string', f.(c.cert_der([c.tl(0x30, c.oidb('2.5.29.17'), c.tl(2, "\x01"))])),
               [:fail, 'extension value is not an OCTET STRING']]
            ])
  end

  t('c21 sigstore: basic_constraints_ca? is true only for a one-byte TRUE cA') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    bc = ->(v) { s.basic_constraints_ca?(c.pc(c.ext('2.5.29.19', v))) }
    c.check([
              ['absent', s.basic_constraints_ca?(c.pc(c.ext('2.5.29.17', 'x'))), false], ['true', bc.(c.tl(0x30, c.tl(1, "\xff"))), true],
              ['true with path length', bc.(c.tl(0x30, c.tl(1, "\xff"), c.tl(2, "\x01"))), true], ['false', bc.(c.tl(0x30, c.tl(1, "\x00"))), false],
              ['empty', bc.(c.tl(0x30)), false], ['not a boolean', bc.(c.tl(0x30, c.tl(2, "\x05"))), false],
              ['two byte boolean', bc.(c.tl(0x30, c.tl(1, "\xff\xff"))), false], ['not a sequence', bc.(c.tl(4, c.tl(1, "\xff"))), false]
            ])
  end

  t('c21 sigstore: fulcio_ext reads raw UTF-8 up to .6 and a DER UTF8String from .7 on') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    one = lambda do |n, v|
      pc = c.pc(c.ext("1.3.6.1.4.1.57264.1.#{n}", v))
      c.fail_msg { s.fulcio_ext(pc, n) }
    end
    c.check([
              ['absent', s.fulcio_ext(c.pc(c.ext('2.5.29.17', 'x')), 1), nil], ['1 raw', one.(1, 'https://iss'), 'https://iss'],
              ['6 raw', one.(6, 'raw'), 'raw'], ['7 der', one.(7, c.tl(0x0c, 'abc')), 'abc'], ['8 der', one.(8, c.tl(0x0c, 'xyz')), 'xyz'],
              ['8 wrong tag', one.(8, c.tl(0x13, 'xyz')), [:fail, 'extension .1.8 is not a DER UTF8String']],
              ['8 trailing', one.(8, c.tl(0x0c, 'xyz') + 'x'), [:fail, 'extension .1.8 is not a DER UTF8String']]
            ])
  end

  t('c21 sigstore: openssl_parses! carries the OpenSSL refusal and accepts a real certificate') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    real = StrictChain.cert('c21-leaf', 'c21-root', [StrictChain.ca('CA:FALSE')]).to_der
    c.check([['real', c.fail_msg { s.openssl_parses!(real).class }, OpenSSL::X509::Certificate],
             ['garbage', c.fail_msg { s.openssl_parses!("\x30\x00".b) }, [:fail, "#{AtlasPca::Attest::Cert::NO_START_LINE} (CertificateError)"]]])
  end

  t('c21 sigstore: san_decodes? accepts exactly the nine GeneralName tags and is exactly false otherwise') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    san = ->(v) { s.san_decodes?(c.pc(c.ext('2.5.29.17', v))) }
    rows = [0xA0, 0x81, 0x82, 0xA3, 0xA4, 0xA5, 0x86, 0x87, 0x88].map { |tag| ["tag #{tag.to_s(16)}", san.(c.tl(0x30, c.tl(tag, 'x'))), true] }
    rows += [0x80, 0x83, 0x84, 0x85, 0x89, 0xA1, 0xA2].map { |tag| ["tag #{tag.to_s(16)} refused", san.(c.tl(0x30, c.tl(tag, 'x'))), false] }
    rows += [['absent', s.san_decodes?(c.pc(c.ext('2.5.29.19', c.tl(0x30)))), true], ['empty sequence', san.(c.tl(0x30)), true],
             ['not a sequence', san.(c.tl(4, c.tl(0x86, 'x'))), false], ['trailing byte', san.(c.tl(0x30, c.tl(0x86, 'x')) + "\x00".b), false],
             ['truncated', san.("\x30".b), false], ['one good one bad', san.(c.tl(0x30, c.tl(0x86, 'x'), c.tl(0x89, 'x'))), false]]
    c.check(rows)
  end

  t('c21 sigstore: san_identity returns the one URI or email and refuses the rest with its own text') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    id = ->(v) { c.fail_msg { s.san_identity(c.pc(c.ext('2.5.29.17', v))) } }
    one = [:fail, 'subjectAltName must hold exactly one name']
    c.check([
              ['uri', id.(c.tl(0x30, c.tl(0x86, 'https://a'))), 'https://a'], ['email', id.(c.tl(0x30, c.tl(0x81, 'a@b'))), 'a@b'],
              ['absent', c.fail_msg { s.san_identity(c.pc(c.ext('2.5.29.19', c.tl(0x30)))) }, [:fail, 'no subjectAltName']],
              ['two names', id.(c.tl(0x30, c.tl(0x86, 'a'), c.tl(0x86, 'b'))), one], ['no names', id.(c.tl(0x30)), one],
              ['not a sequence', id.(c.tl(4, c.tl(0x86, 'u'))), one],
              ['dns name', id.(c.tl(0x30, c.tl(0x82, 'a.example'))), [:fail, 'subjectAltName must be a URI or an email']]
            ])
  end

  t('c21 sigstore: inside? is inclusive at both ends and false for an unreadable bound') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    cert = Struct.new(:raw).new('x')
    at = lambda do |lo_hi, now|
      Seam.with(AtlasPca::Attest::Der, { der_validity_ms: ->(_d) { lo_hi } }) { s.inside?(cert, now) }
    end
    c.check([
              ['below', at.([10, 20], 9), false], ['at start', at.([10, 20], 10), true], ['inside', at.([10, 20], 15), true],
              ['at end', at.([10, 20], 20), true], ['above', at.([10, 20], 21), false],
              ['no start', at.([nil, 20], 5), false], ['no end', at.([10, nil], 15), false], ['neither', at.([nil, nil], 15), false]
            ])
  end

  t('c21 sigstore: chain_ok? needs every link issued, signed, valid at the time and (above the leaf) a CA') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    sc = StrictChain
    n = NodeX509
    cert = ->(o) { AtlasPca::Attest::Cert.new(o.to_der) }
    now = StrictChain::NOW
    good = sc.chain.map(&cert)
    plain_inter = sc.chain(inter: [sc.ca('CA:FALSE'), sc.ku]).map(&cert)
    odd = AtlasPca::Attest::Cert.new(n.cert(n.other, n.name('c21-odd'), [], n.b(0x77), subject_key: sc.key('c21-odd'), signer: sc.key('inter')))
    c.check([
              ['whole chain', s.chain_ok?(good, now), true], ['from the intermediate', s.chain_ok?(good[1..], now), true],
              ['before validity', s.chain_ok?(good, 1_600_000_000_000), false], ['intermediate is not a CA', s.chain_ok?(plain_inter, now), false],
              ['issuer name differs but the signature is right', s.chain_ok?([odd, good[1], good[2]], now), false],
              ['leaf alone is not self issued', s.chain_ok?([good[0]], now), false]
            ])
  end

  # ============================================================================================================== sigstore: signatures
  t('c21 sigstore: ed25519? and verify_sig route EC, RSA and Ed25519 keys exactly') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    ec = C21Sig::EC256
    rsa = C21Sig::RSA2K
    ed = C21Sig::ED
    d = 'message'
    ec_sig = ec.sign(OpenSSL::Digest.new('SHA256'), d)
    rsa_sig = rsa.sign('SHA256', d)
    ed_sig = ed.sign(nil, d)
    # real EC / RSA keys (fresh copies) that merely claim to be Ed25519
    fake_ec = OpenSSL::PKey.read(ec.public_to_der).tap { |k| k.define_singleton_method(:oid) { 'ED25519' } }
    fake_rsa = OpenSSL::PKey.read(rsa.public_to_der).tap { |k| k.define_singleton_method(:oid) { 'ED25519' } }
    bad_rsa = rsa_sig.byteslice(0, rsa_sig.bytesize - 1) + [rsa_sig.getbyte(-1) ^ 1].pack('C')
    acceptor = Class.new { def oid = 'other'; def verify(*) = true }.new
    c.check([
              ['ed key', s.ed25519?(ed), true], ['ec key', s.ed25519?(ec), false], ['rsa key', s.ed25519?(rsa), false],
              ['no oid', s.ed25519?(Object.new), false], ['ec subclass named ed25519', s.ed25519?(fake_ec), false],
              ['rsa subclass named ed25519', s.ed25519?(fake_rsa), false],
              ['ec', s.verify_sig('sha256', d, ec, ec_sig), true], ['ec wrong data', s.verify_sig('sha256', d + 'x', ec, ec_sig), false],
              ['ec wrong digest', s.verify_sig('sha384', d, ec, ec_sig), false],
              ['rsa', s.verify_sig('sha256', d, rsa, rsa_sig), true], ['rsa tampered', s.verify_sig('sha256', d, rsa, bad_rsa), false],
              ['rsa wrong data', s.verify_sig('sha256', d + 'x', rsa, rsa_sig), false],
              ['ed', s.verify_sig(nil, d, ed, ed_sig), true], ['ed wrong data', s.verify_sig(nil, d + 'x', ed, ed_sig), false],
              ['no digest with an EC key', s.verify_sig(nil, d, ec, ec_sig), false], ['no digest with an RSA key', s.verify_sig(nil, d, rsa, rsa_sig), false],
              ['no digest with a key that accepts anything', s.verify_sig(nil, d, acceptor, ec_sig), false],
              ['digest with an ed key', s.verify_sig('sha256', d, ed, ed_sig), false],
              ['not a key', s.verify_sig('sha256', d, Object.new, ec_sig), false]
            ])
  end

  # ============================================================================================================== sigstore: SCT
  t('c21 sigstore: verify_sct frames every SCT, advances through the list and reports each refusal') do
    next true if C21Sig.skip?

    c = C21Sig
    unk = c.make_sct(log_id: C21Sig::OTHER_ID)
    good = c.make_sct
    trunc47 = "\x00".b + ('b' * 32) + ("\x00" * 8) + "\x00\x01".b + 'X' + "\x04\x03\x00".b
    nopin = 'no SCT from a pinned CT log'
    c.check([
              ['valid', c.sct_run(c.sct_list(good)), nil], ['valid after an unknown log', c.sct_run(c.sct_list(unk, good)), nil],
              ['two unknown logs', c.sct_run(c.sct_list(unk, unk)), nopin],
              ['signature flipped', c.sct_run(c.sct_list(c.make_sct(flip: true))), 'SCT signature invalid'],
              ['46 bytes', c.sct_run(c.sct_list(c.raw_sct(46, 1))), 'SCT truncated'], ['47 bytes, other version', c.sct_run(c.sct_list(c.raw_sct(47, 1))), nopin],
              ['10 bytes', c.sct_run(c.sct_list(c.raw_sct(10, 1))), 'SCT truncated'], ['extension runs past the end', c.sct_run(c.sct_list(trunc47)), 'SCT truncated'],
              ['one stray byte after the last SCT', c.sct_run(c.sct_list(unk, tail: "\x00".b)), 'SCT truncated']
            ])
  end

  # ============================================================================================================== sigstore: checkpoint, ints, PAE
  t('c21 sigstore: verify_checkpoint accepts a log signature on the first line after the body and reports nil') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    key = C21Sig::EC256
    key_id = OpenSSL::Digest::SHA256.digest(key.public_to_der)
    log = s::PinnedLog.new(key_id, key, s::Validity.new(0, Float::INFINITY), nil)
    root = OpenSSL::Digest::SHA256.digest('root')
    body = "origin.example\n5\n#{c.b64(root)}\n"
    sig = key.sign(OpenSSL::Digest.new('SHA256'), body)
    text = "#{body}\n— log.example #{c.b64(key_id.byteslice(0, 4) + sig)}\n"
    c.check([
              ['ok', s.verify_checkpoint(text, log, 5, root), nil],
              ['size', s.verify_checkpoint(text, log, 6, root), 'checkpoint size differs from the proof'],
              ['root', s.verify_checkpoint(text, log, 5, root.reverse), 'checkpoint root differs from the proof'],
              ['no block', s.verify_checkpoint(body, log, 5, root), 'checkpoint has no signature block'],
              ['other key', s.verify_checkpoint(text, s::PinnedLog.new(key_id.reverse, key, s::Validity.new(0, Float::INFINITY), nil), 5, root),
               'no checkpoint signature by the pinned log key']
            ])
  end

  t('c21 sigstore: dec_int accepts only canonical decimal integers up to 2^53-1') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    nd = [:fail, 'not a decimal integer string']
    c.check([
              ['zero', s.dec_int('0'), 0], ['plain', s.dec_int('15'), 15], ['max', s.dec_int('9007199254740991'), 9_007_199_254_740_991],
              ['past max', c.fail_msg { s.dec_int('9007199254740992') }, [:fail, 'integer out of range']],
              ['nil', c.fail_msg { s.dec_int(nil) }, nd], ['int', c.fail_msg { s.dec_int(5) }, nd], ['empty', c.fail_msg { s.dec_int('') }, nd],
              ['leading zero', c.fail_msg { s.dec_int('01') }, nd], ['minus', c.fail_msg { s.dec_int('-1') }, nd],
              ['17 digits', c.fail_msg { s.dec_int('10000000000000000') }, nd]
            ])
  end

  t('c21 sigstore: dsse_pae is the DSSE v1 encoding as bytes, and pem_der returns bytes or empty') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    pae = s.dsse_pae('é', 'é')
    pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
    c.check([
              ['in-toto', s.dsse_pae('application/vnd.in-toto+json', 'abc'), 'DSSEv1 28 application/vnd.in-toto+json 3 abc'],
              ['non ascii', pae, "DSSEv1 2 \xC3\xA9 2 \xC3\xA9".b], ['non ascii encoding', pae.encoding, Encoding::BINARY],
              ['pem', s.pem_der(pem), 'ABC'], ['pem no final newline', s.pem_der(pem.chomp), 'ABC'], ['not pem', s.pem_der('nope'), ''],
              ['not pem encoding', s.pem_der('nope').encoding, Encoding::BINARY], ['kind', s.kind_of('a', 'b'), 'a/b'], ['kind int', s.kind_of('a', 1), '']
            ])
  end

  # ============================================================================================================== sigstore: RFC 3161
  t('c21 sigstore: generalized_time reads fractions to the millisecond and refuses anything else') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    gt = lambda do |tag, text|
      b = c.tl(tag, text)
      c.fail_msg { s.generalized_time(b, s.tlv(b, 0)) }
    end
    c.check([
              ['plain', gt.(0x18, '20240101000000Z'), 1_704_067_200_000], ['half second', gt.(0x18, '20240101000000.5Z'), 1_704_067_200_500],
              ['nine digits', gt.(0x18, '20240101000000.123456789Z'), 1_704_067_200_123],
              ['utc time', gt.(0x17, '240101000000Z'), [:fail, 'genTime is not a GeneralizedTime']],
              ['nil', c.fail_msg { s.generalized_time('', nil) }, [:fail, 'genTime is not a GeneralizedTime']],
              ['text', gt.(0x18, 'garbage'), [:fail, 'genTime malformed']], ['month 13', gt.(0x18, '20241301000000Z'), [:fail, 'genTime malformed']]
            ])
  end

  t('c21 sigstore: digest_of names the digest or refuses an unknown algorithm') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    alg = lambda do |o|
      b = c.tl(0x30, c.tl(0x30, c.oidb(o)))
      c.fail_msg { s.digest_of(b, s.kids(b, s.tlv(b, 0))[0]) }
    end
    c.check([['sha256', alg.('2.16.840.1.101.3.4.2.1'), 'sha256'], ['sha384', alg.('2.16.840.1.101.3.4.2.2'), 'sha384'],
             ['sha512', alg.('2.16.840.1.101.3.4.2.3'), 'sha512'], ['md5', alg.('1.2.840.113549.2.5'), [:fail, 'unsupported digest algorithm']]])
  end

  t('c21 sigstore: verify_rfc3161 returns the genTime of a pinned TSA token and nothing else') do
    next true if C21Sig.skip?

    c = C21Sig
    f = ->(tok, data = C21Sig::DATA, ts = nil) { c.fail_msg { c.rf(tok, data, ts) } }
    ok = c.token
    c.check([
              ['valid', c.rf(ok), C21Sig::GEN], ['valid response, granted', c.rf(c.token(status: 0)), C21Sig::GEN],
              ['valid response, granted with mods', c.rf(c.token(status: 1)), C21Sig::GEN],
              ['fraction', c.rf(c.token(gen: c.tl(0x18, '20240101000000.5Z'))), C21Sig::GEN + 500],
              ['token read as UTF-8 text', c.rf(ok.dup.force_encoding('UTF-8')), C21Sig::GEN],
              ['trailing byte', f.(ok + "\x00".b), [:fail, 'timestamp is not one SEQUENCE']],
              ['not a sequence', f.(c.tl(0x31, c.tl(0x30))), [:fail, 'timestamp is not one SEQUENCE']],
              ['status refused', f.(c.token(status: 2)), [:fail, 'timestamp status is not granted']],
              ['status without a token', f.(c.tl(0x30, c.tl(0x30, c.int(0)))), [:fail, 'no timeStampToken']],
              ['empty sequence', f.(c.tl(0x30)), [:fail, 'not an OID']], ['first part is an empty sequence', f.(c.tl(0x30, c.tl(0x30))), [:fail, 'not an OID']],
              ['first part is a short sequence', f.(c.tl(0x30, c.tl(0x30, c.tl(2)))), [:fail, 'not an OID']],
              ['no content', f.(c.tl(0x30, c.oidb(C21Sig::OID_SD))), [:fail, 'not CMS SignedData']],
              ['other content type', f.(c.tl(0x30, c.oidb(C21Sig::OID_TST), c.tl(0xa0, c.tl(0x30)))), [:fail, 'not CMS SignedData']],
              ['no encapsulated content', f.(c.tl(0x30, c.oidb(C21Sig::OID_SD), c.tl(0xa0, c.tl(0x30, c.int(3), c.tl(0x31))))),
               [:fail, 'no encapsulated content']],
              ['no TSTInfo explicit tag', f.(c.tl(0x30, c.oidb(C21Sig::OID_SD),
                                                  c.tl(0xa0, c.tl(0x30, c.int(3), c.tl(0x31), c.tl(0x30, c.oidb(C21Sig::OID_TST)))))),
               [:fail, 'content is not TSTInfo']],
              ['TSTInfo content missing', f.(c.tl(0x30, c.oidb(C21Sig::OID_SD),
                                                   c.tl(0xa0, c.tl(0x30, c.int(3), c.tl(0x31), c.tl(0x30, c.oidb(C21Sig::OID_TST), c.tl(0xa0)))))),
               [:fail, 'TSTInfo is not an OCTET STRING']],
              ['TSTInfo content not an octet string',
               f.(c.tl(0x30, c.oidb(C21Sig::OID_SD),
                       c.tl(0xa0, c.tl(0x30, c.int(3), c.tl(0x31), c.tl(0x30, c.oidb(C21Sig::OID_TST), c.tl(0xa0, c.tl(0x30))))))),
               [:fail, 'TSTInfo is not an OCTET STRING']],
              ['other data', f.(ok, 'other'), [:fail, 'messageImprint is not the hash of the signature']],
              ['unknown imprint digest', f.(c.token(mi_oid: '1.2.840.113549.2.5')), [:fail, 'unsupported digest algorithm']],
              ['genTime is a UTCTime', f.(c.token(gen: c.tl(0x17, '240101000000Z'))), [:fail, 'genTime is not a GeneralizedTime']],
              ['genTime text', f.(c.token(gen: c.tl(0x18, 'garbage'))), [:fail, 'genTime malformed']],
              ['genTime month', f.(c.token(gen: c.tl(0x18, '20241301000000Z'))), [:fail, 'genTime malformed']],
              ['no signerInfos', f.(c.token(no_si: true)), [:fail, 'no signerInfos']],
              ['two signerInfos', f.(c.token(nsi: 2)), [:fail, 'exactly one SignerInfo is required']],
              ['attributes not tagged', f.(c.token(attrs_tag: 0x31)), [:fail, 'signed attributes are required']],
              ['attribute with two values',
               f.(c.token(ac: c.attr(C21Sig::OID_CT, c.oidb(C21Sig::OID_TST), c.oidb(C21Sig::OID_TST)))), [:fail, 'an attribute must have one value']],
              ['message digest of something else',
               f.(c.token(ac: c.attr(C21Sig::OID_CT, c.oidb(C21Sig::OID_TST)) + c.attr(C21Sig::OID_MD, c.tl(4, c.sha('x'))))),
               [:fail, 'signed attributes do not commit to the TSTInfo']],
              ['no message digest', f.(c.token(ac: c.attr(C21Sig::OID_CT, c.oidb(C21Sig::OID_TST)))), [:fail, 'signed attributes do not commit to the TSTInfo']],
              ['signature not an octet string', f.(c.token(sig_tag: 0x31)), [:fail, 'signature is not an OCTET STRING']],
              ['no pinned authority', f.(ok, C21Sig::DATA, []), [:fail, 'no pinned timestamp authority signed it (valid at its time)']]
            ])
  end

  # ============================================================================================================== sigstore: the verifier
  t('c21 sigstore: a fault inside each stage is reported under that stage') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    b, roots = c.case_of(C21Sig::OK_V1)
    raise 'fixture is not an ok bundle' unless AtlasPca.verify_sigstore_bundle_core(b, roots)[:ok] == true

    boom = ->(*) { raise 'c21' }
    orig_sig = s.method(:verify_sig)
    orig_json = s.method(:json_parse)
    seen = 0
    run = ->(stubs) { c.slim(Seam.with(s, stubs) { AtlasPca.verify_sigstore_bundle_core(b, roots) }) }
    c.check([
              ['cert_chain', run.({ san_decodes?: boom }), { ok: false, code: 'cert_chain', detail: 'fail closed: c21' }],
              ['sct', run.({ verify_sct: boom }), { ok: false, code: 'sct', detail: 'fail closed: c21' }],
              ['signature', run.({ verify_sig: ->(h, d, k, sg) { d.start_with?('DSSEv1') ? raise('c21') : orig_sig.call(h, d, k, sg) } }),
               { ok: false, code: 'signature', detail: 'fail closed: c21' }],
              ['null entry body', run.({ json_parse: ->(_t) {} }), { ok: false, code: 'tlog_body', detail: 'fail closed: entry body is null' }],
              ['null statement', run.({ json_parse: ->(t) { (seen += 1) == 1 ? orig_json.call(t) : nil } }),
               { ok: false, code: 'statement', detail: 'fail closed: statement is null' }]
            ])
  end

  t('c21 sigstore: the CA search accepts a CA valid exactly at the signing time, stops at the first issuer and refuses a CA leaf') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    b, roots = c.case_of(C21Sig::OK_V1)
    base = AtlasPca.verify_sigstore_bundle_core(b, roots)
    signed_ms = base[:core]['signed_time'] * 1000
    pinned = ->(cas) { s::PinnedRoots.new(roots.tlogs, roots.ctlogs, cas, roots.tsas) }
    edge = pinned.(roots.cas.map { |ca| ca.valid.end_ == Float::INFINITY ? s::PinnedCa.new(ca.chain, s::Validity.new(signed_ms, Float::INFINITY)) : ca })
    leaf = AtlasPca::Attest::Cert.new(c.leaf_der_of(b))
    n = NodeX509
    junk = c.tl(0x30, c.tl(0x30, c.oidb('1.2.3.4.5')), c.tl(0x03, "\x00".b + 'junk'))
    bad = AtlasPca::Attest::Cert.new(n.cert(n.root, leaf.issuer_der, [], n.b(0x55), subject_key: C21Sig::JunkKey.new(junk)))
    extra = pinned.(roots.cas + [s::PinnedCa.new([bad], s::Validity.new(0, Float::INFINITY))])
    cert = AtlasPca::Attest::Cert
    orig_ca = cert.instance_method(:ca)
    as_ca = begin
      cert.send(:define_method, :ca) { true }
      c.slim(AtlasPca.verify_sigstore_bundle_core(b, roots))
    ensure
      cert.send(:define_method, :ca, orig_ca)
    end
    c.check([
              ['ok', base[:ok], true], ['ca valid from exactly the signing time', AtlasPca.verify_sigstore_bundle_core(b, edge)[:ok], true],
              ['later CA never examined', AtlasPca.verify_sigstore_bundle_core(b, extra)[:ok], true],
              ['leaf is a CA', as_ca, { ok: false, code: 'cert_chain', detail: 'the leaf is a CA certificate' }]
            ])
  end

  t('c21 sigstore: the entry body is read as the kind the bundle names, with its own refusals (dsse and intoto)') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    b, roots = c.case_of(C21Sig::OK_V1)
    sha = OpenSSL::Digest::SHA256.hexdigest(s.b64(b['dsseEnvelope']['payload']))
    ph = { 'algorithm' => 'sha256', 'value' => sha }
    one = { ok: false, code: 'tlog_body', detail: 'the entry must name exactly one signature' }
    run = lambda do |bundle, eb|
      c.slim(Seam.with(s, { json_parse: ->(_t) { eb } }) { AtlasPca.verify_sigstore_bundle_core(bundle, roots) })
    end
    dsse = ->(sigs) { { 'kind' => 'dsse', 'apiVersion' => '0.0.1', 'spec' => { 'payloadHash' => ph }.merge(sigs.nil? ? {} : { 'signatures' => sigs }) } }
    b2 = Marshal.load(Marshal.dump(b))
    b2['verificationMaterial']['tlogEntries'][0]['kindVersion'] = { 'kind' => 'intoto', 'version' => '0.0.2' }
    intoto = ->(sigs) { { 'kind' => 'intoto', 'apiVersion' => '0.0.2', 'spec' => { 'content' => { 'payloadHash' => ph, 'envelope' => { 'signatures' => sigs } } } } }
    c.check([
              ['dsse absent', run.(b, dsse.(nil)), one], ['dsse not an array', run.(b, dsse.({ 0 => {} })), one], ['dsse not an object', run.(b, dsse.([5])), one],
              ['dsse empty', run.(b, dsse.([])), one],
              ['intoto absent', run.(b2, intoto.(nil)), one], ['intoto not an array', run.(b2, intoto.({ 0 => {} })), one],
              ['intoto not an object', run.(b2, intoto.([5])), one], ['intoto empty', run.(b2, intoto.([])), one]
            ])
  end

  t('c21 sigstore: a Rekor v2 entry names the digest of the signing key and refuses an unknown algorithm') do
    next true if C21Sig.skip?

    c = C21Sig
    s = c.s
    b, roots = c.case_of(C21Sig::OK_V2)
    raise 'fixture is not an ok bundle' unless AtlasPca.verify_sigstore_bundle_core(b, roots)[:ok] == true

    payload = s.b64(b['dsseEnvelope']['payload'])
    dsse_sig = s.b64(b['dsseEnvelope']['signatures'][0]['sig'])
    leaf_der = c.leaf_der_of(b)
    pae = s.dsse_pae(s::INTOTO_PAYLOAD_TYPE, payload)
    hr = lambda do |alg, digest|
      { 'kind' => 'hashedrekord', 'apiVersion' => '0.0.2',
        'spec' => { 'hashedRekordV002' => { 'data' => { 'algorithm' => alg, 'digest' => c.b64(digest) },
                                            'signature' => { 'content' => c.b64(dsse_sig),
                                                             'verifier' => { 'x509Certificate' => { 'rawBytes' => c.b64(leaf_der) } } } } } }
    end
    run = lambda do |alg_of_key, eb|
      c.slim(Seam.with(s, { json_parse: ->(_t) { eb }, leaf_hash_alg: ->(_k) { alg_of_key } }) { AtlasPca.verify_sigstore_bundle_core(b, roots) })
    end
    c.check([
              ['sha512 key and entry', run.('sha512', hr.('SHA2_512', OpenSSL::Digest.new('SHA512').digest(pae))),
               { ok: false, code: 'signature', detail: 'DSSE signature invalid' }],
              ['unknown algorithm, no key algorithm', run.(nil, hr.('bogus', 'x')),
               { ok: false, code: 'tlog_body', detail: "the entry digest algorithm is not the signing key's" }],
              ['known algorithm, other key algorithm', run.('sha256', hr.('SHA2_512', 'x')),
               { ok: false, code: 'tlog_body', detail: "the entry digest algorithm is not the signing key's" }]
            ])
  end

  t('c21 sigstore: verify_sigstore_bundle needs a string build type, a builder id and reads the first dependency only when it is an object') do
    next true if C21Sig.skip?

    c = C21Sig
    core = { 'subjects' => [], 'identity' => 'i', 'oidc_issuer' => 'o', 'signed_time' => 5, 'rekor_log_index' => 6 }
    st = lambda do |bt, deps|
      bd = { 'buildType' => bt, 'externalParameters' => {} }
      bd['resolvedDependencies'] = deps unless deps.nil?
      { 'predicateType' => AtlasPca::SLSA_PROVENANCE_V1, 'predicate' => { 'buildDefinition' => bd, 'runDetails' => { 'builder' => { 'id' => 'bid' } } } }
    end
    run = lambda do |statement|
      Seam.with(AtlasPca::SigstoreBundle, { verify_sigstore_bundle_core: ->(_b, _r) { { ok: true, core: core, statement: statement } } }) do
        AtlasPca.verify_sigstore_bundle({}, nil)
      end
    end
    need = { ok: false, code: 'predicate', detail: 'buildType, externalParameters and builder.id are required (SLSA Build L1)' }
    prov = ->(r) { r[:facts]&.key?('provenance_source') }
    c.check([
              ['build type not a string', run.(st.(5, nil)), need],
              ['dependencies as an integer keyed object', prov.(run.(st.('bt', { 0 => { 'uri' => 'u' } }))), false],
              ['dependencies hold a non-object', [run.(st.('bt', [5]))[:ok], prov.(run.(st.('bt', [5])))], [true, false]],
              ['dependencies empty', prov.(run.(st.('bt', []))), false],
              ['first dependency', run.(st.('bt', [{ 'uri' => 'u', 'digest' => { 'gitCommit' => 'g' } }]))[:facts]['provenance_source'],
               { 'uri' => 'u', 'git_commit' => 'g' }]
            ])
  end

  # ============================================================================================================== forbid-wins certificates
  t('c21 forbid: a certificate must be an actual Hash with Array clauses, a Hash winner and an Array shadowed (duck typed stand-ins)') do
    c = C21Sig
    ok = ->(cert, prec = []) { AtlasPca.forbid_certificate_consistent?(cert, prec) }
    malformed = { 'kind' => 'malformed', 'id' => nil }
    base = c.fc([], 'deny', malformed)
    permit = c.row('p', 'permit')
    c.check([
              ['baseline malformed', ok.(base), true],
              ['cert is not a Hash', ok.(C21Sig::Duck.new(base)), false],
              ['clauses are not an Array', ok.(base.merge('clauses' => C21Sig::EmptyDuck.new)), false],
              ['winner is not a Hash', ok.(base.merge('winner' => C21Sig::Duck.new(malformed))), false],
              ['shadowed is not an Array', ok.(base.merge('shadowed' => C21Sig::EmptyDuck.new)), false],
              ['winner nil', ok.(base.merge('winner' => nil)), false], ['shadowed nil', ok.(base.merge('shadowed' => nil)), false],
              ['winner nil and shadowed nil', ok.(base.merge('winner' => nil, 'shadowed' => nil)), false],
              ['malformed with a winner id', ok.(c.fc([], 'deny', { 'kind' => 'malformed', 'id' => 'x' })), false],
              ['malformed with shadowed', ok.(c.fc([], 'deny', malformed, ['a'])), false],
              ['malformed that allows', ok.(c.fc([], 'allow', malformed)), false],
              ['malformed with clauses', ok.(c.fc([permit], 'deny', malformed)), false],
              ['a permit', ok.(c.fc([permit], 'allow', { 'kind' => 'permit', 'id' => 'p' })), true],
              ['row is not a Hash', ok.(c.fc([C21Sig::Duck.new(permit)], 'allow', { 'kind' => 'permit', 'id' => 'p' })), false],
              ['row id is not a String', ok.(c.fc([c.row(5, 'permit')], 'allow', { 'kind' => 'permit', 'id' => 5 })), false],
              ['row kind unknown', ok.(c.fc([c.row('x', 'bogus'), permit], 'allow', { 'kind' => 'permit', 'id' => 'p' })), false],
              ['row value unknown', ok.(c.fc([c.row('x', 'permit', 'maybe'), permit], 'allow', { 'kind' => 'permit', 'id' => 'p' })), false]
            ])
  end

  t('c21 forbid: the named forbid is the most authoritative signer, ties by id, and every other match is shadowed in order') do
    c = C21Sig
    rows = [c.row('a', 'forbid', 'true', 'aa'), c.row('c', 'forbid', 'true'), c.row('b', 'forbid', 'true', 'zz'), c.row('p', 'permit'),
            c.row('e', 'escalate', 'unknown'), c.row('n', 'forbid', 'false', 'zz')]
    cert = c.fc(rows, 'deny', { 'kind' => 'forbid', 'id' => 'b' }, %w[a c p e])
    prec = %w[zz aa]
    ok = ->(x, p = prec) { AtlasPca.forbid_certificate_consistent?(x, p) }
    wrong_order = c.fc(rows, 'deny', { 'kind' => 'forbid', 'id' => 'b' }, %w[c a p e])
    wrong_winner = c.fc(rows, 'deny', { 'kind' => 'forbid', 'id' => 'a' }, %w[b c p e])
    ties = c.fc([c.row('y', 'forbid'), c.row('x', 'forbid')], 'deny', { 'kind' => 'forbid', 'id' => 'x' }, ['y'])
    bad_precedence = Object.new
    def bad_precedence.to_ary = raise('c21')
    c.check([
              ['ranked', ok.(cert), true], ['shadowed in another order', ok.(wrong_order), false], ['alphabetical winner', ok.(wrong_winner), false],
              ['no precedence ties by id', ok.(ties, []), true], ['a precedence that cannot be read', ok.(cert, bad_precedence), false],
              ['no matching permit denies', ok.(c.fc([c.row('p', 'permit', 'false')], 'deny', { 'kind' => 'none', 'id' => nil })), true],
              ['escalate', ok.(c.fc([c.row('p', 'permit'), c.row('e', 'escalate')], 'escalate', { 'kind' => 'escalate', 'id' => 'e' }, ['p'])), true]
            ])
  end

  # ============================================================================================================== refusal help
  t('c21 refusal_help: the table, the generic entry and the lookup order are the TypeScript ones') do
    c = C21Sig
    want = JSON.parse(C21Sig::REFUSAL_TABLE_JSON)
    refs = "#{AtlasPca::PCA_DOCS}/reference/refusals.md"
    rows = [['table', AtlasPca::REFUSAL_TABLE, want], ['docs root', AtlasPca::PCA_DOCS, 'https://github.com/Atlas-Authorization/pca/blob/main/docs'],
            ['refusals doc', AtlasPca::REFUSALS_DOC, refs]]
    want.each do |chk, meaning, fix, docs|
      h = AtlasPca.explain_refusal("#{chk}: detail")
      rows << ["row #{chk}", [h.class, h.check, h.meaning, h.fix, h.docs], [AtlasPca::RefusalHelp, chk, meaning, fix, docs]]
    end
    unk = AtlasPca.explain_refusal('nonsense')
    rows << ['unknown', [unk.check, unk.meaning, unk.fix, unk.docs],
             ['unknown', 'The guard refused and the reason is not in the table.',
              'Read the reason as written; every refusal names the check that failed.', refs]]
    rows << ['non-string', AtlasPca.explain_refusal(nil).check, 'unknown']
    rows << ['empty', AtlasPca.explain_refusal('').check, 'unknown']
    rows << ['head wins over an earlier row named inside', AtlasPca.explain_refusal('policy: replay: x').check, 'policy']
    rows << ['named inside', AtlasPca.explain_refusal('Denied. replay: x').check, 'replay']
    rows << ['named inside, first row of the table wins', AtlasPca.explain_refusal('Denied. policy: replay: x').check, 'replay']
    rows << ['head without a colon', AtlasPca.explain_refusal('replay').check, 'replay']
    rows << ['doc of a known check', AtlasPca.refusal_doc('chain: bad'), "#{refs}#chain"]
    rows << ['doc of an unknown reason', AtlasPca.refusal_doc('what'), refs]
    c.check(rows)
  end
end
