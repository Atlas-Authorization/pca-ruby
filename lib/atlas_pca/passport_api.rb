# frozen_string_literal: true

module AtlasPca
  # The agent passport surface of the reference (`passport`): the binding match, the registry, the trust score, the signed passport with its
  # hardware-evidence rule, the verdict-returning verification and the assurance label. Records are String-keyed Hashes with the reference's
  # member names. `AtlasPca.passport_fingerprint` / `issue_passport` (agent.rb) are the fingerprint and issue functions of the same module.
  # A post-quantum passport verifies only under a PQ key pinned for its issuer (this SDK has no unbound opt-out).
  module PassportApi
    UNDEF = IntentV2::UNDEF
    PASSPORT_SIG_DOMAIN = "atlas-pca/passport-sig/v1\0"
    PASSPORT_VERSION = 1
    DEFAULT_PASSPORT_EVIDENCE_AGE_MS = 24 * 3600 * 1000
    MAX_SKEW_MS = 60_000
    SVN_RE = /\A(?:0|[1-9][0-9]*)\z/.freeze
    MALFORMED_MIN = "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)"

    module_function

    def pm(h, k) = h.is_a?(Hash) && h.key?(k) ? h[k] : UNDEF

    def read!(v, key)
      raise TypeError, "Cannot read properties of #{v.nil? ? 'null' : 'undefined'} (reading '#{key}')" if v.nil? || UNDEF.equal?(v)

      pm(v, key)
    end

    def str?(x) = x.is_a?(String) && !x.empty?

    # list.length of a JS value: Array / String have one, anything else is undefined (nil here)
    def js_length(list) = list.is_a?(Array) || list.is_a?(String) ? list.length : nil

    # list.includes(value): an Array by SameValueZero, a String by substring of String(value); anything else has no `includes`.
    def js_includes(list, value)
      return list.any? { |x| Attestation.same_value_zero?(x, value) } if list.is_a?(Array)
      return list.include?(Attestation.jstr(value)) if list.is_a?(String)

      raise TypeError, 'list.includes is not a function'
    end

    # {ok, reasons[]}: every reason the passport does not satisfy the binding, in the reference's order. Raises for a null passport / binding.
    def matches_binding(passport, binding)
      b = binding
      p = passport
      reasons = []
      need = lambda do |list, value, label|
        len = js_length(list)
        next unless Attestation.truthy?(list)
        next if len == 0 # rubocop:disable Style/NumericPredicate

        if UNDEF.equal?(value) then reasons << "#{label} required by binding but absent from passport"
        elsif !js_includes(list, value) then reasons << "#{label} '#{Attestation.jstr(value)}' not in allowlist"
        end
      end
      al = read!(b, 'model_allowlist')
      if Attestation.truthy?(al) && (js_length(al) || 0) > 0 && !js_includes(al, read!(p, 'model_id'))
        reasons << "model_id '#{Attestation.jstr(pm(p, 'model_id'))}' not in allowlist"
      end
      need.call(pm(b, 'weights_allowlist'), read!(p, 'weights_digest'), 'weights_digest')
      need.call(pm(b, 'system_prompt_allowlist'), pm(p, 'system_prompt_digest'), 'system_prompt_digest')
      need.call(pm(b, 'tool_manifest_allowlist'), pm(p, 'tool_manifest_digest'), 'tool_manifest_digest')
      op = pm(b, 'operator')
      if !UNDEF.equal?(op) && !Attestation.js_eq(pm(p, 'operator'), op)
        reasons << "operator '#{Attestation.jstr(pm(p, 'operator'))}' != required '#{Attestation.jstr(op)}'"
      end
      reasons << 'binding requires a hardware-rooted attestation' if Attestation.truthy?(pm(b, 'require_hardware')) && !Attestation.truthy?(pm(p, 'hardware_rooted'))
      reasons << 'binding requires hardware-measured weights' if Attestation.truthy?(pm(b, 'require_measured_weights')) && !Attestation.truthy?(pm(p, 'weights_measured'))
      mm = pm(b, 'min_measurement')
      unless UNDEF.equal?(mm)
        rm = pm(p, 'runtime_measurement')
        if mm.is_a?(String)
          reasons << 'runtime_measurement does not equal the pinned measurement' unless Attestation.js_eq(rm, mm)
        else
          bound = mm.is_a?(Hash) && mm.length == 1 ? pm(mm, 'svn') : UNDEF
          if !Attestation.safe_int?(bound) || bound.negative? || (bound.is_a?(Float) && bound.zero? && (1.0 / bound).negative?)
            reasons << MALFORMED_MIN
          else
            svn = rm.is_a?(String) && SVN_RE.match?(rm) ? rm.to_i : nil
            reasons << "runtime SVN #{Attestation.jstr(rm)} < required #{Attestation.jstr(bound)}" if svn.nil? || !Attestation.safe_int?(svn) || svn < bound
          end
        end
      end
      { 'ok' => reasons.empty?, 'reasons' => reasons }
    end

    # A registry over passports keyed by id (a later duplicate replaces the earlier in place; ids are not validated).
    class Registry
      def initialize(passports)
        @by_id = {}
        passports.each { |p| @by_id[PassportApi.pm(p, 'id')] = p }
      end

      def get(id) = @by_id[id]
      def has?(id) = @by_id.key?(id)
      def all = @by_id.values
    end

    def build_registry(passports) = Registry.new(passports)

    # 0..1: hardware rooting 0.4, weights 0.1 (0.2 measured), a prompt 0.1, a tool manifest 0.1, a known operator 0.2.
    def trust_score(passport, opts = nil)
      o = opts.nil? || UNDEF.equal?(opts) ? {} : opts
      s = 0
      s += 0.4 if Attestation.truthy?(read!(passport, 'hardware_rooted'))
      s += Attestation.truthy?(pm(passport, 'weights_measured')) ? 0.2 : 0.1 if Attestation.truthy?(pm(passport, 'weights_digest'))
      s += 0.1 if Attestation.truthy?(pm(passport, 'system_prompt_digest'))
      s += 0.1 if Attestation.truthy?(pm(passport, 'tool_manifest_digest'))
      ko = pm(o, 'knownOperators')
      s += 0.2 if !ko.nil? && !UNDEF.equal?(ko) && js_includes(ko, pm(passport, 'operator'))
      [0, [1, s].min].max
    end

    def passport_evidence_binding(passport_id, subject, nonce)
      { 'holderPub' => subject, 'grantRef' => "passport:#{passport_id}", 'epoch' => 0, 'nonce' => nonce }
    end

    # The signed passport. `opts`: 'issuerSecret' (32 bytes or a KeyPair), 'subject', 'exp', 'iat'?, 'nbf'?, 'evidence'? ({document, at?}),
    # 'suite'? ({'alg', 'pq' => the ML-DSA-65 key pair}). Raises on an id that is not the fingerprint, a hardware passport without evidence, an
    # unsafe time, exp <= nbf or an unknown suite.
    def sign_passport(passport, opts)
      raise TypeError, "Cannot read properties of #{passport.nil? ? 'null' : 'undefined'} (reading 'id')" unless passport.is_a?(Hash)

      o = opts
      raise 'signPassport: passport.id is not the fingerprint of its identity (use issuePassport)' unless Attestation.js_eq(pm(passport, 'id'), AtlasPca.passport_fingerprint(passport))

      evidence = pm(o, 'evidence')
      raise 'signPassport: hardware_rooted requires attestation evidence (fail closed)' if Attestation.truthy?(pm(passport, 'hardware_rooted')) && !Attestation.truthy?(evidence)

      at = evidence.is_a?(Hash) ? pm(evidence, 'at') : UNDEF
      raise RangeError, 'signPassport: evidence.at must be a safe integer' if Attestation.truthy?(evidence) && !UNDEF.equal?(at) && !Attestation.safe_int?(at)

      suite = pm(o, 'suite')
      alg = pm(suite, 'alg')
      suite_name = IntentV2.suite_of(alg)
      raise "signPassport: unknown signature alg '#{Attestation.jstr(alg)}'" if suite_name.nil?

      nullish = ->(x) { x.nil? || UNDEF.equal?(x) }
      iat = nullish.call(pm(o, 'iat')) ? pm(passport, 'issued_at') : pm(o, 'iat')
      nbf = nullish.call(pm(o, 'nbf')) ? iat : pm(o, 'nbf')
      exp = pm(o, 'exp')
      unless [iat, nbf, exp].all? { |x| Attestation.safe_int?(x) } && exp > nbf
        raise RangeError, 'signPassport: iat/nbf/exp must be safe integers with exp > nbf'
      end

      ev = Attestation.truthy?(evidence) ? evidence.merge('at' => nullish.call(at) ? iat : at) : UNDEF
      secret = pm(o, 'issuerSecret')
      signer = secret.is_a?(AtlasPca::KeyPair) ? secret : AtlasPca::KeyPair.new(secret)
      pq = pm(suite, 'pq')
      pq = nil if UNDEF.equal?(pq)
      body = { 'typ' => 'atlas-pca/passport', 'ver' => PASSPORT_VERSION, 'passport' => passport.reject { |_k, v| UNDEF.equal?(v) }, 'iss' => signer.public,
               'sub' => pm(o, 'subject'), 'iat' => iat, 'nbf' => nbf, 'exp' => exp, 'evidence' => ev }
      body = body.reject { |_k, v| UNDEF.equal?(v) }
      body = IntentV2.bind_suite_fields(body, alg, pq.respond_to?(:public) ? pq.public : UNDEF)
      msg = PASSPORT_SIG_DOMAIN.b + AtlasPca.canon_bytes(body)
      sig, pq_sig = AtlasPca.sign_with_suite(suite_name == 'ed25519' ? nil : suite_name, signer, pq, msg)
      out = body.merge('sig' => sig)
      out['pq_sig'] = pq_sig unless pq_sig.nil?
      out
    end

    def bad(reason, detail = nil) = detail.nil? || detail == '' || UNDEF.equal?(detail) ? { 'ok' => false, 'reason' => reason } : { 'ok' => false, 'reason' => reason, 'detail' => detail }

    # The verdict of a signed passport: {ok: true, passport, iss, sub, exp, hardware_verified} or {ok: false, reason, detail?}. `o`: 'trustedIssuers',
    # 'now', 'clockSkewMs'?, 'subject'?, 'maxEvidenceAgeMs'?, 'pqPins'?, 'revocation' (a callable ({id, iss, sub}) -> true | false, raising or absent
    # is revocation_unavailable) and 'attestationVerifier' (a callable (document, expected) -> {ok, bound, measured, reason}). Time checks, then
    # revocation, then hardware. Total.
    def verify_passport(sp, o)
      return bad('malformed') unless sp.is_a?(Hash) && sp['typ'] == 'atlas-pca/passport'

      pass = sp['passport']
      return bad('malformed') if pass.nil? || !sp.key?('passport')
      return bad('unsupported_version', Attestation.jstr(pm(sp, 'ver'))) unless Attestation.js_eq(pm(sp, 'ver'), PASSPORT_VERSION)

      alg = pm(sp, 'alg')
      return bad('unsupported_suite', Attestation.jstr(alg)) if !UNDEF.equal?(alg) && IntentV2.suite_of(alg).nil?

      iss = pm(sp, 'iss')
      sub = pm(sp, 'sub')
      sig = pm(sp, 'sig')
      unless str?(iss) && str?(sub) && str?(sig) && str?(pm(pass, 'id')) && str?(pm(pass, 'model_id')) && str?(pm(pass, 'operator')) && [true, false].include?(pm(pass, 'hardware_rooted'))
        return bad('malformed')
      end

      now = pm(o, 'now')
      iat = pm(sp, 'iat')
      nbf = pm(sp, 'nbf')
      exp = pm(sp, 'exp')
      return bad('malformed', 'times') unless [iat, nbf, exp, now].all? { |x| Attestation.safe_int?(x) } && exp > nbf

      issuers = pm(o, 'trustedIssuers')
      return bad('unknown_issuer') unless issuers.is_a?(Array) && issuers.include?(iss)

      body = sp.reject { |k, _| k == 'sig' || k == 'pq_sig' }
      msg = PASSPORT_SIG_DOMAIN.b + AtlasPca.canon_bytes(body)
      pins = pm(o, 'pqPins')
      return bad('bad_signature') unless IntentV2.verify_pinned_suite(alg, iss, pm(sp, 'pq_pk'), msg, sig, pm(sp, 'pq_sig'), pins.is_a?(Hash) ? pins : nil)
      return bad('id_mismatch') unless pass['id'] == AtlasPca.passport_fingerprint(pass)

      cs = pm(o, 'clockSkewMs')
      skew = cs.nil? || UNDEF.equal?(cs) ? 0 : (cs.is_a?(Numeric) && !(cs.is_a?(Float) && cs.nan?) ? [[cs, 0].max, MAX_SKEW_MS].min : Float::NAN)
      return bad('not_yet_valid') if now + skew < nbf
      return bad('expired') if now - skew >= exp

      subject = pm(o, 'subject')
      return bad('subject_mismatch') if !UNDEF.equal?(subject) && !Attestation.js_eq(subject, sub)

      rev = pm(o, 'revocation')
      return bad('revocation_unavailable', 'no revocation source') unless rev.respond_to?(:call)

      revoked = begin
        rev.call({ 'id' => pass['id'], 'iss' => iss, 'sub' => sub })
      rescue StandardError
        return bad('revocation_unavailable')
      end
      return bad('revoked') if revoked == true

      hw = pass['hardware_rooted']
      return ok_verdict(pass, iss, sub, exp, hw) unless hw

      hardware_verdict(sp, pass, sub, now, skew, o) || ok_verdict(pass, iss, sub, exp, hw)
    rescue StandardError, ScriptError, SecurityError, SystemStackError => e
      bad('malformed', e.message)
    end

    def ok_verdict(pass, iss, sub, exp, hw) = { 'ok' => true, 'passport' => pass, 'iss' => iss, 'sub' => sub, 'exp' => exp, 'hardware_verified' => hw }

    # nil when the hardware evidence is accepted, else the refusal verdict.
    def hardware_verdict(sp, pass, sub, now, skew, o)
      ev = pm(sp, 'evidence')
      ev = {} if ev.nil? || UNDEF.equal?(ev)
      doc = pm(ev, 'document')
      return bad('hardware_evidence_missing') unless doc.is_a?(Hash) && str?(doc['nonce'])

      at = pm(ev, 'at')
      return bad('hardware_evidence_missing', 'evidence.at') unless Attestation.safe_int?(at)

      max_age = pm(o, 'maxEvidenceAgeMs')
      max_age = DEFAULT_PASSPORT_EVIDENCE_AGE_MS if max_age.nil? || UNDEF.equal?(max_age)
      return bad('hardware_evidence_stale') if !Attestation.finite?(max_age) || max_age.negative? || now - at > max_age || at - now > skew

      verifier = pm(o, 'attestationVerifier')
      return bad('hardware_verifier_missing') unless verifier.respond_to?(:call)

      r = begin
        verifier.call(doc, passport_evidence_binding(pass['id'], sub, doc['nonce']).merge('nonceIssuedAt' => now))
      rescue StandardError => e
        return bad('hardware_attestation_failed', e.message.empty? ? 'error' : e.message)
      end
      return bad('hardware_attestation_failed', r.is_a?(Hash) ? pm(r, 'reason') : nil) unless r.is_a?(Hash) && r['ok'] == true && r['bound'] == true

      m = r['measured']
      m = {} unless m.is_a?(Hash)
      same = ->(k) { Attestation.js_eq(pm(m, k), pm(pass, k)) }
      mismatch = !r['measured'].is_a?(Hash) || !same.call('model_id') || !same.call('operator') ||
                 %w[weights_digest runtime_measurement system_prompt_digest tool_manifest_digest].any? { |k| !UNDEF.equal?(pm(pass, k)) && !same.call(k) } ||
                 (pm(pass, 'weights_measured') == true && pm(m, 'weights_measured') != true)
      mismatch ? bad('hardware_identity_mismatch') : nil
    end

    # {level, vendor?}: a passport that was not hardware verified is `software`; otherwise the verifier's attached label, else `unknown`.
    def passport_assurance(verdict, verifier = nil)
      return { 'level' => 'software' } unless verdict['hardware_verified']

      l = AtlasPca.assurance_label_of(verifier)
      out = { 'level' => l ? l['level'] : 'unknown' }
      out['vendor'] = l['vendor'] if l && Attestation.truthy?(l['vendor'])
      out
    end
  end
end
