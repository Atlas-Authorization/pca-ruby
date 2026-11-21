# frozen_string_literal: true

require 'set'
require_relative '../atlas_pca'
require_relative 'predicates'
require_relative 'js_compat'
require_relative 'intent_v2'
require_relative 'intent_omega'
require_relative 'intent_clopper'
require_relative 'signers_more'

# The wallet side of the PCA Intent Layer v2: the principal-signed answer (wire), friction tiers scaled by harm, cell coordinates
# over the wallet's own outcome space, the statistics behind the noise estimates, attention canaries and the approval-fatigue
# model. Native port of the TypeScript reference (@atlasauth/pca-wallet). The trusted card and clarification planning live in
# WalletCard, risk-priced escalation in WalletPricing. Values are plain JSON (String-keyed Hashes, Arrays, numbers, Strings); where
# the reference takes a callback or a Set, this port takes a callable or a Set. A reference throw is a raised exception.
module AtlasPca
  module Wallet
    UNDEF = Predicates::UNDEF
    O = IntentOmega

    INTENT_ANSWER_SIG_DOMAIN = "atlas-pca/intent-obs/v2\0"
    INTENT_ANSWER_REF_DOMAIN = 'atlas-pca/intent-answer-ref/v1'
    INTENT_TYPED_DOMAIN = 'atlas-pca/intent-typed/v1'
    INTENT_DEVICE_CHALLENGE_DOMAIN = 'atlas-pca/intent-device/v1'
    INTENT_ACTION_DOMAIN = 'atlas-pca/intent-action/v1'
    MIN_HOLD_MS = 2000
    FRICTION_ORDER = %w[tap hold typed device].freeze
    PROVENANCE_ORDER = %w[trusted first_party tool web agent].freeze
    DEFAULT_FRICTION_THRESHOLDS = { 'hTap' => 5, 'hDevice' => 100_000 }.freeze
    TAINTED = %w[web agent].freeze
    EMPTY_NOISE = { 'falseYes' => 0, 'correctNo' => 0, 'falseNo' => 0, 'correctYes' => 0 }.freeze
    NOISE_PRIOR = { 'a' => 1, 'b' => 9 }.freeze
    DEFAULT_FATIGUE = { 'betaF' => 0.005, 'etaStop' => 0.15, 'deltaC' => 0.05, 'freezeOn' => 'mean', 'assumeNoiseFree' => false, 'delta' => 0.05 }.freeze
    BELOW_HALF = 0.5 - 1e-9
    MAX_SAFE = (2**53) - 1

    ANS_KEYS = %w[v kind map_digest session question_id verb cell y partial source observed_at ux signer alg sig].freeze
    UX_KEYS = %w[tier rendered_digest typed_digest hold_ms webauthn canary action_digest consent_for_action].freeze
    WA_KEYS = %w[credential_id authenticator_data client_data_json signature].freeze
    QID_RE = /\A[A-Za-z0-9_-]{1,64}\z/
    ACC_RE = /\Aenv\.acc\.([A-Za-z0-9_.-]+)\.post\z/
    MON_RE = /\Aenv\.mon\.([A-Za-z0-9_.-]+)\.state\z/
    PROV_RE = /\Aenv\.prov\.([^\n\r  ]+)\z/
    WORLD_RE = /\Aenv\.world\.([A-Za-z0-9_.-]+)\z/
    LANCZOS = [676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905,
               -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7].freeze

    module_function

    # ---- JavaScript value helpers shared by the wallet modules ---------------------------------------------------------------

    def number?(v) = v.is_a?(Integer) || v.is_a?(Float)
    def finite_number?(v) = number?(v) && (v.is_a?(Integer) || v.finite?)
    def neg_zero?(v) = v.is_a?(Float) && v.zero? && (1.0 / v).negative?

    # Number.isSafeInteger (accepts -0)
    def safe_int?(v)
      return false unless number?(v)
      return v.abs <= MAX_SAFE if v.is_a?(Integer)

      v.finite? && v == v.floor && v.abs <= MAX_SAFE
    end

    # A safe integer that is not -0 (the wire isInt).
    def int?(v) = safe_int?(v) && !neg_zero?(v)

    def integral?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor)

    def js_str(v) = Predicates.js_string(v)

    # float(x) as the reference's arithmetic sees a number: numbers and booleans, a numeric String; anything else throws.
    def fl(x)
      case x
      when Integer, Float then x.to_f
      when true then 1.0
      when false then 0.0
      when String then Float(x.strip)
      else raise TypeError, "not a number: #{x.inspect}"
      end
    rescue ArgumentError
      raise TypeError, "not a number: #{x.inspect}"
    end

    def truthy?(v)
      return false if v.nil? || v == false || v.equal?(UNDEF)
      return !v.zero? && !(v.is_a?(Float) && v.nan?) if number?(v)
      return !v.empty? if v.is_a?(String)

      true
    end

    def u16key(s) = O.u16key(s)

    # for...of over a JSON value: arrays and strings iterate, anything else is not iterable.
    def iterate(v)
      return v if v.is_a?(Array)
      return v.chars if v.is_a?(String)

      raise TypeError, 'value is not iterable'
    end

    # ---- friction (wire.ts, friction.ts) -------------------------------------------------------------------------------------

    def friction_tier?(x) = x.is_a?(String) && FRICTION_ORDER.include?(x)
    def friction_rank(t) = t.is_a?(String) && FRICTION_ORDER.include?(t) ? FRICTION_ORDER.index(t) : -1

    def max_friction(*ts)
      best = 'tap'
      ts.each { |t| best = t if friction_rank(t) > friction_rank(best) }
      best
    end

    def satisfies_tier(given, required) = friction_rank(given) >= friction_rank(required)
    def provenance_level?(x) = x.is_a?(String) && PROVENANCE_ORDER.include?(x)

    # The least trusted level of a set; "agent" for an empty or unknown set (fail closed).
    def worst_provenance(levels)
      best = -1
      iterate(levels).each do |lv|
        return 'agent' unless provenance_level?(lv)

        best = [best, PROVENANCE_ORDER.index(lv)].max
      end
      best.negative? ? 'agent' : PROVENANCE_ORDER[best]
    end

    def friction_for(inp, th = nil)
      th = DEFAULT_FRICTION_THRESHOLDS if th.nil?
      harm = inp['expectedHarm']
      return { 'tier' => 'device', 'rules' => ['harm-unknown'] } unless finite_number?(harm) && harm >= 0

      rules = []
      tier = 'tap'
      raise_to = lambda do |t, why|
        rules << why if friction_rank(t) >= friction_rank(tier)
        tier = max_friction(tier, t)
      end
      rev = inp['reversibility']
      raise_to.call('hold', 'rate-limited') if rev == 'rate_limited'
      raise_to.call('hold', 'harm>=h_tap') if harm >= th['hTap']
      raise_to.call('typed', 'irreversible') if rev == 'irreversible'
      prov = inp['provenance']
      prov_list = prov.nil? ? [] : (prov.is_a?(Hash) ? prov.keys : iterate(prov))
      tainted_critical = prov_list.any? do |p|
        raise TypeError, 'provenance entry is not an object' unless p.is_a?(Hash)

        p['sensitivity'] == 'critical' && TAINTED.include?(worst_provenance(p['levels']))
      end
      raise_to.call('typed', 'tainted-critical') if tainted_critical
      raise_to.call('device', 'critical-irreversible') if truthy?(inp['widensCriticalIdentity']) && rev == 'irreversible'
      raise_to.call('device', 'harm>=h_device') if harm >= th['hDevice']
      raise_to.call(FRICTION_ORDER[[FRICTION_ORDER.length - 1, friction_rank(tier) + 1].min], 'single-source') if truthy?(inp['singleSource'])
      raise_to.call(inp['siteMin'], 'site-minimum') if inp.key?('siteMin')
      { 'tier' => tier, 'rules' => rules }
    end

    # ---- helpers (wire.ts) -----------------------------------------------------------------------------------------------------

    def obj?(v) = v.is_a?(Hash)
    def b64u32?(v) = !AtlasPca.b64d(v, 32).nil?
    def coords_error(c) = AtlasPca.cell_coords_error(c)

    def g(o, k) = o.is_a?(Hash) && o.key?(k) ? o[k] : UNDEF

    # Object.entries of a JSON value (strings and arrays yield their indices; null and undefined throw).
    def entries(v)
      case v
      when Hash then v.to_a
      when Array then v.each_with_index.map { |x, i| [i.to_s, x] }
      when String then v.chars.each_with_index.map { |c, i| [i.to_s, c] }
      else
        raise TypeError, 'Cannot convert undefined or null to object' if v.nil? || v.equal?(UNDEF)

        []
      end
    end

    # JSON.parse(JSON.stringify(v)): -0 becomes 0, an integral float an integer.
    def plain(v)
      case v
      when Hash then v.transform_values { |x| plain(x) }
      when Array then v.map { |x| plain(x) }
      when Float then v.finite? && v == v.floor && v.abs <= MAX_SAFE ? v.to_i : v
      else v
      end
    end

    # The action digest of an attempted action (what intent_required.action_digest and a JIT consent bind to).
    def pca_action_digest(a)
      raise TypeError, 'not an object' unless a.is_a?(Hash)

      params = a.key?('params') ? a['params'] : nil
      act = {}
      [['verb', g(a, 'verb')], ['resource', g(a, 'resource')], ['params_digest', AtlasPca.params_digest(params)],
       ['reversibility_class', g(a, 'reversibility_class')]].each do |k, v|
        raise TypeError, 'canonicalize: undefined' if v.equal?(UNDEF)

        act[k] = v
      end
      AtlasPca.hash_canonical({ 'd' => INTENT_ACTION_DOMAIN, 'action' => act })
    end

    # The default projection of an attempted action onto Omega paths: the resource and every scalar param.
    def action_values_of(a)
      values = {}
      res = g(a, 'resource')
      values['action.resource'] = res unless res.equal?(UNDEF)
      entries(g(a, 'params')).each do |k, v|
        values["action.params.#{k}"] = v if v.is_a?(String) || finite_number?(v)
      end
      out = { 'values' => values }
      out['verb'] = a['verb'] unless g(a, 'verb').equal?(UNDEF)
      out
    end

    # ---- M6: the signed answer ---------------------------------------------------------------------------------------------------

    def num_eq?(v, n) = number?(v) && v == n

    def only_keys(o, allowed)
      o.each_key { |k| return "unknown member \"#{k}\"" unless allowed.include?(k) }
      nil
    end

    def partial_error(p)
      return 'partial.path must be a non-empty string' if !obj?(p) || !p['path'].is_a?(String) || p['path'].empty?

      keys = p.keys.reject { |k| k == 'path' }
      return 'partial must carry exactly one of upTo / from / except / notFor' unless keys.length == 1

      k = keys[0]
      v = p[k]
      return "partial.#{k} must be an integer" if %w[upTo from].include?(k) && !int?(v)
      return 'partial.except must be a non-empty integer array' if k == 'except' && !(v.is_a?(Array) && !v.empty? && v.all? { |x| int?(x) })
      if k == 'notFor' && !(v.is_a?(Array) && !v.empty? && v.all? { |x| x.is_a?(String) && !x.empty? })
        return 'partial.notFor must be a non-empty string array'
      end
      return "unknown partial member \"#{k}\"" unless %w[upTo from except notFor].include?(k)

      nil
    end

    def answer_shape_error(a)
      return 'not an object' unless obj?(a)

      extra = only_keys(a, ANS_KEYS)
      return extra if extra
      return 'not a pca-intent-observation v2' if !num_eq?(a['v'], 2) || a['kind'] != 'pca-intent-observation'

      %w[map_digest session signer].each { |k| return "#{k} is not canonical base64url (32 bytes)" unless b64u32?(a[k]) }
      qid = a['question_id']
      return 'question_id must match [A-Za-z0-9_-]{1,64}' if !qid.is_a?(String) || !QID_RE.match?(qid)
      return 'verb must be a non-empty string' if !a['verb'].is_a?(String) || a['verb'].empty?

      ce = coords_error(a['cell'])
      return "cell: #{ce}" if ce
      return 'y must be 0 or 1' unless num_eq?(a['y'], 0) || num_eq?(a['y'], 1)

      if a.key?('partial')
        pe = partial_error(a['partial'])
        return pe if pe
        return 'a partial answer carries y = 1 (yes for the part)' unless num_eq?(a['y'], 1)
      end
      return 'source must be elicitation or clarification' unless %w[elicitation clarification].include?(a['source'])
      return 'observed_at must be a non-negative safe integer' if !int?(a['observed_at']) || a['observed_at'].negative?
      return 'alg must be ed25519' if a['alg'] != 'ed25519'

      ux = a['ux']
      return 'ux must be an object' unless obj?(ux)

      ue = only_keys(ux, UX_KEYS)
      return "ux: #{ue}" if ue
      return 'ux.tier is not a friction tier' unless friction_tier?(ux['tier'])
      return 'ux.rendered_digest is not canonical base64url (32 bytes)' unless b64u32?(ux['rendered_digest'])
      return 'ux.canary must be a boolean' unless [true, false].include?(ux['canary'])
      return 'ux.typed_digest is not canonical base64url (32 bytes)' if ux.key?('typed_digest') && !b64u32?(ux['typed_digest'])
      return 'ux.hold_ms must be a non-negative integer' if ux.key?('hold_ms') && !(int?(ux['hold_ms']) && ux['hold_ms'] >= 0)
      return 'ux.action_digest is not canonical base64url (32 bytes)' if ux.key?('action_digest') && !b64u32?(ux['action_digest'])
      return 'ux.consent_for_action must be a boolean' if ux.key?('consent_for_action') && ![true, false].include?(ux['consent_for_action'])
      if ux['consent_for_action'] == true && (!ux.key?('action_digest') || !num_eq?(a['y'], 1) || a.key?('partial'))
        return 'consent_for_action needs action_digest and a plain yes'
      end
      return 'a canary never consents to an action' if ux['consent_for_action'] == true && ux['canary'] == true

      if ux.key?('webauthn')
        wa = ux['webauthn']
        return 'ux.webauthn is malformed' if !obj?(wa) || only_keys(wa, WA_KEYS) || !WA_KEYS.all? { |k| wa[k].is_a?(String) }
      end
      if num_eq?(a['y'], 1) && !ux['canary']
        tier = ux['tier']
        return "hold tier needs hold_ms >= #{MIN_HOLD_MS}" if tier == 'hold' && !(int?(ux['hold_ms']) && ux['hold_ms'] >= MIN_HOLD_MS)
        return 'typed tier needs typed_digest' if tier == 'typed' && !ux.key?('typed_digest')
        return 'device tier needs a WebAuthn assertion' if tier == 'device' && !ux.key?('webauthn')
      end
      nil
    end

    def answer_body(a)
      body = {}
      %w[v kind map_digest session question_id verb cell y partial source observed_at ux signer alg].each { |k| body[k] = a[k] if a.key?(k) }
      plain(body)
    end

    def domain_message(domain, body) = domain.b + AtlasPca.strict_bytes(body)

    # Wallet side: sign the principal's answer with the principal key (Ed25519, domain-separated, over the canonical body).
    # `key` is the principal's AtlasPca::KeyPair.
    def sign_intent_answer(a, key)
      base = a.dup
      base.merge!('v' => 2, 'kind' => 'pca-intent-observation', 'signer' => key.public, 'alg' => 'ed25519')
      body = answer_body(base)
      bad = answer_shape_error(body)
      raise ArgumentError, "signIntentAnswer: #{bad}" if bad

      body.merge('sig' => AtlasPca.b64e(key.sign(domain_message(INTENT_ANSWER_SIG_DOMAIN, body))))
    end

    # Verify a signed answer; `principals` restricts the signer (the keys named in the session root). Never raises.
    def verify_intent_answer(a, principals = nil)
      bad = answer_shape_error(a)
      return { 'ok' => false, 'reason' => bad } if bad
      return { 'ok' => false, 'reason' => 'signer is not a principal of the session' } if !principals.nil? && !(principals.is_a?(Array) && principals.include?(a['signer']))

      sig = a['sig']
      return { 'ok' => false, 'reason' => 'bad signature' } unless sig.is_a?(String)

      msg = domain_message(INTENT_ANSWER_SIG_DOMAIN, answer_body(a))
      AtlasPca.verify_b64u(a['signer'], msg, sig) ? { 'ok' => true } : { 'ok' => false, 'reason' => 'bad signature' }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "malformed answer: #{e.message}" }
    end

    # Content address of a signed answer (evidence bundles and delta grants refer to it).
    def answer_ref(a) = AtlasPca.hash_canonical({ 'd' => INTENT_ANSWER_REF_DOMAIN, 'a' => a })
    def typed_digest(question_id, normalized_value) = AtlasPca.hash_canonical({ 'd' => INTENT_TYPED_DOMAIN, 'q' => question_id, 'v' => normalized_value })

    # The 32-byte WebAuthn challenge of a device-tier answer: binds the question, the card the human saw, y and the action.
    def device_challenge(question_id, rendered_digest, y, action_digest = nil)
      AtlasPca.hash_canonical({ 'd' => INTENT_DEVICE_CHALLENGE_DOMAIN, 'q' => question_id, 'r' => rendered_digest, 'y' => y, 'a' => action_digest })
    end

    # ---- cell coordinates <-> the wallet's own Omega (box.ts) ----------------------------------------------------------------

    def coord_key_of(path)
      if (m = ACC_RE.match(path)) then return m[1] end
      if (m = MON_RE.match(path)) then return "mon:#{m[1]}" end
      if (m = PROV_RE.match(path)) then return "prov:#{m[1]}" end
      if (m = WORLD_RE.match(path)) then return m[1] end

      path
    end

    def cat_label(d, i) = d['values'][i]['value']

    # Resolve coordinates to a box of cells of the verb's space: {ok, vs, box} or {ok: false, reason}. Every dimension must be
    # named exactly once; anything the wallet cannot resolve exactly is refused.
    def resolve_coords(omega, verb, coords)
      vs = omega['verbs'].find { |v| v['verb'] == verb }
      return { 'ok' => false, 'reason' => "verb #{verb.is_a?(String) ? verb : js_str(verb)} is not in the wallet's outcome space" } if vs.nil?

      by_key = {}
      vs['dims'].each_with_index do |d, k|
        by_key[d['path']] = k
        by_key[coord_key_of(d['path'])] = k
      end
      named = Set.new
      entries(coords).each do |key, _|
        k = by_key[key]
        return { 'ok' => false, 'reason' => "unknown dimension #{key}" } if k.nil?
        return { 'ok' => false, 'reason' => "dimension #{vs['dims'][k]['path']} is named twice" } if named.include?(k)

        named << k
      end
      box = []
      vs['dims'].each do |d|
        c = g(coords, d['path'])
        c = g(coords, coord_key_of(d['path'])) if c.equal?(UNDEF) || c.nil?
        return { 'ok' => false, 'reason' => "coordinates leave out dimension #{d['path']}" } if c.equal?(UNDEF)
        raise TypeError, 'Cannot read properties of null' if c.nil?

        if d['kind'] == 'num'
          unless c.is_a?(Array) && c.length == 2 && number?(c[0]) && number?(c[1])
            return { 'ok' => false, 'reason' => "dimension #{d['path']} is numeric: expected an index range" }
          end

          lo, hi = c
          unless integral?(lo) && integral?(hi) && !neg_zero?(lo) && !neg_zero?(hi) && lo >= 0 && lo <= hi && hi < O.cell_count(d)
            return { 'ok' => false, 'reason' => "index range of #{d['path']} is out of range" }
          end

          box << (lo.to_i..hi.to_i).to_a
        else
          raise TypeError, 'c.every is not a function' unless c.is_a?(Array)
          return { 'ok' => false, 'reason' => "dimension #{d['path']} is categorical: expected a value set" } unless c.all? { |x| x.is_a?(String) }

          ids = []
          c.each do |label|
            hits = d['values'].each_index.select { |j| d['values'][j]['value'] == label }
            return { 'ok' => false, 'reason' => "unknown value #{Js.json_string(label)} for #{d['path']}" } if hits.empty?
            return { 'ok' => false, 'reason' => "value #{Js.json_string(label)} names two cells of #{d['path']}" } if hits.length > 1

            ids << hits[0]
          end
          box << ids.uniq.sort
        end
      end
      { 'ok' => true, 'vs' => vs, 'box' => box }
    end

    # The coordinates of a box (the inverse of resolve_coords; numeric sides must be contiguous).
    def coords_of_box(vs, box)
      out = {}
      vs['dims'].each_with_index do |d, k|
        ids = box[k]
        if d['kind'] == 'num'
          lo = ids.min
          hi = ids.max
          raise ArgumentError, "coordsOfBox: numeric side of #{d['path']} is not contiguous" if hi - lo + 1 != ids.length

          out[d['path']] = [lo, hi]
        else
          out[d['path']] = ids.map { |i| cat_label(d, i) }
        end
      end
      out
    end

    def coords_of_cell(vs, idx) = coords_of_box(vs, idx.map { |i| [i] })
    def cell_in_box(box, idx) = box.length == idx.length && box.each_with_index.all? { |ids, k| ids.include?(idx[k]) }

    def box_cells(box)
      out = [[]]
      box.each { |ids| out = out.flat_map { |pre| ids.map { |i| pre + [i] } } }
      out
    end

    def box_size(box) = box.reduce(1) { |n, ids| n * ids.length }

    # The cell of a concrete action in the wallet's Omega ({vs, idx}); nil when it falls outside it (fail closed).
    def cell_of_action(omega, a)
      raise TypeError, 'not an object' unless a.is_a?(Hash)

      vs = omega['verbs'].find { |v| v['verb'] == a['verb'] }
      return nil if vs.nil?

      values = a.key?('values') ? a['values'] : nil
      raise TypeError, "Cannot use 'in' operator" unless values.is_a?(Hash) || values.is_a?(Array)

      vs['dims'].each { |d| return nil unless values.is_a?(Hash) && values.key?(d['path']) }
      idx = O.cell_of(vs, { 'verb' => a['verb'], 'values' => values })
      idx.nil? ? nil : { 'vs' => vs, 'idx' => idx }
    end

    def flat_index(vs, idx)
      f = 0
      vs['dims'].each_with_index { |d, k| f = (f * O.cell_count(d)) + idx[k] }
      f
    end

    # ---- stats (stats.ts) --------------------------------------------------------------------------------------------------------

    def ln_gamma(x)
      x = fl(x)
      return O.js_log(Math::PI / Math.sin(Math::PI * x)) - ln_gamma(1 - x) if x < 0.5

      z = x - 1
      a = 0.99999999999980993
      t = z + 7.5
      LANCZOS.each_with_index { |c, i| a += c / (z + i + 1) }
      (0.5 * Math.log(2 * Math::PI)) + ((z + 0.5) * Math.log(t)) - t + Math.log(a)
    end

    # The continued fraction of I_x(a, b) (modified Lentz; a zero denominator is replaced by 1e-300, never divided by).
    def betacf(a, b, x)
      a = fl(a)
      b = fl(b)
      x = fl(x)
      tiny = 1e-300
      qab = a + b
      qap = a + 1
      qam = a - 1
      c = 1.0
      d = 1 - ((qab * x) / qap)
      d = tiny if d.abs < tiny
      d = 1 / d
      h = d
      (1..300).each do |m|
        m2 = 2 * m
        aa = (m * (b - m) * x) / ((qam + m2) * (a + m2))
        d = 1 + (aa * d)
        d = tiny if d.abs < tiny
        c = 1 + (aa / c)
        c = tiny if c.abs < tiny
        d = 1 / d
        h *= d * c
        aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2))
        d = 1 + (aa * d)
        d = tiny if d.abs < tiny
        c = 1 + (aa / c)
        c = tiny if c.abs < tiny
        d = 1 / d
        dl = d * c
        h *= dl
        break if (dl - 1).abs < 1e-15
      end
      h
    end

    # Regularized incomplete beta I_x(a, b), a, b > 0, x in [0, 1].
    def beta_inc(x, a, b)
      raise ArgumentError, 'betaInc: a and b must be > 0' unless a > 0 && b > 0
      return 0 if x <= 0
      return 1 if x >= 1

      a = fl(a)
      b = fl(b)
      x = fl(x)
      lbt = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + (a * Math.log(x)) + (b * Math.log(1 - x))
      bt = Math.exp(lbt)
      return (bt * betacf(a, b, x)) / a if x < (a + 1) / (a + b + 2)

      1 - ((bt * betacf(b, a, 1 - x)) / b)
    end

    # The q-quantile of Beta(a, b) by bisection (200 steps).
    def beta_quantile(q, a, b)
      raise ArgumentError, 'betaQuantile: q must be in [0, 1]' unless q >= 0 && q <= 1
      return 0 if q.zero?
      return 1 if q == 1

      lo = 0.0
      hi = 1.0
      200.times do
        mid = (lo + hi) / 2
        if beta_inc(mid, a, b) < q then lo = mid else hi = mid end
      end
      hi
    end

    def clopper_pearson_upper(k, n, alpha) = IntentClopper.clopper_pearson_upper(k, n, alpha)

    # Binary entropy in bits.
    def bin_ent(p)
      return 0 if p <= 0 || p >= 1

      -((p * Math.log2(p)) + ((1 - p) * Math.log2(1 - p)))
    end

    # ---- canaries (canary.ts) -----------------------------------------------------------------------------------------------------

    # Fold one canary answer into the counts (pure).
    def record_canary(n, expected, y)
      out = n.dup
      if num_eq?(expected, 0)
        if num_eq?(y, 1) then out['falseYes'] = n['falseYes'] + 1 else out['correctNo'] = n['correctNo'] + 1 end
      elsif num_eq?(y, 0)
        out['falseNo'] = n['falseNo'] + 1
      else
        out['correctYes'] = n['correctYes'] + 1
      end
      out
    end

    def estimate_noise(n, delta_c = 0.05)
      raise ArgumentError, 'estimateNoise: deltaC must be in (0, 1)' unless delta_c > 0 && delta_c < 1

      ap = NOISE_PRIOR['a'] + n['falseYes']
      bp = NOISE_PRIOR['b'] + n['correctNo']
      an = NOISE_PRIOR['a'] + n['falseNo']
      bn = NOISE_PRIOR['b'] + n['correctYes']
      known_no = n['falseYes'] + n['correctNo']
      known_yes = n['falseNo'] + n['correctYes']
      {
        'etaPos' => ap.to_f / (ap + bp),
        'etaNeg' => an.to_f / (an + bn),
        'etaPosUpper' => beta_quantile(1 - delta_c, ap, bp),
        'etaNegUpper' => beta_quantile(1 - delta_c, an, bn),
        'etaPosCP' => known_no.zero? ? 1 : clopper_pearson_upper(n['falseYes'], known_no, delta_c),
        'etaNegCP' => known_yes.zero? ? 1 : clopper_pearson_upper(n['falseNo'], known_yes, delta_c),
        'asked' => known_no + known_yes
      }
    end

    def cell_key(verb, idx) = "#{js_str(verb)}|#{iterate(idx).map { |i| integral?(i) && !i.is_a?(String) ? js_str(i.to_i) : js_str(i) }.join(',')}"

    # Cells one step outside the confirmed region in exactly one dimension (deterministic order).
    def boundary_neighbours(omega, confirmed)
      inside = confirmed.to_set { |c| cell_key(c['verb'], c['idx']) }
      out = {}
      confirmed.each do |c|
        vs = omega['verbs'].find { |v| v['verb'] == c['verb'] }
        next if vs.nil?

        vs['dims'].each_with_index do |d, k|
          n = O.cell_count(d)
          alts = d['kind'] == 'num' ? [c['idx'][k] - 1, c['idx'][k] + 1] : (0...n).to_a
          alts.each do |a|
            next if a.negative? || a >= n || a == c['idx'][k]

            idx = c['idx'].dup
            idx[k] = a
            key = cell_key(c['verb'], idx)
            out[key] = { 'verb' => c['verb'], 'idx' => idx } unless inside.include?(key)
          end
        end
      end
      out.sort_by { |k, _| u16key(k) }.map { |_, v| v }
    end

    # Decide whether to insert a canary now, and which (nil: no canary this time). ctx carries omega, confirmed, knownNo (callable
    # (verb, idx) -> "ceiling" | "veto" | nil), knownYes, exclude (Set of `verb|i,j,..` keys), rand (callable), optional rho
    # (default 0.1), lowHarmSession and canariesSoFar.
    def pick_canary(ctx)
      rho = ctx['rho']
      rho = 0.1 if rho.nil?
      raise ArgumentError, 'pickCanary: rho must be in [0, 1]' unless rho >= 0 && rho <= 1
      return nil if truthy?(ctx['lowHarmSession']) && ctx['canariesSoFar'] >= 1
      return nil unless ctx['rand'].call < rho

      exclude = ctx['exclude']
      no = []
      boundary_neighbours(ctx['omega'], ctx['confirmed']).each do |c|
        next if exclude.include?(cell_key(c['verb'], c['idx']))

        why = ctx['knownNo'].call(c['verb'], c['idx'])
        no << { 'verb' => c['verb'], 'idx' => c['idx'], 'expected' => 0, 'source' => why } if truthy?(why)
      end
      yes = ctx['knownYes'].reject { |c| exclude.include?(cell_key(c['verb'], c['idx'])) }
                           .map { |c| { 'verb' => c['verb'], 'idx' => c['idx'].dup, 'expected' => 1, 'source' => 'confirmed-yes' } }
      return nil if no.empty? && yes.empty?

      pool = if !no.empty? && !yes.empty?
               ctx['rand'].call < 0.5 ? no : yes
             else
               no.empty? ? yes : no
             end
      pool[[pool.length - 1, (ctx['rand'].call * pool.length).floor].min]
    end

    # ---- approval fatigue (fatigue.ts) ---------------------------------------------------------------------------------------------

    # eta+ under load: base + beta_f * n_recent, capped at 1/2.
    def eta_under_load(base, beta_f, n_recent)
      raise ArgumentError, 'etaUnderLoad: bad arguments' unless base >= 0 && beta_f >= 0 && integral?(n_recent) && n_recent >= 0

      [0.5, base + (beta_f * n_recent)].min
    end

    def noise_state(counts, n_recent, model = nil)
      model = DEFAULT_FATIGUE if model.nil?
      e = estimate_noise(counts, model['deltaC'])
      eta_pos = eta_under_load(e['etaPos'], model['betaF'], n_recent)
      eta_pos_bar = eta_under_load(e['etaPosUpper'], model['betaF'], n_recent)
      stat = model['freezeOn'] == 'mean' ? eta_pos : eta_pos_bar
      { 'etaPos' => eta_pos, 'etaPosBar' => eta_pos_bar, 'etaNegBar' => [0.5, e['etaNegUpper']].min, 'frozen' => stat > model['etaStop'] }
    end

    def admission_policy(state, model = nil)
      model = DEFAULT_FATIGUE if model.nil?
      return { 'tau' => 1, 'etaPos' => 0, 'etaNeg' => 0, 'doubleConfirmIrreversible' => false, 'falseAdmitBound' => 0 } if truthy?(model['assumeNoiseFree'])
      raise ArgumentError, 'admissionPolicy: delta must be in (0, 1)' unless model['delta'] > 0 && model['delta'] < 1

      ep = [BELOW_HALF, state['etaPosBar']].min
      en = [BELOW_HALF, state['etaNegBar']].min
      { 'tau' => 1 - model['delta'], 'etaPos' => ep, 'etaNeg' => en, 'doubleConfirmIrreversible' => ep > 0, 'falseAdmitBound' => ep * ep }
    end

    # Sliding-window question counter shared across sessions (the per-hour cap is an accumulator, so an agent cannot split around
    # it by opening sessions). Keeps only timestamps inside the window.
    class SlidingWindowCounter
      def initialize(window_ms = 3_600_000)
        raise ArgumentError, 'SlidingWindowCounter: windowMs must be a positive integer' unless Wallet.integral?(window_ms) && window_ms > 0

        @window_ms = window_ms
        @times = []
      end

      def prune(now)
        return unless Wallet.finite_number?(now) # an infinite clock must never forget a recorded event

        @times.shift while !@times.empty? && @times[0] <= now - @window_ms
      end
      private :prune

      def count(now)
        prune(now)
        @times.length
      end

      # Record one event at `now` if the count is below `cap`; false (and nothing recorded) otherwise.
      def try_add(now, cap)
        return false unless Wallet.finite_number?(now)

        prune(now)
        return false unless @times.length < cap
        raise ArgumentError, 'SlidingWindowCounter: time went backwards' if !@times.empty? && !(now >= @times[-1])

        @times << now
        true
      end
    end

    # Two "yes" answers at typed or device tier, on different screens, with at least one other screen between them.
    def double_confirmed(records)
      strong = records.select { |r| %w[typed device].include?(r['tier']) }.map { |r| r['screen'] }.sort
      strong.each_index { |i| ((i + 1)...strong.length).each { |j| return true if strong[j] - strong[i] >= 2 } }
      false
    end
  end
end
