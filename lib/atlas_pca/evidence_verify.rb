# frozen_string_literal: true

# `EvidenceVerify.verify_evidence_bundle`: deterministic replay of a dispute evidence bundle (Intent Layer v2). Every finding is
# RECOMPUTED from the signed artifacts; nothing the bundle claims about itself (the canary summary, the accumulator posts, the
# verdicts) is taken on trust. The output is a findings report whose text comes from fixed templates, so two readers of the same
# bundle with the same trust inputs get byte-identical reports (`report_digest`). Three statuses, never mixed: `pass` (re-verified
# here), `fail` (re-verification refuted it), `unverified` (this verifier had no way to check it: no verifier for the format, an
# unopened map, a missing trust key); `complete` is false whenever one is present.
#
# Port of the TypeScript reference (@atlasauth/pca-evidence, verifyEvidenceBundle). Never raises on a malformed bundle: it is a report
# with a failed `shape` finding, and a fault inside the replay is a failed `shape` finding too (fail closed). A `trust['verifiers'][name]`
# port is a callable `(artifact, bundle) -> {'ok' => bool, 'reason' => str}` that OVERRIDES the core default of that artifact.
require_relative '../atlas_pca'
require_relative 'analyzer_js'
require_relative 'evidence'
require_relative 'intent_history'
require_relative 'intent_jit'
require_relative 'intent_mapkit'
require_relative 'intent_statement'
require_relative 'ledger'
require_relative 'webauthn'
require_relative 'wallet'

module AtlasPca
  module EvidenceVerify
    extend AnalyzerJs

    UNDEF = AnalyzerJs::UNDEF
    E = AtlasPca::Evidence
    INTENT_ANCHOR_LOG = 'pca-intent:v1'
    DEFAULT_REVOCATION_MAX_AGE_S = { 'payment' => 60, 'default' => 300 }.freeze
    V2_CHECKS = %w[schema intent_session accumulators].freeze
    TS_CHECK_NAMES = { 'chain' => 'cap_chain', 'freshness_anchor' => 'freshness' }.freeze

    TEMPLATES = {
      'shape' => 'The bundle is well formed (pca-intent-evidence v1, closed members)',
      'principal.pinned' => 'Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)',
      'trust.principals' => 'The pinned principal keys (trust.principals) are well formed',
      'statement.commit' => 'The session root commits to the intent statement the bundle names',
      'statement.opening' => 'The opened statement is signed by a principal and hashes to the committed ref',
      'session_root.signature' => 'The session root is signed by one of its principal keys',
      'schema.signature' => 'The action schema is signed by a site key',
      'schema.digest' => 'The session root binds this action schema',
      'schema.anchor' => 'The action schema is anchored in a transparency log',
      'map.replay' => 'The task map replays to its committed digest',
      'root_grant' => 'The root intent grant G_0 is principal-signed and bound to the session',
      'delta.signature' => 'The delta grant is a root capability signed by a principal of the session',
      'delta.chain' => 'The delta grant chains to the session (session, seq, prev, root)',
      'delta.backed' => 'Every delta grant is backed by a principal "yes" answer',
      'answer.signature' => 'The answer is signed by a principal of the session, for this session',
      'answer.map' => 'The answer refers to a map version in the bundle',
      'answer.tier' => 'The answer meets the site minimum friction tier for the verb',
      'answer.typed' => 'The typed-tier value re-derives the signed typed digest',
      'answer.device' => 'The device-tier WebAuthn assertion verifies with user verification',
      'canaries.summary' => 'The canary summary equals the one recomputed from the signed canary answers',
      'pcactn.verify' => 'The PCActn verifies (signature, chain, audience, validity at its issue time)',
      'pcactn.root' => "The PCActn's root capability is G_0 or a bundled delta grant",
      'pcactn.session' => "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
      'subject.present' => 'The subject PCActn is in the bundle',
      'jit.consent' => 'The irreversible subject action carries a principal JIT consent bound to its exact action digest',
      'accumulator.declared' => 'The accumulator is declared in the session root',
      'accumulator.arithmetic' => 'The accumulator posts are the running values of the counted events',
      'accumulator.cap' => "Every accumulator post is within the admitting grant's cap",
      'accumulator.receipts' => 'The sequencer reservation receipt verifies and is consistent',
      'acc.keysets.equivocation' => 'No two different sequencer key sets share one root and version',
      'acc.keysets' => "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
      'trust.acc' => 'The verifier freshness configuration (trust.acc) is well formed',
      'effect.binding' => "The effect record is bound to the PCActn's signed params",
      'effect.charged' => 'The charged amount is within the confirmed value',
      'effect.frame' => 'No monitored state outside the write set changed',
      'effect.signature' => 'The effect record is signed by the site',
      'verdict.signature' => 'The site verdict record verifies',
      'fact.signature' => 'The oracle fact verifies under a pinned oracle key',
      'classifier.signature' => 'The classifier verdict verifies under a pinned judge key',
      'offer_set.signature' => 'The offer set is signed by a site key, for this session',
      'labels.signature' => 'The label receipt is signed by a pinned site key, for this session',
      'settlement.signature' => 'The settlement record verifies',
      'revocation.history' => 'The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)',
      'revocation.epoch' => 'A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time',
      'anchor.inclusion' => 'The anchored artifact is included under a guardian-signed head of the intent log'
    }.freeze
    STATUS_TEXT = { 'pass' => 'verified', 'fail' => 'REFUTED', 'unverified' => 'not verified here' }.freeze
    NOT_PROVEN = [
      'That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.',
      "That the site's signed schema describes what its endpoints really do (SCH).",
      "That the site's effect records and any oracle facts are true (EFF, ORC).",
      'Acceptance of this bundle by any card network, court or regulator.'
    ].freeze

    # the wallet-side answer wire (pca-intent-observation v2) is the Wallet module's: the same checks as the reference's verifyIntentAnswer
    W = AtlasPca::Wallet
    INTENT_ANSWER_SIG_DOMAIN = W::INTENT_ANSWER_SIG_DOMAIN
    INTENT_ANSWER_REF_DOMAIN = W::INTENT_ANSWER_REF_DOMAIN
    INTENT_TYPED_DOMAIN = W::INTENT_TYPED_DOMAIN
    INTENT_DEVICE_CHALLENGE_DOMAIN = W::INTENT_DEVICE_CHALLENGE_DOMAIN
    FRICTION_ORDER = W::FRICTION_ORDER
    MIN_HOLD_MS = W::MIN_HOLD_MS

    module_function

    def friction_rank(t) = W.friction_rank(t)
    def friction_tier?(x) = W.friction_tier?(x)
    def b64u32?(v) = W.b64u32?(v)
    def answer_shape_error(a) = W.answer_shape_error(a)
    def verify_intent_answer(a, principals = nil) = W.verify_intent_answer(a, principals)
    def answer_ref(a) = W.answer_ref(a)
    def typed_digest(question_id, normalized_value) = W.typed_digest(question_id, normalized_value)
    def device_challenge(question_id, rendered_digest, y, action_digest = nil) = W.device_challenge(question_id, rendered_digest, y, action_digest)

    # ---- helpers -------------------------------------------------------------------------------------------------------------

    def n(v) = js_str(v)
    def pg(o, k) = own(o, k)
    def sorted16(xs) = xs.each_with_index.sort_by { |x, i| [u16key(x), i] }.map(&:first)

    # `Number(x?.[k]) || 0`
    def num_or0(x, k)
      v = pg(x, k)
      return 0 if v.equal?(UNDEF) || v.nil?
      return (v ? 1 : 0) if v == true || v == false
      return (v.is_a?(Float) && v.nan? ? 0 : v) if num?(v)
      return 0 unless v.is_a?(String)

      r = begin
        v.strip.empty? ? 0.0 : Float(v.strip)
      rescue ArgumentError
        return 0
      end
      r.nan? ? 0 : r
    end

    def sign_of(a) = a.negative? ? -1 : (a.positive? ? 1 : 0)
    def finite_num?(v) = num?(v) && jsnum(v).finite?

    def ts_check_name(name) = TS_CHECK_NAMES.fetch(name, name)

    def ts_reason(reason)
      return reason unless reason.is_a?(String)

      head, sep, rest = reason.partition(': ')
      reason = "#{TS_CHECK_NAMES[head]}#{sep}#{rest}" if !sep.empty? && TS_CHECK_NAMES.key?(head)
      reason += ' / suite' if reason == 'leaf_signature: signature does not verify under the leaf holder key'
      reason
    end

    # ---- findings ------------------------------------------------------------------------------------------------------------

    class Findings
      attr_reader :list

      def initialize = @list = []

      def add(code, status, refs = nil, detail = nil)
        d = AtlasPca::AnalyzerJs.truthy?(detail) ? " (#{detail})" : ''
        @list << { 'code' => code, 'status' => status, 'text' => "#{TEMPLATES.fetch(code)}: #{STATUS_TEXT.fetch(status)}#{d}.", 'refs' => (refs || []).dup }
      end

      def verdict(code, v, refs = nil)
        if AtlasPca::AnalyzerJs.truthy?(v['ok'])
          add(code, 'pass', refs)
        else
          add(code, 'fail', refs, v['reason'])
        end
      end

      # Run `port` if supplied, else the core default; with neither, the artifact stays unverified.
      def check(code, port, core, artifact, bundle, refs, what)
        v = begin
          if port then port.call(artifact, bundle)
          elsif core then core.call
          end
        rescue StandardError => e # a throwing verifier is a refutation
          { 'ok' => false, 'reason' => "verifier threw: #{e.message}" }
        end
        if v.nil?
          add(code, 'unverified', refs, "no verifier for #{what}")
        else
          verdict(code, v, refs)
        end
      end
    end

    def nul(e) = e.nil? ? { 'ok' => true } : { 'ok' => false, 'reason' => e }

    def empty_summary
      { 'admitted_under' => nil, 'principal_keys' => [], 'answers' => { 'total' => 0, 'yes' => 0, 'no' => 0, 'partial' => 0, 'canaries' => 0 }, 'refusals' => [],
        'consent' => nil, 'charged' => nil, 'canary_accuracy' => { 'correct' => 0, 'asked' => 0 }, 'attribution' => { 'pinned' => false, 'keys_to_check' => [] },
        'proven' => [], 'not_proven' => NOT_PROVEN.dup }
    end

    def finish(f, digest, summary)
      findings = f.list.each_with_index.sort_by { |x, i| [u16key(x['code']), u16key(x['refs'].join(',')), u16key(x['status']), u16key(x['text']), i] }.map(&:first)
      consistent = !findings.empty? && findings.none? { |x| x['status'] == 'fail' }
      pinned = findings.select { |x| x['code'] == 'principal.pinned' }
      attributed = pinned.any? { |x| x['status'] == 'pass' } && pinned.none? { |x| x['status'] != 'pass' }
      ok = consistent && attributed
      complete = findings.none? { |x| x['status'] == 'unverified' }
      if consistent && !attributed && !summary['attribution']['keys_to_check'].empty?
        summary['not_proven'].unshift("The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: #{summary['attribution']['keys_to_check'].join(', ')}.")
      end
      unverified = sorted16(findings.select { |x| x['status'] == 'unverified' }.map { |x| x['code'] }.uniq)
      summary['not_proven'] << "Checked only through a supplied verifier, or not at all: #{unverified.join(', ')}." unless unverified.empty?
      body = { 'ok' => ok, 'consistent' => consistent, 'attributed' => attributed, 'complete' => complete, 'digest' => digest, 'findings' => findings, 'summary' => summary }
      body.merge('report_digest' => AtlasPca.hash_canonical({ 'd' => E::EVIDENCE_REPORT_DOMAIN, 'r' => body }))
    end

    # Replay a bundle against the reader's trust inputs (`trust`: siteKeys, principals, sessionRootDigest, minTier, jitTier, typedValues,
    # credentials, canaryLabels, oracleKeys, judges, labelKeys, anchorGuardian, acc, verifiers; all optional). Returns the findings report
    # {ok, consistent, attributed, complete, digest, findings, summary, report_digest}.
    def verify_evidence_bundle(bundle, trust = nil)
      trust = {} if trust.nil?
      raise TypeError, 'trust must be an object' unless trust.is_a?(Hash)

      f = Findings.new
      summary = empty_summary
      te = E.acc_trust_error(trust.fetch('acc', UNDEF))
      if te
        f.add('trust.acc', 'fail', [], te)
        return finish(f, nil, summary)
      end
      pe = E.principals_trust_error(trust.fetch('principals', UNDEF))
      if pe
        f.add('trust.principals', 'fail', [], pe)
        return finish(f, nil, summary)
      end
      bad = E.bundle_shape_error(bundle)
      if bad
        f.add('shape', 'fail', [], bad)
        return finish(f, nil, summary)
      end
      begin
        b = E.normalize_bundle(bundle)
        digest = E.evidence_digest(b)
      rescue StandardError => e
        f.add('shape', 'fail', [], "not canonicalizable: #{e.message}")
        return finish(f, nil, summary)
      end
      f.add('shape', 'pass')
      begin
        replay(b, digest, trust, f, summary)
      rescue StandardError => e # a fault inside the replay refutes the shape (fail closed)
        f.add('shape', 'fail', [], "replay aborted: #{e.message}")
      end
      finish(f, digest, summary)
    end

    # The verifier context (`intentV2.acc`) for a candidate action: pre-states of the site-local accumulators and monitor states.
    def acc_context_for(s_root, history, params, t, schema)
      state = {}
      s_root['accumulators'].each do |a|
        next if a['holder']['kind'] != 'site_local'
        next if !a['key'].nil? && AtlasPca.acc_key_of(a, params).nil? # the verifier fails the claim (missing key)

        state[a['id']] = AtlasPca.acc_pre_state(a, history, { 'params' => params, 't' => t }, schema)
      end
      { 'state' => state, 'monitors' => s_root['monitors'].to_h { |m| [m['id'], AtlasPca.monitor_state(m, history)] } }
    end

    def replay(b, digest, trust, f, summary)
      s_root = b['session_root']
      session = b['subject']['session']
      aud = b['subject']['aud']
      doc = b['schema']['doc']
      # Consistency is checked against the keys the session root names; ATTRIBUTION (below) against the reader's pins.
      principals = sorted16(s_root['principals'].map { |p| p['key'] })
      summary['principal_keys'] = principals
      s_ref = !trust['sessionRootDigest'].nil? ? trust['sessionRootDigest'] : AtlasPca.session_root_digest(s_root)
      ports = !trust['verifiers'].nil? ? trust['verifiers'] : {}
      # The reader's PQ pins (trust.principals[].pq_pk, out of band; NEVER the bundle's own S.principals).
      pq_pins = (trust['principals'] || []).select { |p| p['pq_pk'].is_a?(String) }.to_h { |p| [p['key'], p['pq_pk']] }
      site_keys = trust['siteKeys']

      # -- session root ---------------------------------------------------------------------------------------------------------
      if s_root['session'] != session
        f.add('session_root.signature', 'fail', ['session_root'], 'session root is for another session')
      else
        f.check('session_root.signature', ports['sessionRoot'], -> { AtlasPca.verify_session_root(s_root, pq_pins) }, s_root, b, ['session_root'], 'the session root')
      end

      # -- statement ------------------------------------------------------------------------------------------------------------
      f.add('statement.commit', s_root['intent_ref'] == b['statement']['commit'] ? 'pass' : 'fail', ['statement'])
      opening = b['statement'].fetch('opening', UNDEF)
      if opening.equal?(UNDEF)
        f.add('statement.opening', 'unverified', ['statement'], 'the statement was not opened (it stays a commitment)')
      else
        v = AtlasPca::IntentStatement.verify_intent(opening)
        if !v['ok']
          f.add('statement.opening', 'fail', ['statement'], v['reason'])
        elsif AtlasPca::IntentStatement.intent_ref(opening) != b['statement']['commit']
          f.add('statement.opening', 'fail', ['statement'], 'the opening does not hash to the commitment')
        elsif !principals.include?(opening['principal'])
          f.add('statement.opening', 'fail', ['statement'], 'signed by a key that is not a principal of the session')
        else
          f.add('statement.opening', 'pass', ['statement'])
        end
      end

      # -- schema ---------------------------------------------------------------------------------------------------------------
      f.check('schema.signature', ports['schema'], site_keys.nil? ? nil : -> { AtlasPca.verify_action_schema(doc, site_keys) }, doc, b, ['schema'],
              'the action schema (no site keys supplied)')
      schema_digest = AtlasPca.action_schema_digest(doc)
      f.add('schema.digest', s_root['schema']['digest'] == schema_digest && s_root['schema']['aud'] == aud ? 'pass' : 'fail', ['schema'])

      # -- maps -----------------------------------------------------------------------------------------------------------------
      map_commits = b['maps'].to_h { |m| [m['commit'], true] }
      b['maps'].each do |m|
        ref = ["map:#{n(m['seq'])}"]
        unless truthy?(m.fetch('map', UNDEF))
          f.add('map.replay', 'unverified', ref, 'committed map not revealed')
          next
        end
        r = AtlasPca::IntentMapkit.verify_intent_map(m['map'])
        if !r['ok']
          f.add('map.replay', 'fail', ref, r['problems'][0, 3].join('; '))
        elsif AtlasPca::IntentMapkit.intent_map_digest(m['map']) != m['commit']
          f.add('map.replay', 'fail', ref, 'the revealed map does not hash to its commit')
        else
          f.add('map.replay', 'pass', ref)
        end
      end

      # -- grants: G_0 and the delta chain (core intent_session caveat) ---------------------------------------------------------
      grants = {}
      g0 = b['root_grant']
      cv = AtlasPca.grant_session_caveat(g0)
      why, ok = AtlasPca.verify_chain([g0], g0['issuer'], true, nil, pq_pins)
      if !ok
        f.add('root_grant', 'fail', ['G_0'], why)
      elsif !principals.include?(g0['issuer'])
        f.add('root_grant', 'fail', ['G_0'], 'not signed by a principal of the session')
      elsif cv.nil? || !AtlasPca.intent_session_caveat_error(cv).nil?
        f.add('root_grant', 'fail', ['G_0'], cv.nil? ? 'no intent_session caveat' : (AtlasPca.intent_session_caveat_error(cv) || ''))
      elsif cv['session'] != session || !strict_eq(cv['seq'], 0) || cv['root'] != s_ref
        f.add('root_grant', 'fail', ['G_0'], 'intent_session caveat does not bind seq 0 of this session root')
      else
        f.add('root_grant', 'pass', ['G_0'])
        grants[g0['id']] = { 'cap' => g0, 'seq' => 0 }
      end
      prev_id = g0['id']
      b['deltas'].each_with_index do |d, i|
        want = i + 1
        ref = ["D_#{want}"]
        why, ok = AtlasPca.verify_chain([d], d['issuer'], true, nil, pq_pins)
        if !ok || !principals.include?(d['issuer']) || d.key?('parent')
          f.add('delta.signature', 'fail', ref, !ok ? why : 'not a principal-signed root capability')
          next
        end
        f.add('delta.signature', 'pass', ref)
        cv = AtlasPca.grant_session_caveat(d)
        n_cv = d['caveats'].count { |k| pg(k, 'type') == 'intent_session' }
        why2 = nil
        if cv.nil? || n_cv != 1
          why2 = 'no single intent_session caveat'
        elsif !AtlasPca.intent_session_caveat_error(cv).nil?
          why2 = AtlasPca.intent_session_caveat_error(cv)
        elsif cv['session'] != session
          why2 = 'bound to another session'
        elsif cv['root'] != s_ref
          why2 = 'bound to another session root'
        elsif !strict_eq(cv['seq'], want)
          why2 = "seq #{n(cv['seq'])} where #{want} was expected (gap, duplicate or reorder)"
        elsif cv.fetch('prev', UNDEF) != prev_id
          why2 = 'prev does not name the previous grant'
        end
        if why2
          f.add('delta.chain', 'fail', ref, why2)
        else
          f.add('delta.chain', 'pass', ref)
          grants[d['id']] = { 'cap' => d, 'seq' => want }
        end
        prev_id = d['id']
      end

      # -- answers --------------------------------------------------------------------------------------------------------------
      verified = []
      b['answers'].each do |a|
        qid = pg(a, 'question_id')
        ref = ["answer:#{n(qid)}"]
        v = verify_intent_answer(a, principals)
        unless v['ok']
          f.add('answer.signature', 'fail', ref, v['reason'])
          next
        end
        if a['session'] != session
          f.add('answer.signature', 'fail', ref, 'answer for another session')
          next
        end
        f.add('answer.signature', 'pass', ref)
        verified << a
        f.add('answer.map', map_commits.key?(a['map_digest']) ? 'pass' : 'fail', ref)
        ux = a['ux']
        next if truthy?(ux.fetch('canary', UNDEF)) || !strict_eq(a['y'], 1)

        mn = trust['minTier'].is_a?(Hash) ? trust['minTier'][a['verb']] : nil
        unless mn.nil?
          f.add('answer.tier', friction_rank(ux['tier']) >= friction_rank(mn) ? 'pass' : 'fail', ref, "#{n(ux['tier'])} vs minimum #{n(mn)}")
        end
        if ux['tier'] == 'typed'
          tv = trust['typedValues'].is_a?(Hash) ? trust['typedValues'][qid] : nil
          if tv.nil?
            f.add('answer.typed', 'unverified', ref, 'the typed value is not known to this verifier')
          else
            f.add('answer.typed', typed_digest(qid, tv) == ux.fetch('typed_digest', UNDEF) ? 'pass' : 'fail', ref)
          end
        end
        next unless ux['tier'] == 'device'

        wa = ux['webauthn']
        creds = trust['credentials']
        cred = truthy?(wa) && creds.is_a?(Hash) ? creds[wa['credential_id']] : nil
        if !truthy?(wa) || cred.nil?
          f.add('answer.device', 'unverified', ref, 'unknown authenticator')
        else
          r = AtlasPca::WebAuthn.verify_assertion(
            { 'authenticator_data' => AtlasPca.b64d(wa['authenticator_data']), 'client_data_json' => AtlasPca.b64d(wa['client_data_json']),
              'signature' => AtlasPca.b64d(wa['signature']), 'public_key' => cred['publicKey'] },
            { 'expected_challenge' => device_challenge(qid, ux['rendered_digest'], a['y'], ux.fetch('action_digest', nil)), 'rp_id' => cred['rpId'],
              'origins' => cred['origins'], 'require_uv' => true, 'stored_sign_count' => cred['signCount'].nil? ? 0 : cred['signCount'] }
          )
          f.add('answer.device', r['ok'] ? 'pass' : 'fail', ref, r['ok'] ? nil : r['reason'])
        end
      end
      real = verified.reject { |a| truthy?(a['ux'].fetch('canary', UNDEF)) }
      canaries = verified.select { |a| truthy?(a['ux'].fetch('canary', UNDEF)) }
      summary['answers'] = { 'total' => real.length, 'yes' => real.count { |a| strict_eq(a['y'], 1) && !a.key?('partial') }, 'no' => real.count { |a| strict_eq(a['y'], 0) },
                             'partial' => real.count { |a| a.key?('partial') }, 'canaries' => canaries.length }
      summary['refusals'] = sorted16(real.select { |a| strict_eq(a['y'], 0) }.map { |a| a['question_id'] })
      yes_count = real.count { |a| strict_eq(a['y'], 1) }
      f.add('delta.backed', yes_count >= b['deltas'].length ? 'pass' : 'fail', [], "#{b['deltas'].length} delta(s), #{yes_count} principal yes answer(s)")

      # -- canaries: recomputed, the claimed summary is never trusted --------------------------------------------------------------
      labels = b['canary_labels'].to_h { |c| [c['question_id'], c['label']] }
      false_yes = false_no = missing = 0
      canary_labels = trust['canaryLabels'].is_a?(Hash) ? trust['canaryLabels'] : {}
      canaries.each do |a|
        label = canary_labels[a['question_id']]
        label = labels[a['question_id']] if label.nil?
        if label.nil?
          missing += 1
        elsif strict_eq(label, 0) && strict_eq(a['y'], 1)
          false_yes += 1
        elsif strict_eq(label, 1) && strict_eq(a['y'], 0)
          false_no += 1
        end
      end
      summary['canary_accuracy'] = { 'correct' => canaries.length - missing - false_yes - false_no, 'asked' => canaries.length }
      c = b['canaries']
      if missing.positive?
        f.add('canaries.summary', 'fail', [], "#{missing} canary answer(s) without a known label")
      elsif !strict_eq(c['asked'], canaries.length) || !strict_eq(c['false_yes'], false_yes) || !strict_eq(c['false_no'], false_no)
        f.add('canaries.summary', 'fail', [], "claimed #{n(c['asked'])}/#{n(c['false_yes'])}/#{n(c['false_no'])}, recomputed #{canaries.length}/#{false_yes}/#{false_no}")
      else
        f.add('canaries.summary', 'pass', [], "#{canaries.length} asked, #{false_yes} false yes, #{false_no} false no")
      end

      # -- sequencer key sets (rule 15): replayed per root in issue order, versions monotone like core keyset_versions ------------
      acc_trust = trust['acc']
      freshness = lambda do |ks|
        out = {}
        out['max_receipt_age_ms'] = acc_trust['max_receipt_age_s'] * 1000 if !acc_trust.nil? && !acc_trust['max_receipt_age_s'].nil?
        out['max_keyset_age_ms'] = acc_trust['max_keyset_age_s'] * 1000 if !acc_trust.nil? && !acc_trust['max_keyset_age_s'].nil?
        if !ks['tracked'].nil?
          out['tracked'] = ks['tracked']
        elsif !ks['minV'].nil?
          out['min_keyset_version'] = ks['minV']
        end
        out
      end

      root_holders = {}
      s_root['accumulators'].each { |a| root_holders[a['holder']['root']] = a['holder'] if a['holder']['kind'] == 'sequenced' }
      accepted = []
      verified_sets = [] # signed under a pinned root and not a rollback (equivocating sets included): the tracked-version history
      equivocated = {}
      seqkeys = b['accumulator']['sequencer_keys']
      raw = seqkeys.nil? ? [] : seqkeys.dup
      cmp_sets = lambda do |x, y|
        %w[issued_at version].each do |k|
          d = sign_of(num_or0(x, k) - num_or0(y, k))
          return d unless d.zero?
        end
        hx = AtlasPca.hash_canonical(x)
        hy = AtlasPca.hash_canonical(y)
        u16key(hx) <=> u16key(hy)
      end
      sets = raw.each_with_index.sort { |(x, i), (y, j)| (r = cmp_sets.call(x, y)).zero? ? i <=> j : r }.map(&:first)
      tracked = {}
      by_version = {}
      sets.each_with_index do |k, i|
        ref = "keyset##{i}:#{k.is_a?(Hash) ? n(k.fetch('version', UNDEF)) : '?'}"
        holder = k.is_a?(Hash) && k['sequencer'].is_a?(String) ? root_holders[k['sequencer']] : nil
        if holder.nil?
          f.add('acc.keysets', 'fail', [ref], 'not signed by a sequencer root the session root pins')
          next
        end
        unless AtlasPca.verify_sequencer_key_set(k, holder['root'], holder.fetch('root_pq_pk', UNDEF))
          f.add('acc.keysets', 'fail', [ref], 'the key set does not verify under its pinned root')
          next
        end
        prev = tracked[holder['root']]
        if !prev.nil? && k['version'] < prev
          f.add('acc.keysets', 'fail', [ref], "version #{n(k['version'])} rolls back the tracked version #{n(prev)}")
          next
        end
        # Equivocation (core rule 15): two DIFFERENT sets under one root and version are both refused; an identical duplicate is not.
        slot = "#{holder['root']}##{n(k['version'])}"
        kd = AtlasPca.sequencer_key_set_digest(k)
        seen = by_version[slot]
        if !seen.nil? && seen['digest'] != kd
          equivocated[slot] = true
          verified_sets << k
          f.add('acc.keysets.equivocation', 'fail', [seen['ref'], ref], "two different key sets under version #{n(k['version'])} of one sequencer root")
          next
        end
        by_version[slot] = { 'digest' => kd, 'ref' => ref } if seen.nil?
        verified_sets << k
        tracked[holder['root']] = [prev.nil? ? 0 : prev, k['version']].max
        accepted << k
        f.add('acc.keysets', 'pass', [ref])
      end
      accepted = accepted.reject { |k| equivocated.key?("#{k['sequencer']}##{n(k['version'])}") }

      # In force = accepted sets of the root issued by admission (+ the core skew); the tracked state is the newest VERIFIED set issued by then.
      key_sets_at = lambda do |root, t|
        own_sets = accepted.select { |k| k['sequencer'] == root }
        newest = nil
        verified_sets.each do |k|
          newest = k if k['sequencer'] == root && k['issued_at'] <= t && (newest.nil? || k['version'] > newest['version'])
        end
        poisoned = !newest.nil? && equivocated.key?("#{root}##{n(newest['version'])}")
        floor = newest.nil? ? 0 : newest['version']
        { 'sets' => own_sets.select { |k| k['issued_at'] <= t + AtlasPca::IntentV2::RECEIPT_SKEW_MS && k['version'] >= floor },
          'minV' => newest.nil? ? nil : newest['version'],
          'tracked' => !newest.nil? && !poisoned ? { 'version' => newest['version'], 'digest' => AtlasPca.sequencer_key_set_digest(newest) } : nil }
      end

      # -- PCActns --------------------------------------------------------------------------------------------------------------
      by_digest = {}
      root_seq = {}
      effect_of = ->(d) { b['effects'].find { |e| e['pcactn_digest'] == d } }
      digest_of = lambda do |p|
        AtlasPca.hash_canonical(p)
      rescue StandardError
        nil
      end
      grants_by_seq = grants.values.sort_by { |g| g['seq'] }.map { |g| g['cap'] }

      # Index of the epoch in force at t (the last one issued at or before t, in issue order), or -1.
      epoch_idx_at = lambda do |t|
        idx = -1
        b['revocation_epochs'].each_with_index { |r, i| idx = i if r['epoch']['issued_at'] <= t }
        idx
      end

      # The admitted history, as the site's store held it: one event per accumulator-bearing PCActn, in event order.
      history = []
      b['accumulator']['events'].each do |ev|
        next if history.any? { |h| h['id'] == ev['pcactn_digest'] }

        p = b['pcactns'].find { |x| digest_of.call(x) == ev['pcactn_digest'] }
        eff = effect_of.call(ev['pcactn_digest'])
        params = eff.is_a?(Hash) ? eff['params'] : nil
        next unless !p.nil? && truthy?(params.nil? ? UNDEF : params)

        status = ev['status']
        history << { 'id' => ev['pcactn_digest'], 'verb' => p['action']['verb'], 'resource' => p['action']['resource'], 'params' => params, 't' => p['iat'],
                     'status' => status.nil? ? 'committed' : status }
      end

      # The verifier state `decide_intent_v2` reads, rebuilt from the bundle (nil when the bundle lacks the plaintext params).
      v2_context = lambda do |p, d, seq|
        eff = effect_of.call(d)
        params = eff.is_a?(Hash) ? eff['params'] : nil
        next nil if !truthy?(params.nil? ? UNDEF : params) || seq.nil?

        idx = history.index { |h| h['id'] == d } || -1
        before = idx >= 0 ? history[0, idx] : history.select { |h| h['t'] <= p['iat'] }
        acc = acc_context_for(s_root, before, params, p['iat'], { 'verbs' => doc['verbs'] })
        ri = epoch_idx_at.call(p['iat'])
        rev = ri >= 0 ? b['revocation_epochs'][ri] : nil
        rev_last = ri.positive? ? b['revocation_epochs'][ri - 1] : nil
        kv = root_holders.keys.to_h { |root| [root, key_sets_at.call(root, p['iat'])['tracked']] }
        session_ctx = { 'root' => s_root, 'grants' => grants_by_seq[0, seq], 'pq_pins' => pq_pins }
        session_ctx['revocation'] = rev unless rev.nil?
        session_ctx['revocation_last'] = rev_last unless rev_last.nil?
        ctx = {
          'params' => params, 'schema' => { 'docs' => [doc], 'keys' => site_keys.nil? ? [] : site_keys }, 'session' => session_ctx,
          'acc' => acc.merge('receipts' => b['accumulator']['receipts'].nil? ? [] : b['accumulator']['receipts'],
                             'sequencer_keys' => root_holders.keys.flat_map { |root| key_sets_at.call(root, p['iat'])['sets'] },
                             'keyset_versions' => kv.reject { |_, t| t.nil? })
        }
        ctx['policy'] = { 'acc' => acc_trust } unless acc_trust.nil?
        ctx
      end

      b['pcactns'].each do |p|
        d = digest_of.call(p)
        if d.nil?
          f.add('pcactn.verify', 'fail', ['pcactn:?'], 'not canonicalizable')
          next
        end
        by_digest[d] = p
        ref = ["pcactn:#{d}"]
        chain = p.is_a?(Hash) ? p['cap_chain'] : nil
        root = chain.is_a?(Array) && !chain.empty? ? chain[0] : nil
        unless truthy?(root.nil? ? UNDEF : root)
          f.add('pcactn.verify', 'fail', ref, 'empty capability chain')
          next
        end
        rid = root.is_a?(Hash) ? root['id'] : nil
        g = rid.is_a?(String) ? grants[rid] : nil
        same_root = !g.nil? && AtlasPca.hash_canonical(g['cap']) == AtlasPca.hash_canonical(root)
        is_ = p.fetch('intent_session', UNDEF)
        ctx = !is_.equal?(UNDEF) && same_root ? v2_context.call(p, d, g['seq']) : nil
        # The root's authority is pcactn.root (byte-equal to G_0 / a verified delta) plus principal.pinned (trust.principals): a non-Ed25519
        # root verifies only under the reader's pins, else it is refused.
        r = AtlasPca.verify_pcactn(p, root, now: p['iat'], audience: aud, insecure_skip_plan_root_check: true, pq_pins: pq_pins, intent_v2: ctx)
        checks = r.checks.dup
        reason = r.reason
        # the replayed grant comes from the bundle (not the verifier's own store): its post-quantum root needs the reader's pin
        if root.is_a?(Hash) && root['alg'].is_a?(String) && root['alg'] != 'ed25519' && checks.key?('chain') && checks['chain'] != false &&
           !AtlasPca.verify_chain([root], root['issuer'], true, nil, pq_pins).last
          first_failed = checks.keys.index { |k| checks[k] == false }
          reason = 'chain: capability chain invalid' if first_failed.nil? || first_failed > checks.keys.index('chain')
          checks['chain'] = false
        end
        failed = sorted16(checks.select { |_, st| st == false }.keys.map { |k| ts_check_name(k) })
        v1f = failed.reject { |k| V2_CHECKS.include?(k) }
        v2f = failed.select { |k| V2_CHECKS.include?(k) }
        f.add('pcactn.verify', v1f.empty? ? 'pass' : 'fail', ref, v1f.empty? ? nil : "#{v1f.join(', ')}: #{ts_reason(reason) || ''}")
        if same_root
          f.add('pcactn.root', 'pass', ref, g['seq'].zero? ? 'G_0' : "D_#{g['seq']}")
          root_seq[d] = g['seq']
        else
          f.add('pcactn.root', 'fail', ref, 'rooted at a grant that is not G_0 or a verified delta of this session')
        end
        next if is_.equal?(UNDEF)

        why = nil
        if pg(is_, 'session') != session
          why = 'another session'
        elsif pg(is_, 'root') != s_ref
          why = 'another session root'
        elsif pg(is_, 'schema') != schema_digest
          why = 'another schema'
        elsif !g.nil? && !strict_eq(pg(is_, 'seq'), g['seq'])
          why = "seq #{n(pg(is_, 'seq'))} but rooted at seq #{g['seq']}"
        else
          claims = pg(is_, 'acc')
          claims = [] if claims.equal?(UNDEF) || claims.nil?
          raise TypeError, 'is_.acc is not iterable' unless claims.is_a?(Array)

          claims.each do |cl|
            ev = b['accumulator']['events'].find { |e| e['pcactn_digest'] == d && e['acc'] == pg(cl, 'id') }
            if ev.nil? || !strict_eq(ev['post'], pg(cl, 'post'))
              why = "the signed claim #{n(pg(cl, 'id'))}.post = #{n(pg(cl, 'post'))} has no matching accumulator event"
            end
          end
        end
        why = "core v2 checks failed: #{v2f.join(', ')}" if why.nil? && !v2f.empty?
        if !why.nil?
          f.add('pcactn.session', 'fail', ref, why)
        elsif ctx.nil?
          f.add('pcactn.session', 'unverified', ref, 'the core v2 checks need the plaintext params of the effect record')
        else
          f.add('pcactn.session', 'pass', ref)
        end
      end
      subject = by_digest[b['subject']['pcactn_digest']]
      f.add('subject.present', subject.nil? ? 'fail' : 'pass', ["pcactn:#{b['subject']['pcactn_digest']}"])
      s_seq = root_seq[b['subject']['pcactn_digest']]
      summary['admitted_under'] = s_seq.nil? ? nil : (s_seq.zero? ? 'G_0' : "D_#{s_seq}")

      # -- effects (no core format yet: signature through the port) ---------------------------------------------------------------
      b['effects'].each do |e|
        ref = ["effect:#{n(e['pcactn_digest'])}"]
        p = by_digest[e['pcactn_digest']]
        if p.nil?
          f.add('effect.binding', 'fail', ref, 'no such PCActn in the bundle')
          next
        end
        if !e.key?('params')
          f.add('effect.binding', 'unverified', ref, 'no raw params to bind')
        else
          f.add('effect.binding', AtlasPca.params_digest(e['params']) == p['action']['params_digest'] ? 'pass' : 'fail', ref)
        end
        charged = e.fetch('charged', UNDEF)
        if truthy?(charged)
          cref = pg(charged, 'ref')
          name = cref.is_a?(String) && cref.start_with?('action.params.') ? cref['action.params.'.length..] : nil
          params = e.fetch('params', UNDEF)
          bound = !name.nil? && truthy?(params) && params.is_a?(Hash) ? params.fetch(name, UNDEF) : UNDEF
          amount = pg(charged, 'amount')
          if !finite_num?(bound) || !finite_num?(amount)
            f.add('effect.charged', 'unverified', ref, "no numeric #{n(cref)} to compare")
          else
            f.add('effect.charged', amount <= bound ? 'pass' : 'fail', ref, "#{n(amount)} vs #{n(bound)}")
            summary['charged'] = { 'amount' => amount, 'bound' => bound } if e['pcactn_digest'] == b['subject']['pcactn_digest']
          end
        end
        if e.key?('frame_violations')
          fv = e['frame_violations']
          f.add('effect.frame', fv.empty? ? 'pass' : 'fail', ref, fv.empty? ? nil : sorted16(fv.map { |x| n(x) }).join(', '))
        end
        f.check('effect.signature', ports['effect'], nil, e, b, ref, 'effect records (no core format yet)')
      end

      # -- JIT consent for an irreversible subject action (core action digest) -----------------------------------------------------
      if !subject.nil? && subject['action']['reversibility_class'] == 'irreversible'
        ref = ["pcactn:#{b['subject']['pcactn_digest']}"]
        ad = AtlasPca::IntentJit.intent_action_digest(subject['action'])
        need = !trust['jitTier'].nil? ? trust['jitTier'] : 'typed'
        cons = real.find do |a|
          strict_eq(a['y'], 1) && a['ux']['consent_for_action'] == true && a['ux'].fetch('action_digest', UNDEF) == ad &&
            friction_rank(a['ux']['tier']) >= friction_rank(need)
        end
        if cons
          f.add('jit.consent', 'pass', ref, "question #{n(cons['question_id'])}, #{n(cons['ux']['tier'])} tier")
          summary['consent'] = { 'question_id' => cons['question_id'], 'tier' => cons['ux']['tier'], 'signer' => cons['signer'] }
        else
          f.add('jit.consent', 'fail', ref, "no principal yes at #{n(need)} tier or above bound to this action digest")
        end
      end

      # -- accumulators (core declarations and value rule) -------------------------------------------------------------------------
      decls = s_root['accumulators'].to_h { |a| [a['id'], a] }
      schema_verbs = { 'verbs' => doc['verbs'] }
      value_of = lambda do |decl, d|
        p = by_digest[d]
        eff = effect_of.call(d)
        params = eff.is_a?(Hash) ? eff['params'] : nil
        next nil if p.nil? || !truthy?(params.nil? ? UNDEF : params)

        v = AtlasPca.acc_value_of(decl, p['action']['verb'], params, schema_verbs)
        v['ok'] ? v['val'] : nil
      end

      running = {}
      b['accumulator']['events'].each_with_index do |ev, i|
        ref = ["acc:#{ev['acc']}##{i}"]
        decl = decls[ev['acc']]
        if decl.nil?
          f.add('accumulator.declared', 'fail', ref)
          next
        end
        p = by_digest[ev['pcactn_digest']]
        counted = ev['status'] != 'released' && ev['status'] != 'reverted'
        prev = running.fetch(ev['acc'], 0)
        expected = nil
        if !counted
          expected = prev
        elsif decl['agg'] == 'count'
          expected = prev + 1
        elsif %w[sum max].include?(decl['agg'])
          val = value_of.call(decl, ev['pcactn_digest'])
          expected = decl['agg'] == 'sum' ? prev + val : [prev, val].max unless val.nil?
        end
        if p.nil?
          f.add('accumulator.arithmetic', 'fail', ref, 'event names a PCActn that is not in the bundle')
        elsif expected.nil?
          f.add('accumulator.arithmetic', ev['post'] >= prev ? 'unverified' : 'fail', ref, ev['post'] >= prev ? 'contribution not recomputable' : 'post decreased')
        else
          f.add('accumulator.arithmetic', ev['post'] == expected ? 'pass' : 'fail', ref, ev['post'] == expected ? nil : "post #{n(ev['post'])}, recomputed #{n(expected)}")
        end
        running[ev['acc']] = counted ? ev['post'] : prev
        next unless counted

        seq = p.nil? ? nil : root_seq[ev['pcactn_digest']]
        delta = ev.fetch('delta', UNDEF)
        if !delta.equal?(UNDEF) && !seq.nil? && delta != seq
          f.add('accumulator.cap', 'fail', ref, 'the event names a different admitting grant from the PCActn root')
          next
        end
        want_seq = seq.nil? ? delta : seq
        grant = grants.values.find { |g| strict_eq(g['seq'], want_seq) }
        caps = [!grant.nil? && !p.nil? ? E.cap_of(grant['cap'], ev['acc'], p['action']['verb']) : nil,
                finite_num?(decl['domain_max']) ? decl['domain_max'] : nil, finite_num?(decl['cap']) ? decl['cap'] : nil].compact
        if caps.empty?
          f.add('accumulator.cap', 'unverified', ref, 'no cap stated for this accumulator')
        else
          cap = caps.min
          f.add('accumulator.cap', finite_num?(ev['post']) && ev['post'] <= cap ? 'pass' : 'fail', ref, "post #{n(ev['post'])}, cap #{n(cap)}")
        end
      end
      receipts = b['accumulator']['receipts'].nil? ? [] : b['accumulator']['receipts']
      f.add('accumulator.receipts', 'fail', ['accumulator'], 'a sequenced accumulator without receipts') if b['accumulator']['holder'] == 'sequenced' && receipts.empty?
      receipts.each_with_index do |r, i|
        core = lambda do
          # nil = the signature and freshness held but the contribution cannot be recomputed (params withheld): unverified.
          decl = decls[r['acc']]
          next { 'ok' => false, 'reason' => 'the receipt names an accumulator that is not sequenced in the session root' } if decl.nil? || decl['holder']['kind'] != 'sequenced'

          holder = decl['holder']
          next { 'ok' => false, 'reason' => 'receipt for another session or audience' } if r['session'] != session || r['aud'] != aud

          d = by_digest.find { |_, pp| AtlasPca.pcactn_reservation_digest(pp) == r['pcactn_digest'] }&.first
          next { 'ok' => false, 'reason' => 'the receipt reserves for a PCActn that is not in the bundle' } if d.nil?

          # Rule 15 freshness is judged at ADMISSION time (the reserved PCActn's iat), never at bundle-verification time.
          admitted_at = by_digest[d]['iat']
          ks = key_sets_at.call(holder['root'], admitted_at)
          unless AtlasPca.verify_receipt_against_holder(r, holder, ks['sets'], admitted_at, freshness.call(ks))
            next { 'ok' => false, 'reason' => 'not signed by a key the pinned sequencer root listed, or not fresh, at admission time' }
          end
          next { 'ok' => false, 'reason' => 'the receipt had expired when the action was admitted' } unless finite_num?(admitted_at) && finite_num?(r['expires_at']) && admitted_at <= r['expires_at']

          val = value_of.call(decl, d)
          next nil if val.nil?
          next { 'ok' => false, 'reason' => 'pre + delta does not give post for the reserved value' } unless AtlasPca.receipt_arithmetic_ok(decl, r, val)

          { 'ok' => true }
        end
        rs = pg(r, 'seq')
        f.check('accumulator.receipts', ports['receipt'], core, r, b, ["receipt:#{n(pg(r, 'acc'))}##{n(rs.equal?(UNDEF) || rs.nil? ? i : rs)}"],
                'the reserved contribution (the effect params were withheld)')
      end

      # -- W-B artifacts: facts, classifier verdicts, offer sets, label receipts ------------------------------------------------------
      oracle_keys = trust['oracleKeys']
      (b['facts'] || []).each_with_index do |x, i|
        pk = x.is_a?(Hash) && x['oracle'].is_a?(String) && oracle_keys.is_a?(Hash) ? oracle_keys[x['oracle']] : nil
        fact_core = lambda do
          w = AtlasPca.validate_fact_wire(x)
          next { 'ok' => false, 'reason' => w } if w

          AtlasPca.wb_verify_artifact_sig(AtlasPca::FACT_DOMAIN, x, pk) ? { 'ok' => true } : { 'ok' => false, 'reason' => 'bad oracle signature' }
        end
        f.check('fact.signature', ports['fact'], pk.nil? ? nil : fact_core, x, b, ["fact:#{i}"], 'this fact (oracle key not pinned)')
      end
      judges = !trust['judges'].nil? ? trust['judges'] : []
      (b['classifier'] || []).each_with_index do |x, i|
        judge = x.is_a?(Hash) && x['judge'].is_a?(String) ? x['judge'] : nil
        cls_core = lambda do
          w = AtlasPca.validate_classifier_verdict_wire(x)
          next { 'ok' => false, 'reason' => w } if w
          next { 'ok' => false, 'reason' => 'verdict for another session' } if x['session'] != session

          AtlasPca.wb_verify_artifact_sig(AtlasPca::INTENT_CLASSIFIER_DOMAIN, x, judge) ? { 'ok' => true } : { 'ok' => false, 'reason' => 'bad judge signature' }
        end
        f.check('classifier.signature', ports['classifier'], judge.nil? || !judges.include?(judge) ? nil : cls_core, x, b, ["classifier:#{i}"],
                'this classifier verdict (judge not pinned)')
      end
      (b['offer_sets'] || []).each_with_index do |x, i|
        key = (site_keys || []).find { |k| x.is_a?(Hash) && pg(k, 'kid') == x.fetch('kid', UNDEF) && pg(k, 'alg') == 'ed25519' }
        offer_core = lambda do
          w = AtlasPca.validate_offer_set_wire(x)
          next { 'ok' => false, 'reason' => w } if w
          next { 'ok' => false, 'reason' => 'offer set for another session' } if x['session'] != session

          AtlasPca.wb_verify_artifact_sig(AtlasPca::OFFER_SET_DOMAIN, x, key['pk']) ? { 'ok' => true } : { 'ok' => false, 'reason' => 'bad site signature' }
        end
        f.check('offer_set.signature', ports['offerSet'], key.nil? ? nil : offer_core, x, b, ["offer_set:#{i}"], 'this offer set (site key not pinned)')
      end
      label_keys = if !trust['labelKeys'].nil?
                     trust['labelKeys']
                   else
                     (site_keys || []).select { |k| k['alg'] == 'ed25519' }.map { |k| { 'site' => doc['site'], 'kid' => k['kid'], 'pk' => k['pk'] } }
                   end
      (b['labels'] || []).each_with_index do |x, i|
        labels_core = lambda do
          e = AtlasPca.verify_labels(x, label_keys)
          next({ 'ok' => false, 'reason' => 'label receipt for another session' }) if e.nil? && pg(x, 'session') != session

          nul(e)
        end
        f.check('labels.signature', ports['labels'], label_keys.empty? ? nil : labels_core, x, b, ["labels:#{i}"], 'this label receipt (no site keys)')
      end

      # -- ported artifacts with no core format --------------------------------------------------------------------------------------
      b['verdicts'].each { |v| f.check('verdict.signature', ports['verdict'], nil, v, b, ["verdict:#{n(pg(v, 'pcactn_digest'))}"], 'site verdicts (no core format yet)') }
      (b['settlements'] || []).each_with_index { |x, i| f.check('settlement.signature', ports['settlement'], nil, x, b, ["settlement:#{i}"], 'settlement records (no core format yet)') }

      # -- revocation (core check_session_revocation, rule 13 step 7) ------------------------------------------------------------------
      # The bundle's epochs, in issue order, must form ONE append-only chain signed by the session's dedicated revocation authority: every
      # epoch is checked as of its own issue time with its predecessor as the tracked `last`; the epoch in force at the action time decides.
      epochs = b['revocation_epochs']
      rev = s_root.fetch('revocation', UNDEF)
      if epochs.empty?
        f.add('revocation.epoch', 'unverified', [], 'no revocation epoch in the bundle')
      elsif !truthy?(rev)
        f.add('revocation.epoch', 'fail', [], 'the session root names no revocation authority')
      else
        authority = rev['key']
        max_age = rev['max_age_s']
        max_age_ms = (max_age.nil? ? DEFAULT_REVOCATION_MAX_AGE_S['default'] : max_age) * 1000
        pin = rev.fetch('pq_pk', UNDEF).equal?(UNDEF) ? nil : { authority => rev['pq_pk'] }
        rcheck = lambda do |ev, ids, now, last|
          AtlasPca.check_session_revocation(ev, session: session, authority: authority, ids: ids, now: now, max_age_ms: max_age_ms, pins: pin,
                                                last: last.nil? ? V2JS::UNDEF : last)
        end
        history_ok = true
        epochs.each_with_index do |ev, i|
          v = rcheck.call(ev, [], ev['epoch']['issued_at'], i.positive? ? epochs[i - 1] : nil)
          history_ok = false unless v['ok']
          f.verdict('revocation.history', v, ["epoch##{i}:#{n(ev['epoch']['epoch'])}"])
        end
        if subject.nil?
          f.add('revocation.epoch', 'unverified', [], 'no subject action time')
        else
          ids = [AtlasPca.session_revocation_id(session)] + b['maps'].map { |m| AtlasPca.map_revocation_id(m['commit']) } +
                b['deltas'].map { |d| AtlasPca.delta_revocation_id(d['id']) }
          idx = epoch_idx_at.call(subject['iat'])
          ev = idx >= 0 ? epochs[idx] : nil
          if ev.nil?
            f.add('revocation.epoch', 'fail', [], 'every epoch was issued after the action')
          elsif !history_ok
            f.add('revocation.epoch', 'fail', ["epoch:#{n(ev['epoch']['epoch'])}"], 'the bundled epochs are not one append-only chain')
          else
            f.verdict('revocation.epoch', rcheck.call(ev, ids, subject['iat'], idx.positive? ? epochs[idx - 1] : nil), ["epoch:#{n(ev['epoch']['epoch'])}"])
          end
        end
      end

      # -- anchors --------------------------------------------------------------------------------------------------------------
      f.add('schema.anchor', 'unverified', ['schema'], 'the anchor names a log position without an inclusion proof') if truthy?(b['schema'].fetch('anchor', UNDEF))
      anchorable = lambda do |kind, d|
        case kind
        when 'evidence' then d == digest
        when 'statement' then d == b['statement']['commit']
        when 'map' then d.is_a?(String) && map_commits.key?(d)
        when 'schema' then d == schema_digest
        when 'observation' then verified.any? { |a| answer_ref(a) == d }
        else false
        end
      end
      f.add('anchor.inclusion', 'unverified', ['anchor:evidence'], 'the bundle is not anchored') unless b['anchors'].any? { |a| a['kind'] == 'evidence' }
      b['anchors'].each do |a|
        ref = ["anchor:#{n(a['kind'])}:#{n(a['index'])}"]
        unless anchorable.call(a['kind'], a['digest'])
          f.add('anchor.inclusion', 'fail', ref, 'the anchor names an artifact that is not this one')
          next
        end
        g = trust['anchorGuardian']
        unless truthy?(g.nil? ? UNDEF : g)
          f.add('anchor.inclusion', 'unverified', ref, 'no anchor-log guardian key supplied')
          next
        end
        h = a['signed_tree_head']
        okk = h['principal'] == INTENT_ANCHOR_LOG && h['instance_id'] == g['instance'] && AtlasPca.verify_tree_head(h, g['public']) &&
              strict_eq(a['proof']['index'], a['index']) && strict_eq(a['proof']['size'], h['size']) &&
              AtlasPca.verify_ledger_inclusion(h['root'], a['proof'], E.anchor_commit(a['kind'], a['digest']))
        f.add('anchor.inclusion', okk ? 'pass' : 'fail', ref)
      end

      # -- attribution: the session-root keys that sign in this bundle must be pinned by the reader --------------------------------------
      # Everything above verifies against keys the bundle's own self-signed session root names, so it proves internal consistency only.
      # The revocation authority and the sequencer roots are named inside S, so they are attributed transitively once S's signer is pinned.
      signing = [s_root.fetch('signer', UNDEF), g0['issuer']] + b['deltas'].map { |d| d['issuer'] } + b['answers'].map { |a| a['signer'] }
      signing << opening['principal'] if truthy?(opening)
      keys = sorted16(signing.select { |k| k.is_a?(String) }.uniq)
      summary['attribution']['keys_to_check'] = keys
      pins_in = trust['principals']
      if pins_in.nil?
        f.add('principal.pinned', 'unverified', keys, 'no pinned principal keys: the bundle names its own principals; verify these keys out of band')
      else
        pins = pins_in.to_h { |p| [p['key'], p] }
        unpinned = keys.reject { |k| pins.key?(k) }
        pq_mismatch = lambda do |k|
          pin = pins[k]
          sp = s_root['principals'].find { |x| x['key'] == k }
          !pin.nil? && pin['pq_pk'] != (sp.nil? ? nil : sp['pq_pk'])
        end
        mism = keys.select { |k| pq_mismatch.call(k) }
        if !unpinned.empty?
          f.add('principal.pinned', 'fail', unpinned, 'signing keys that are not pinned principals')
        elsif !mism.empty?
          f.add('principal.pinned', 'fail', mism, 'the session root binds a different PQ key than the pin')
        else
          f.add('principal.pinned', 'pass', keys)
          summary['attribution']['pinned'] = true
        end
      end

      # -- plain-language facts (only what passed) ---------------------------------------------------------------------------------------
      proven = []
      passed = ->(code) { f.list.any? { |x| x['code'] == code && x['status'] == 'pass' } && f.list.none? { |x| x['code'] == code && x['status'] == 'fail' } }
      if truthy?(summary['admitted_under']) && passed.call('pcactn.verify')
        proven << "The subject action was signed by the agent under #{summary['admitted_under']}, a grant signed by the session principal#{summary['attribution']['pinned'] ? ' (pinned)' : ' (NOT pinned)'}."
      end
      who = lambda do |k|
        summary['attribution']['pinned'] ? "Pinned principal key #{k}" : "Session-root key #{k} (NOT pinned: not attributed to a known principal)"
      end
      if summary['consent']
        proven << "#{who.call(summary['consent']['signer'])} signed a #{summary['consent']['tier']}-tier \"yes\" bound to this exact action (question #{summary['consent']['question_id']})."
      end
      ch = summary['charged']
      proven << "The charged amount #{n(ch['amount'])} is within the confirmed value #{n(ch['bound'])}." if ch && ch['amount'] <= ch['bound']
      proven << "The principal refused #{summary['refusals'].length} question(s): #{summary['refusals'].join(', ')}." unless summary['refusals'].empty?
      proven << "Canary accuracy #{summary['canary_accuracy']['correct']}/#{summary['canary_accuracy']['asked']}." if summary['canary_accuracy']['asked'].positive?
      proven << 'Every accumulator post is within the cap of the grant that admitted it.' if passed.call('accumulator.cap')
      proven << 'The site reports no change to monitored state outside the write set.' if passed.call('effect.frame')
      summary['proven'] = proven
    end
  end
end
