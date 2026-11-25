# frozen_string_literal: true

require 'set'
require_relative 'wallet'
require_relative 'wallet_card'
require_relative 'intent_required'
require_relative 'webauthn'

# The trusted question channel of the wallet (PCA Intent Layer v2, 3.4 and 3.14): one instance per session. SELECTION belongs to the
# verifier (questions enter only as a site-signed intent_required, re-derived by the wallet, or as a structured agent clarification
# whose cell the wallet picks itself); RENDERING and ORDERING belong to the wallet; friction scales with harm; canaries are inserted
# with probability rho and update only the noise counts; caps and a freeze on the estimated false-yes rate bound the questions; a
# cell is asked at most once per session; under estimated noise an irreversible cell needs two confirmations. Native port of the
# TypeScript reference (@atlasauth/pca-wallet, channel). Options, items and results are String-keyed Hashes with the reference's
# member names; the view is a Hash of callables {'p', 'vetoed', 'outsideCeiling', 'confirmed'}.
module AtlasPca
  module WalletChannel
    W = Wallet
    O = IntentOmega
    B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    SPLIT = /[|,]/

    module_function

    # A grant view over an intent learner, with an optional ceiling predicate insideCeiling.call(verb, idx) (true = inside every ceiling).
    def learner_view(l, opts = nil)
      opts ||= {}
      vs_of = lambda do |verb|
        vs = l.omega['verbs'].find { |v| v['verb'] == verb }
        raise ArgumentError, "learnerView: unknown verb #{verb}" if vs.nil?

        vs
      end
      inside = opts['insideCeiling']
      {
        'p' => ->(verb, idx) { l.acceptance(O.cell_rep(vs_of.call(verb), idx)) },
        'vetoed' => ->(verb, idx) { l.is_vetoed(O.cell_rep(vs_of.call(verb), idx)) },
        'outsideCeiling' => ->(verb, idx) { inside ? !inside.call(verb, idx) : false },
        'confirmed' => -> { l.cells.select { |c| c['inGrant'] }.map { |c| { 'verb' => c['verb'], 'idx' => c['cell'] } } }
      }
    end

    class TrustedChannel
      def initialize(opts)
        @o = opts
        @pending = {}
        @asked = Set.new
        @canary_used = Set.new
        @known_yes = []
        @confirmations = {}
        @refused_while_frozen = []
        @session_questions = 0
        @canaries = 0
        @screen_no = 0
      end

      def per_session = (v = (@o['caps'] || {})['perSession']).nil? ? 6 : v
      def per_hour = (v = (@o['caps'] || {})['perHour']).nil? ? 12 : v
      def fatigue = W.truthy?(@o['fatigue']) ? @o['fatigue'] : W::DEFAULT_FATIGUE
      private :per_session, :per_hour, :fatigue

      # The current noise state (eta+ under load, frozen?).
      def noise = W.noise_state(@o['noise'].call, @o['hourly'].count(@o['now'].call), fatigue)

      # The admission policy the learner should use now (tau, eta+, eta-; double confirmation).
      def admission = W.admission_policy(noise, fatigue)

      def questions_asked = @session_questions

      def new_id
        s = +'q_'
        10.times { s << B64U[((@o['rand'].call * 64).floor % 64)] }
        @pending.key?(s) ? new_id : s
      end
      private :new_id

      def box_stats(vs, box)
        cells = W.box_cells(box)
        mx = @o['maxBoxCells']
        return nil if cells.length > (mx.nil? ? 4096 : mx)

        m = 0.0
        mh = 0.0
        harm = @o['harm'] || O::DEFAULT_HARM
        cells.each do |idx|
          s = O.cell_stats(vs, idx, harm)
          m += s['mass']
          mh += s['mass'] * s['harm']
        end
        { 'weight' => mh, 'meanHarm' => m > 0 ? mh / m : 0 }
      end
      private :box_stats

      def reversibility_of(vs, box)
        rev_fn = @o['reversibility']
        rev_fn ? rev_fn.call(vs, box) : vs['reversibility']
      end
      private :reversibility_of

      def friction_of(vs, box, mean_harm, site_min, irreversible)
        provenance = []
        widens_identity = false
        sens = @o['sensitivity'] || {}
        identity_paths = @o['identityPaths'] || []
        vs['dims'].each_with_index do |d, k|
          if d['path'].start_with?('env.prov.') && d['kind'] == 'cat'
            param = d['path']['env.prov.'.length..]
            levels = []
            box[k].each do |i|
              v = d['values'][i]
              levels.concat((v['kind'] == 'prefix' ? "#{v['value']}*" : v['value']).split(SPLIT, -1))
            end
            provenance << { 'path' => param, 'sensitivity' => W.truthy?(sens[param]) ? sens[param] : 'material', 'levels' => levels }
          end
          # widening an identity parameter = the box admits a value beyond the confirmed (exact, named) ones
          widens_identity = true if d['kind'] == 'cat' && identity_paths.include?(d['path']) && box[k].any? { |i| d['values'][i]['kind'] != 'exact' }
        end
        inp = { 'reversibility' => reversibility_of(vs, box), 'expectedHarm' => mean_harm, 'provenance' => provenance, 'widensCriticalIdentity' => widens_identity }
        inp['siteMin'] = site_min if W.truthy?(site_min)
        tier = W.friction_for(inp, W.truthy?(@o['friction']) ? @o['friction'] : W::DEFAULT_FRICTION_THRESHOLDS)['tier']
        tier = W.max_friction(tier, 'typed') if irreversible && admission['doubleConfirmIrreversible']
        tier
      end
      private :friction_of

      def render(kind, verb, coords, friction, action, vs, box, reason = nil)
        base = { 'omega' => @o['omega'], 'verb' => verb, 'coords' => coords, 'site' => { 'origin' => @o['site']['origin'], 'name' => @o['site']['name'] } }
        base['statementText'] = @o['statementText'] unless @o['statementText'].nil?
        base['reversibility'] = reversibility_of(vs, box)
        base['units'] = @o['units'] if W.truthy?(@o['units'])
        base['action'] = action if W.truthy?(action)
        base['kind'] = kind
        base['reason'] = reason if W.truthy?(reason)
        r = WalletCard.render_card(base.merge('friction' => friction))
        # a typed question needs a value to type; with none on the card, the only stronger tier is the device
        r = WalletCard.render_card(base.merge('friction' => 'device')) if r['ok'] && W.friction_rank(friction) == W.friction_rank('typed') && !W.truthy?(r['card']['typed'])
        r['ok'] ? { 'card' => r['card'], 'friction' => r['card']['friction'] } : nil
      end
      private :render

      def gate
        return { 'ok' => false, 'code' => 'frozen', 'reason' => 'the estimated false-yes rate is above η_stop: no more questions this session' } if noise['frozen']
        return { 'ok' => false, 'code' => 'cap_session', 'reason' => "at most #{W.js_str(per_session)} questions per session" } unless @session_questions < per_session
        hour_now = @o['now'].call
        unless W.finite_number?(hour_now) && @o['hourly'].count(hour_now) < per_hour
          return { 'ok' => false, 'code' => 'cap_hour', 'reason' => "at most #{W.js_str(per_hour)} questions per hour" }
        end

        { 'ok' => true }
      end
      private :gate

      def enqueue(it)
        vs = it.delete('vs')
        it['flat'] = W.box_cells(it['box']).map { |idx| W.flat_index(vs, idx) }.min
        @pending[it['id']] = it
      end
      private :enqueue

      def count
        @session_questions += 1
        raise 'unreachable' unless @o['hourly'].try_add(@o['now'].call, 9_007_199_254_740_991)
      end
      private :count

      # Insert a canary with probability rho (rendered and ordered like a real question).
      def maybe_canary
        exclude = @canary_used.dup
        @pending.each_value { |p| W.box_cells(p['box']).each { |idx| exclude << W.cell_key(p['verb'], idx) } }
        low_harm = @pending.each_value.all? { |p| p['kind'] != 'real' || W.friction_rank(p['card']['friction']) <= W.friction_rank('hold') }
        view = @o['view']
        ctx = {
          'omega' => @o['omega'], 'confirmed' => view['confirmed'].call,
          'knownNo' => ->(verb, idx) { view['outsideCeiling'].call(verb, idx) ? 'ceiling' : (view['vetoed'].call(verb, idx) ? 'veto' : nil) },
          'knownYes' => @known_yes, 'exclude' => exclude, 'rand' => @o['rand'], 'lowHarmSession' => low_harm, 'canariesSoFar' => @canaries
        }
        ctx['rho'] = @o['rho'] unless @o['rho'].nil?
        c = W.pick_canary(ctx)
        return unless c

        vs = @o['omega']['verbs'].find { |v| v['verb'] == c['verb'] }
        box = c['idx'].map { |i| [i] }
        st = box_stats(vs, box)
        return unless st

        coords = W.coords_of_cell(vs, c['idx'])
        action = { 'verb' => c['verb'], 'values' => O.cell_rep(vs, c['idx'])['values'] }
        friction = friction_of(vs, box, st['meanHarm'], nil, false)
        r = render('question', c['verb'], coords, friction, action, vs, box)
        return unless r

        @canaries += 1
        @canary_used << W.cell_key(c['verb'], c['idx'])
        enqueue({ 'id' => new_id, 'kind' => 'canary', 'source' => 'elicitation', 'verb' => c['verb'], 'box' => box, 'coords' => coords, 'card' => r['card'],
                  'action' => action, 'irreversible' => false, 'expected' => c['expected'], 'weight' => st['weight'], 'jit' => false, 'vs' => vs })
      end
      private :maybe_canary

      # Receive a site-signed intent_required (delivered directly, or relayed unchanged by the agent) together with the action the
      # agent attempted. Every check fails closed.
      def receive(ir, ctx)
        now = @o['now'].call
        v = IntentRequired.verify_intent_required(ir, @o['site']['keys'], now)
        return { 'ok' => false, 'code' => 'bad_site_signature', 'reason' => v['reason'] } unless v['ok']
        return { 'ok' => false, 'code' => 'wrong_session', 'reason' => 'the question is for another session' } if ir['session'] != @o['session']
        return { 'ok' => false, 'code' => 'stale_map', 'reason' => 'the question names another map version' } if ir['map_digest'] != @o['mapDigest'].call

        action = ctx['action']
        if action['verb'] != ir['cell']['verb'] || W.pca_action_digest(action) != ir['action_digest']
          return { 'ok' => false, 'code' => 'action_mismatch', 'reason' => 'the action does not match the signed action digest' }
        end

        lifted = @o['lift'] ? @o['lift'].call(action) : W.action_values_of(action)
        r = W.resolve_coords(@o['omega'], ir['cell']['verb'], ir['cell']['coords'])
        return { 'ok' => false, 'code' => 'cell_mismatch', 'reason' => r['reason'] } unless r['ok']

        at = W.cell_of_action(@o['omega'], lifted)
        if at.nil? || !W.cell_in_box(r['box'], at['idx'])
          return { 'ok' => false, 'code' => 'cell_mismatch', 'reason' => "the action's cell (re-derived by the wallet) is not the cell the site names" }
        end

        st = box_stats(r['vs'], r['box'])
        return { 'ok' => false, 'code' => 'cell_too_large', 'reason' => 'the question covers too many cells' } unless st

        cells = W.box_cells(r['box'])
        view = @o['view']
        verb = r['vs']['verb']
        cells.each do |idx|
          return { 'ok' => false, 'code' => 'not_uncertain', 'reason' => 'the cell is outside a ceiling: the principal cannot widen it' } if view['outsideCeiling'].call(verb, idx)
          return { 'ok' => false, 'code' => 'not_uncertain', 'reason' => 'the cell was vetoed' } if view['vetoed'].call(verb, idx)
        end
        pa = view['p'].call(verb, at['idx'])
        unless pa > 0 && pa < 1
          return { 'ok' => false, 'code' => 'not_uncertain', 'reason' => pa <= 0 ? 'the cell is denied' : 'the cell is already in the grant' }
        end
        return { 'ok' => false, 'code' => 'already_asked', 'reason' => 'a cell is asked at most once per session' } if cells.any? { |idx| @asked.include?(W.cell_key(verb, idx)) }

        g = gate
        unless g['ok']
          @refused_while_frozen << { 'verb' => verb, 'coords' => ir['cell']['coords'] } if g['code'] == 'frozen'
          return g
        end
        rev = reversibility_of(r['vs'], r['box'])
        irreversible = rev == 'irreversible'
        friction = friction_of(r['vs'], r['box'], st['meanHarm'], ir['friction'], irreversible)
        rendered = render('question', ir['cell']['verb'], ir['cell']['coords'], friction, lifted, r['vs'], r['box'])
        return { 'ok' => false, 'code' => 'render_failed', 'reason' => 'the card could not be rendered' } unless rendered
        return { 'ok' => false, 'code' => 'already_asked', 'reason' => 'duplicate question id' } if @pending.key?(ir['question_id'])

        cells.each { |idx| @asked << W.cell_key(verb, idx) }
        count
        enqueue({ 'id' => ir['question_id'], 'kind' => 'real', 'source' => 'elicitation', 'verb' => ir['cell']['verb'], 'box' => r['box'], 'coords' => ir['cell']['coords'],
                  'card' => rendered['card'], 'action' => lifted, 'actionDigest' => ir['action_digest'], 'irreversible' => irreversible, 'weight' => st['weight'],
                  'expiresAt' => ir['expires_at'], 'jit' => true, 'vs' => r['vs'] })
        maybe_canary
        { 'ok' => true, 'questionId' => ir['question_id'], 'friction' => rendered['friction'] }
      end

      # An agent clarification (3.14): {candidates: [<= 8 structured actions], reason}, no text. Certain cells are answered at once
      # (dry run); among the uncertain ones the wallet picks the most informative and asks it.
      def clarify(body)
        parsed = WalletCard.parse_clarify_request(body)
        return { 'status' => 400, 'verdicts' => [], 'error' => parsed['error'] } unless parsed['ok']

        st = noise
        pin = {
          'omega' => @o['omega'], 'view' => @o['view'], 'candidates' => parsed['request']['candidates'], 'asked' => @asked,
          'etaPos' => [0.5 - 1e-9, st['etaPosBar']].min, 'etaNeg' => [0.5 - 1e-9, st['etaNegBar']].min, 'harm' => @o['harm'] || O::DEFAULT_HARM
        }
        pin['lift'] = @o['liftCandidate'] if @o['liftCandidate']
        plan = WalletCard.plan_clarification(pin)
        return { 'status' => 200, 'verdicts' => plan['verdicts'] } unless plan['ask']

        g = gate
        return { 'status' => g['code'] == 'frozen' ? 200 : 429, 'verdicts' => plan['verdicts'], 'refused' => g['code'] } unless g['ok']

        ask = plan['ask']
        vs = @o['omega']['verbs'].find { |v| v['verb'] == ask['verb'] }
        box = ask['idx'].map { |i| [i] }
        stats = box_stats(vs, box)
        coords = W.coords_of_cell(vs, ask['idx'])
        raw = parsed['request']['candidates'][ask['index']]
        action = @o['liftCandidate'] ? @o['liftCandidate'].call(raw) : raw
        irreversible = reversibility_of(vs, box) == 'irreversible'
        friction = friction_of(vs, box, stats['meanHarm'], nil, irreversible)
        rendered = render('clarification', vs['verb'], coords, friction, action, vs, box, parsed['request']['reason'])
        return { 'status' => 200, 'verdicts' => plan['verdicts'], 'refused' => 'render_failed' } unless rendered

        qid = new_id
        @asked << W.cell_key(vs['verb'], ask['idx'])
        count
        enqueue({ 'id' => qid, 'kind' => 'real', 'source' => 'clarification', 'verb' => vs['verb'], 'box' => box, 'coords' => coords, 'card' => rendered['card'], 'action' => action,
                  'irreversible' => irreversible, 'weight' => stats['weight'], 'jit' => false, 'vs' => vs })
        maybe_canary
        { 'status' => 200, 'verdicts' => plan['verdicts'], 'questionId' => qid }
      end

      # Pending items in display order: friction desc, E[h|c]*mu(c) desc, cell index asc, id asc.
      def ordered
        @pending.values.sort_by { |i| [-W.friction_rank(i['card']['friction']), -i['weight'], i['flat'], O.u16key(i['id'])] }
      end
      private :ordered

      # The next screen. A typed or device question is always alone; tap/hold questions share up to maxPerScreen.
      def next_screen
        now = @o['now'].call
        @pending.delete_if { |_, it| !it['expiresAt'].nil? && !(W.finite_number?(now) && now <= it['expiresAt']) }
        items = ordered.select { |it| it['shownOn'].nil? }
        return nil if items.empty?

        nxt = @screen_no + 1
        eligible = items.select { |it| it['notBefore'].nil? || nxt >= it['notBefore'] }
        @screen_no = nxt
        return { 'screen' => nxt, 'kind' => 'interstitial', 'questions' => [] } if eligible.empty?

        first = eligible[0]
        picked = [first]
        if W.friction_rank(first['card']['friction']) <= W.friction_rank('hold')
          mx = @o['maxPerScreen']
          mx = 3 if mx.nil?
          eligible[1..].each do |it|
            break if picked.length >= mx

            picked << it if W.friction_rank(it['card']['friction']) <= W.friction_rank('hold')
          end
        end
        picked.each { |it| it['shownOn'] = nxt }
        { 'screen' => nxt, 'kind' => 'questions', 'questions' => picked.map { |it| { 'questionId' => it['id'], 'card' => it['card'] } } }
      end

      # The principal's response to a shown question.
      def answer(question_id, response)
        it = @pending[question_id]
        return { 'ok' => false, 'code' => 'unknown_question', 'reason' => 'no such pending question' } if it.nil?
        return { 'ok' => false, 'code' => 'not_shown', 'reason' => 'the question was never shown' } if it['shownOn'].nil?

        now = @o['now'].call
        if !it['expiresAt'].nil? && !(W.finite_number?(now) && now <= it['expiresAt'])
          @pending.delete(question_id)
          return { 'ok' => false, 'code' => 'expired', 'reason' => 'the question expired' }
        end
        partial = nil
        ans = response['answer']
        if ans == 'no'
          y = 0
        elsif ans == 'partly'
          e = WalletCard.partial_error(it['card'], response['partial'])
          return { 'ok' => false, 'code' => 'bad_response', 'reason' => e } if W.truthy?(e)

          y = 1
          partial = response['partial']
        else
          y = 1
        end
        ux = { 'tier' => it['card']['friction'], 'rendered_digest' => it['card']['rendered_digest'], 'canary' => it['kind'] == 'canary' }
        if y == 1
          ev = tier_evidence(it, response, question_id)
          return ev unless ev['ok']

          ux.merge!(ev['ux'])
        end
        plain_yes = y == 1 && partial.nil?
        if it['kind'] != 'canary' && it['jit'] && it['irreversible'] && plain_yes && W.truthy?(it['actionDigest']) &&
           W.friction_rank(it['card']['friction']) >= W.friction_rank('typed')
          ux['action_digest'] = it['actionDigest']
          ux['consent_for_action'] = true
        end
        body = { 'map_digest' => @o['mapDigest'].call, 'session' => @o['session'], 'question_id' => question_id, 'verb' => it['verb'], 'cell' => it['coords'], 'y' => y }
        body['partial'] = partial if W.truthy?(partial)
        body['source'] = it['source']
        body['observed_at'] = now
        body['ux'] = ux
        answer = W.sign_intent_answer(body, @o['principalSecret'])
        @pending.delete(question_id)
        if it['kind'] == 'canary'
          @o['onNoise'].call(W.record_canary(@o['noise'].call, it['expected'], y))
          return { 'ok' => true, 'kind' => 'canary', 'answer' => answer }
        end
        return { 'ok' => true, 'kind' => 'veto', 'answer' => answer } if y.zero?

        if plain_yes && W.friction_rank(it['card']['friction']) >= W.friction_rank('typed') && it['box'].all? { |ids| ids.length == 1 }
          # a verified high-friction yes: a source of known-yes canaries
          @known_yes << { 'verb' => it['verb'], 'idx' => it['box'].map { |ids| ids[0] } }
        end
        if plain_yes && it['irreversible'] && admission['doubleConfirmIrreversible']
          key = "#{it['verb']}|#{Js.json(it['coords'])}"
          recs = (@confirmations[key] || []) + [{ 'screen' => it['shownOn'], 'tier' => it['card']['friction'] }]
          @confirmations[key] = recs
          return { 'ok' => true, 'kind' => 'confirmed', 'answers' => [it['first'], answer] } if it['kind'] == 'confirmation' && it['first'] && W.double_confirmed(recs)
          return { 'ok' => true, 'kind' => 'pending_confirmation', 'answer' => answer } if it['kind'] == 'confirmation'

          # schedule the second, independent confirmation: at least one other screen in between
          second = it.merge('id' => new_id, 'kind' => 'confirmation', 'first' => answer, 'notBefore' => it['shownOn'] + 2)
          second.delete('shownOn')
          @pending[second['id']] = second
          return { 'ok' => true, 'kind' => 'pending_confirmation', 'answer' => answer }
        end
        { 'ok' => true, 'kind' => 'answer', 'answer' => answer }
      end

      def tier_evidence(it, response, question_id)
        r = response['answer'] == 'no' ? {} : response
        tier = it['card']['friction']
        return { 'ok' => true, 'ux' => {} } if tier == 'tap'

        if tier == 'hold'
          hm = r['holdMs']
          unless W.number?(hm) && W.finite_number?(hm) && hm == hm.floor && hm >= W::MIN_HOLD_MS
            return { 'ok' => false, 'code' => 'tier_evidence', 'reason' => "hold for at least #{W::MIN_HOLD_MS} ms" }
          end

          return { 'ok' => true, 'ux' => { 'hold_ms' => hm } }
        end
        if tier == 'typed'
          t = it['card']['typed']
          return { 'ok' => false, 'code' => 'tier_evidence', 'reason' => 'type the value shown on the card' } if !W.truthy?(t) || !W.truthy?(it['action']) || !r['typed'].is_a?(String)

          want = WalletCard.expected_typed(it['card'], it['action'])
          got = WalletCard.normalize_typed(r['typed'], t['mode'], (@o['units'] || {})[t['path']])
          return { 'ok' => false, 'code' => 'typed_mismatch', 'reason' => 'the typed value does not match the card' } if want.nil? || got.nil? || got != want

          return { 'ok' => true, 'ux' => { 'typed_digest' => W.typed_digest(question_id, got) } }
        end
        if tier == 'device'
          wa = r['webauthn']
          dev = @o['device']
          return { 'ok' => false, 'code' => 'tier_evidence', 'reason' => 'a security-key assertion is required' } if !W.truthy?(wa) || !W.truthy?(dev)
          raise TypeError, 'wa.get is not a function' unless wa.is_a?(Hash)

          cred = wa['credential_id']
          pk = cred.is_a?(String) ? dev['credentials'][cred] : nil
          ad = AtlasPca.b64d(wa['authenticator_data'])
          cd = AtlasPca.b64d(wa['client_data_json'])
          sg = AtlasPca.b64d(wa['signature'])
          return { 'ok' => false, 'code' => 'tier_evidence', 'reason' => 'unknown credential or malformed assertion' } if !W.truthy?(pk) || ad.nil? || cd.nil? || sg.nil?

          challenge = W.device_challenge(question_id, it['card']['rendered_digest'], 1, it['jit'] && it['irreversible'] && W.truthy?(it['actionDigest']) ? it['actionDigest'] : nil)
          counts = dev['signCounts']
          stored = counts.nil? ? 0 : (counts[cred] || 0)
          res = WebAuthn.verify_assertion({ 'authenticator_data' => ad, 'client_data_json' => cd, 'signature' => sg, 'public_key' => pk },
                                          { 'expected_challenge' => challenge, 'rp_id' => dev['rpId'], 'origins' => dev['origins'], 'require_uv' => true, 'stored_sign_count' => stored })
          return { 'ok' => false, 'code' => 'tier_evidence', 'reason' => "security key: #{res['reason']}" } unless res['ok']

          counts[cred] = res['signCount'] unless counts.nil?
          return { 'ok' => true, 'ux' => { 'webauthn' => wa.dup } }
        end
        raise ArgumentError, 'unknown friction tier'
      end
      private :tier_evidence

      # The WebAuthn challenge the wallet UI passes to navigator.credentials.get for a shown device-tier question.
      def device_challenge_for(question_id)
        it = @pending[question_id]
        return nil if it.nil? || it['shownOn'].nil? || it['card']['friction'] != 'device'

        W.device_challenge(question_id, it['card']['rendered_digest'], 1, it['jit'] && it['irreversible'] && W.truthy?(it['actionDigest']) ? it['actionDigest'] : nil)
      end

      # The end-of-session summary shown instead of questions once the session froze.
      def summary = { 'frozen' => noise['frozen'], 'refused' => @refused_while_frozen.dup, 'asked' => @session_questions, 'canaries' => @canaries }

      # A stable digest of the channel's pending state (for tests and audit logs).
      def state_digest
        AtlasPca.hash_canonical({ 'd' => 'atlas-pca/wallet-channel-state/v1',
                                  'p' => ordered.map { |i| { 'id' => i['id'], 'k' => i['kind'], 'd' => i['card']['rendered_digest'] } },
                                  'a' => @asked.to_a.sort_by { |k| O.u16key(k) }, 'n' => @session_questions })
      end
    end
  end
end
