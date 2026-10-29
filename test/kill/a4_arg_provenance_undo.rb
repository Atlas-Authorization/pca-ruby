# frozen_string_literal: true
# Exact-outcome kill tests for arg_provenance.rb (provenance by default), undo.rb (undo windows) and the undo_window
# obligation: token boundaries (incl. non-ASCII word bytes), the trusted-context shortcut, chain links, the action binding, pin
# lookup, floors, the undo token check order, receipt shape, chain checks, the window clamp and the obligation params.

module MutationKill
  module ProvUndo
    module_function

    KEY = AtlasPca::KeyPair.new("\x02".b * 32)
    PIN = { 'mediator' => 'm', 'kid' => 'k1', 'pk' => KEY.public }.freeze
    SEND = { 'verb' => 'email.send', 'resource' => 'mail', 'params' => { 'to' => 'bob@acme.example' } }.freeze
    SEND_FACTS = { 'effects' => ['send'] }.freeze

    def rec(now: -> { 1000 }) = AtlasPca::ProvenanceRecorder.new(mediator: 'm', kid: 'k1', key: KEY, session: AtlasPca.b64e("\x05".b * 32), now: now)

    # A bundle: segments [[origin, source, text]], then the action op.
    def bundle(segs, op = SEND, r = rec)
      segs.each do |o, s, t|
        o == 'principal' ? r.principal(t) : r.send(o.to_sym, s, t)
      end
      r.for_action(op)
    end

    def decide(b, op: SEND, pins: [PIN], action: SEND_FACTS, **extra)
      input = { 'bundle' => b, 'operation' => op, 'mediators' => pins }.merge(extra.to_h { |k, v| [k.to_s, v] })
      input['action'] = action unless action.nil?
      AtlasPca.decide_arg_provenance(input)
    end

    def deep(x) = Marshal.load(Marshal.dump(x))

    UNDO_KEY = AtlasPca::KeyPair.new("\x07".b * 32)
    OTHER = AtlasPca::KeyPair.new("\x08".b * 32)
    REC = { 'id' => 'op_1', 'aud' => 'rs', 'principal' => 'P', 'compensation_digest' => 'C', 'render_digest' => 'R', 'window_end' => 5000 }.freeze

    def receipts(n_events = %w[opened vetoed], states = %w[open vetoed], ats = [1, 2])
      rs = []
      n_events.each_with_index do |ev, i|
        rs << AtlasPca.sign_undo_receipt({ 'record' => 'op_1', 'event' => ev, 'state' => states[i], 'at' => ats[i], 'compensation_digest' => 'C',
                                           'prev' => rs.empty? ? '' : AtlasPca.undo_receipt_digest(rs[-1]), 'note' => '' }, UNDO_KEY)
      end
      rs
    end

    def chain_rec(rs, state = 'vetoed') = { 'id' => 'op_1', 'compensation_digest' => 'C', 'state' => state, 'receipts' => rs }
  end

  P = ProvUndo

  # ---- occurs_as_token: both sides of the boundary, ASCII and not
  t('prov: token boundaries both sides') do
    [['a b', 'a', true], ['b a', 'a', true], ['xa', 'a', false], ['ax', 'a', false], ['a_', 'a', false], ['_a', 'a', false],
     ['a9', 'a', false], ['9a', 'a', false], ['aé', 'a', false], ['éa', 'a', false], ['a.', 'a', true], ['.a', 'a', true],
     ['a', 'a', true], ['', 'a', false], ['a', '', false], ['ab a', 'a', true], ['Aa', 'a', false]].all? do |text, needle, want|
      AtlasPca.occurs_as_token(text, needle) == want
    end
  end

  # ---- the trusted-context shortcut: a principal-only context trusts everything, an observed tool call raises it
  t('prov: principal-only context passes, an observed tool raises it') do
    b = P.bundle([['principal', 'user', 'hello']])
    ok = P.decide(b)
    hit = P.decide(P.deep(b), observed: [{ 'origin' => 'tool', 'source' => 'x' }])
    ok['outcome'] == 'pass' && ok['labels'] == { 'to' => 'trusted' } && ok['control'] == 'trusted' &&
      hit['outcome'] == 'escalate' && hit['code'] == 'untrusted_control_and_args' && hit['labels'] == { 'to' => 'tool' } &&
      hit['path'] == ['tool:x'] && hit['verified'] == true
  end

  t('prov: a value the principal typed verbatim stays trusted in a tool context') do
    b = P.bundle([['principal', 'user', 'mail bob@acme.example the report'], ['tool', 'crm', 'whatever']])
    d = P.decide(b, principal_control: true)
    typed = d['outcome'] == 'pass' && d['labels'] == { 'to' => 'trusted' }
    b2 = P.bundle([['principal', 'user', 'mail xbob@acme.example'], ['tool', 'crm', 'bob@acme.example']])
    d2 = P.decide(b2, principal_control: true)
    typed && d2['outcome'] == 'escalate' && d2['code'] == 'untrusted_args' && d2['tainted'] == ['to']
  end

  # ---- chain links: prev of receipt 0, issued_at direction
  t('prov: receipt 0 must have a null prev') do
    b = P.bundle([['principal', 'user', 'hi']])
    b['receipts'][0]['prev'] = AtlasPca.prov_receipt_ref(b['receipts'][1])
    d = P.decide(b)
    d['outcome'] == 'deny' && d['code'] == 'broken_chain' && d['reason'] == 'receipt 0 does not link to its predecessor'
  end

  t('prov: issued_at may stay equal but never go back') do
    same = P.decide(P.bundle([['principal', 'user', 'bob@acme.example']]))
    b = P.bundle([['principal', 'user', 'hi'], ['tool', 't', 'x']], P::SEND, P.rec(now: -> { 1000 }))
    b['receipts'][1]['issued_at'] = 999
    back = P.decide(b)
    same['outcome'] == 'pass' && back['code'] == 'broken_chain' && back['reason'] == 'receipt 1 is older than its predecessor'
  end

  # ---- the last receipt binds verb, resource and params
  t('prov: the action receipt binds verb, resource and each param') do
    b = P.bundle([['principal', 'user', 'bob@acme.example']])
    others = [P::SEND.merge('verb' => 'email.draft'), P::SEND.merge('resource' => 'mail2'), P::SEND.merge('params' => { 'to' => 'eve@x.example' }),
              P::SEND.merge('params' => { 'to' => 'bob@acme.example', 'cc' => 'x' })].map(&:freeze)
    P.decide(P.deep(b))['outcome'] == 'pass' &&
      others.all? { |o| (d = P.decide(P.deep(b), op: o))['code'] == 'unbound_action' && d['outcome'] == 'deny' }
  end

  # ---- pin lookup by mediator AND kid
  t('prov: a pin must match mediator and kid') do
    b = P.bundle([['principal', 'user', 'bob@acme.example']])
    wrong_kid = P.decide(P.deep(b), pins: [P::PIN.merge('kid' => 'k2')])
    wrong_med = P.decide(P.deep(b), pins: [P::PIN.merge('mediator' => 'n')])
    other_key = P.decide(P.deep(b), pins: [P::PIN.merge('pk' => P::UNDO_KEY.public)])
    both = P.decide(P.deep(b), pins: [P::PIN.merge('kid' => 'k2'), P::PIN])
    [wrong_kid, wrong_med].all? { |d| d['outcome'] == 'escalate' && d['verified'] == false && d['path'] == ['unlabelled'] } &&
      other_key['code'] == 'bad_signature' && both['outcome'] == 'pass' && both['verified'] == true
  end

  # ---- floors: an explicit floor, the sensitive default (first_party) and the non-sensitive fallback (agent)
  t('prov: floors and the non-sensitive fallback') do
    b = P.bundle([['principal', 'user', 'hi'], ['tool', 't', 'x']])
    read = P.decide(P.deep(b), action: { 'effects' => ['read'] })
    floored = P.decide(P.deep(b), action: { 'effects' => ['send'], 'params' => { 'to' => 'tool' } }, principal_control: true)
    low = P.decide(P.deep(b), action: { 'effects' => ['send'], 'params' => { 'to' => 'first_party' } }, principal_control: true)
    unknown = P.decide(P.deep(b), action: nil, principal_control: true)
    read['outcome'] == 'pass' && read['sensitive'] == false && read['labels'] == { 'to' => 'tool' } &&
      floored['outcome'] == 'pass' && low['tainted'] == ['to'] && unknown['sensitive'] == true && unknown['tainted'] == ['to']
  end

  t('prov: no bundle is unverified agent context, never a pass for a sensitive action') do
    d = P.decide(nil)
    r = P.decide(nil, action: { 'effects' => ['read'] })
    d['outcome'] == 'escalate' && d['code'] == 'untrusted_control_and_args' && d['path'] == ['unlabelled'] &&
      r['outcome'] == 'pass' && r['labels'] == { 'to' => 'agent' }
  end

  t('prov: the envelope member is closed and the opt-out exact') do
    AtlasPca.prov_envelope_error({}).nil? && AtlasPca.prov_envelope_error({ 'mode' => 'insecure_off' }).nil? &&
      AtlasPca.prov_envelope_error({ 'mode' => 'enforce', 'mediators' => [P::PIN] }).nil? &&
      !AtlasPca.prov_envelope_error({ 'mode' => 'off' }).nil? && !AtlasPca.prov_envelope_error({ 'x' => 1 }).nil? &&
      !AtlasPca.prov_envelope_error({ 'mediators' => [P::PIN] * 17 }).nil? && !AtlasPca.prov_envelope_error(nil).nil?
  end

  # ---- the recorder clips a long source by UTF-16 units, as the reference does (derived by hand from its clip):
  # 50 x U+1F600 (2 units, 4 bytes) + 30 x U+00E9 (1 unit, 2 bytes) + 'x' = 131 units, 261 bytes > 256 -> keep 65 units =
  # 32 emoji + the lone high surrogate D83D of the 33rd: the strict canonicalizer refuses it, so recording raises (nothing is
  # appended). 100 x U+00E9 + 41 x U+1F600 + 'b' = 183 units,
  # 365 bytes -> 91 units, all U+00E9 (182 bytes). 300 x 'a' -> 150 'a'. Short and empty sources are kept / '-'.
  t('prov: clip halves by UTF-16 units like the reference') do
    clip = ->(src) { P.rec.send(:clip, src) }
    rec = P.rec
    split = begin
      rec.web(("\u{1F600}" * 50) + ("\u00E9" * 30) + 'x', 'page')
      false
    rescue AtlasPca::Malformed
      rec.receipts.empty?
    end
    split &&
      clip.call(("\u00E9" * 100) + ("\u{1F600}" * 41) + 'b') == "\u00E9" * 91 &&
      clip.call('a' * 300) == 'a' * 150 && clip.call('a' * 256) == 'a' * 256 && clip.call('') == '-' &&
      clip.call(("\u{1F600}" * 64) + 'é') == "\u{1F600}" * 32 # 129 units, 258 bytes -> 64 units = 32 whole emoji
  end

  # ---- undo token: every code, in order, and the inclusive exp boundary
  t('undo: token check order and the inclusive exp') do
    tok = AtlasPca.sign_undo_token(P::REC, P::UNDO_KEY)
    pub = P::UNDO_KEY.public
    tampered = tok.merge('exp' => 5001)
    AtlasPca.undo_token_check(tok, pub, P::REC, 5000) == 'ok' &&
      AtlasPca.undo_token_check(tok, pub, P::REC, 5001) == 'expired' &&
      AtlasPca.undo_token_check(tok, pub, P::REC, 0) == 'ok' &&
      AtlasPca.undo_token_check(tok.merge('x' => 1), pub, P::REC, 0) == 'malformed' &&
      AtlasPca.undo_token_check(tok.reject { |k, _| k == 'render_digest' }, pub, P::REC, 0) == 'malformed' &&
      AtlasPca.undo_token_check(tampered, P::OTHER.public, P::REC, 0) == 'signer' &&
      AtlasPca.undo_token_check(tampered, pub, P::REC.merge('id' => 'op_2'), 0) == 'signature' &&
      AtlasPca.undo_token_check(tok, pub, P::REC.merge('id' => 'op_2', 'aud' => 'x'), 9999) == 'record' &&
      AtlasPca.undo_token_check(tok, pub, P::REC.merge('aud' => 'x'), 9999) == 'binding' &&
      AtlasPca.undo_token_check(tok, pub, P::REC.merge('window_end' => 5001), 0) == 'binding' &&
      AtlasPca.undo_token_check(tok, pub, P::REC, 1.5) == 'expired'
  end

  t('undo: a record without render_digest binds the empty string') do
    rec = P::REC.reject { |k, _| k == 'render_digest' }
    tok = AtlasPca.sign_undo_token(rec, P::UNDO_KEY)
    tok['render_digest'] == '' && AtlasPca.undo_token_check(tok, P::UNDO_KEY.public, rec, 0) == 'ok' &&
      AtlasPca.undo_token_check(tok, P::UNDO_KEY.public, P::REC, 0) == 'binding'
  end

  t('undo: token encoding round trip and refusals') do
    tok = AtlasPca.sign_undo_token(P::REC, P::UNDO_KEY)
    AtlasPca.decode_undo_token(AtlasPca.encode_undo_token(tok)) == tok && AtlasPca.decode_undo_token('').nil? &&
      AtlasPca.decode_undo_token('a' * 4097).nil? && AtlasPca.decode_undo_token(AtlasPca.b64e('[1]')).nil? &&
      AtlasPca.decode_undo_token('!!').nil? && AtlasPca.decode_undo_token(nil).nil?
  end

  # ---- receipts: exactly 11 members, chain prev / at / first / last state
  t('undo: receipt member count') do
    r = P.receipts[0]
    AtlasPca.verify_undo_receipt(r, P::UNDO_KEY.public) && r.length == 11 &&
      !AtlasPca.verify_undo_receipt(r.merge('x' => 1), P::UNDO_KEY.public) &&
      !AtlasPca.verify_undo_receipt(r.reject { |k, _| k == 'note' }, P::UNDO_KEY.public) &&
      !AtlasPca.verify_undo_receipt(r, P::OTHER.public)
  end

  t('undo: receipt chain prev, at, first event and last state') do
    sound = AtlasPca.undo_receipt_chain_error(P.chain_rec(P.receipts), P::UNDO_KEY.public).nil?
    same_at = AtlasPca.undo_receipt_chain_error(P.chain_rec(P.receipts(%w[opened vetoed], %w[open vetoed], [2, 2])), P::UNDO_KEY.public).nil?
    back = AtlasPca.undo_receipt_chain_error(P.chain_rec(P.receipts(%w[opened vetoed], %w[open vetoed], [2, 1])), P::UNDO_KEY.public)
    first = AtlasPca.undo_receipt_chain_error(P.chain_rec(P.receipts(%w[vetoed], %w[vetoed], [1])), P::UNDO_KEY.public)
    last = AtlasPca.undo_receipt_chain_error(P.chain_rec(P.receipts, 'open'), P::UNDO_KEY.public)
    rs = P.receipts
    gap = AtlasPca.undo_receipt_chain_error(P.chain_rec([rs[1]]), P::UNDO_KEY.public)
    sound && same_at && back == 'receipt 1 goes back in time' && first == 'the first receipt is not opened' &&
      last == 'the last receipt does not state the record state' && gap == 'receipt 0 does not link to the previous one' &&
      AtlasPca.undo_receipt_chain_error(P.chain_rec([]), P::UNDO_KEY.public) == 'no receipts'
  end

  t('undo: undo_with_receipt links each receipt to the previous one') do
    rec = { 'id' => 'op_1', 'compensation_digest' => 'C', 'state' => 'open' }
    a = AtlasPca.undo_with_receipt(rec, { 'event' => 'opened', 'note' => '' }, 1, P::UNDO_KEY)
    b = AtlasPca.undo_with_receipt(a.merge('state' => 'vetoed'), { 'event' => 'vetoed', 'note' => 'token' }, 2, P::UNDO_KEY)
    b['receipts'][0]['prev'] == '' && b['receipts'][1]['prev'] == AtlasPca.undo_receipt_digest(b['receipts'][0]) &&
      AtlasPca.undo_receipt_chain_error(b, P::UNDO_KEY.public).nil? && !a.key?('ver')
  end

  t('undo: transitions keep the input record and refuse a non-safe attempt') do
    rec = { 'state' => 'compensation_failed', 'window_end' => 10, 'ver' => 1, 'attempt' => 2**53 }
    r = AtlasPca.undo_transition(rec, { 'kind' => 'retry' }, 5)
    ok = AtlasPca.undo_transition(rec.merge('attempt' => 0), { 'kind' => 'retry' }, 5)
    v = { 'state' => 'open', 'window_end' => 10, 'ver' => 1 }
    a = AtlasPca.undo_transition(v, { 'kind' => 'veto', 'veto' => { 'at' => 1, 'via' => 'token', 'by' => 'p' } }, 10)
    r['code'] == 'invalid' && ok['record']['attempt'] == 1 && ok['record']['state'] == 'vetoed' && ok['receipt'] == { 'event' => 'retried', 'note' => '' } &&
      a['record']['ver'] == 2 && v['ver'] == 1 && !v.key?('veto') && a['receipt'] == { 'event' => 'vetoed', 'note' => 'token' } &&
      AtlasPca.undo_transition(v, { 'kind' => 'finalize' }, 11)['record']['outcome'] == { 'at' => 11, 'status' => 'finalized' } &&
      AtlasPca.undo_transition(v, { 'kind' => 'finalize' }, 10)['code'] == 'window_open'
  end

  # ---- the window clamp edges and the policy key spellings
  t('undo: window clamp edges') do
    w = ->(r, p = {}) { AtlasPca.resolve_undo_window(r, p) }
    w.call(29_999) == 30_000 && w.call(30_001) == 30_001 && w.call(86_400_001) == 86_400_000 && w.call(86_399_999) == 86_399_999 &&
      w.call(Float::NAN) == 900_000 && w.call(Float::INFINITY) == 900_000 && w.call(nil) == 900_000 && w.call(45_000.7) == 45_000 &&
      w.call(nil, { 'default_ms' => 60_000 }) == 60_000 && w.call(nil, { defaultMs: 61_000 }) == 61_000 &&
      w.call(90_000, { max_ms: 40_000 }) == 40_000 && w.call(1, { 'minMs' => 100_000_000 }) == 100_000_000
  end

  # ---- the undo_window obligation: exactly {id, window_end}
  t('undo: obligation params') do
    ok = ->(params) { AtlasPca.obligation_error({ 'kind' => 'undo_window', 'params' => params }).nil? }
    ok.call({ 'id' => 'a' * 128, 'window_end' => 0 }) && !ok.call({ 'id' => 'a' * 129, 'window_end' => 0 }) &&
      !ok.call({ 'id' => 'x', 'window_end' => -1 }) && !ok.call({ 'id' => 'x', 'window_end' => 2**53 }) &&
      !ok.call({ 'id' => 'x', 'window_end' => 1, 'by' => 'y' }) && !ok.call({ 'id' => '', 'window_end' => 1 }) &&
      !ok.call({ 'window_end' => 1 }) && !ok.call({ 'id' => 'x' }) &&
      AtlasPca.obligation_error(AtlasPca.undo_window_obligation('op_1', 7)).nil? &&
      AtlasPca.undo_window_obligation('op_1', 7) == { 'kind' => 'undo_window', 'params' => { 'id' => 'op_1', 'window_end' => 7 }, 'due' => 7 }
  end

  t('undo: an admission is validated, a raising hook is none') do
    good = { id: 'op_1', window_end: 9, compensation: { verb: 'drafts.delete', resource: 'drafts' } }
    a = AtlasPca.undo_admission(->(*) { good }, {}, {}, {})
    a == { 'id' => 'op_1', 'window_end' => 9, 'compensation' => { 'verb' => 'drafts.delete', 'resource' => 'drafts' } } &&
      AtlasPca.undo_admission(->(*) { raise 'down' }, {}, {}, {}).nil? &&
      AtlasPca.undo_admission(->(*) { good.merge(compensation: { verb: '', resource: 'd' }) }, {}, {}, {}).nil? &&
      AtlasPca.undo_admission(->(*) { good.merge(compensation: nil) }, {}, {}, {}).nil? &&
      AtlasPca.undo_admission(->(*) { good.merge(window_end: -1) }, {}, {}, {}).nil? &&
      AtlasPca.undo_admission(->(*) { good.merge(id: 'x' * 129) }, {}, {}, {}).nil? &&
      AtlasPca.undo_admission(->(*) {}, {}, {}, {}).nil?
  end
end
