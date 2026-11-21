# frozen_string_literal: true

# d41 (round 3): kills the mutants that survived c20..c33 in workflow.rb, break_glass.rb, optimistic.rb, escalation.rb,
# operations.rb and stepup.rb. Every AtlasPca constant / module is resolved at CALL time (the oracle re-evaluates AtlasPca per
# mutant). Reuses the fixtures of c23 (C23Wea / C23Esc), c29 (C29) and c30 (C30), which load earlier.
require 'tmpdir'
require 'json'

module MutationKill
  module D41
    module_function

    def skip?(*names) = (f = ENV['MUT_FILE']) && !f.empty? && !names.include?(f)

    def eq(label, got, want)
      return true if got == want && got.class == want.class

      raise "d41 #{label}: got #{got.inspect}, want #{want.inspect}"
    end

    # the receipt `r` (from C23Wea.rcpt) with members replaced and the signature recomputed by the receipt signer
    def resign(r, over)
      body = r.reject { |k, _| k == 'sig' }.merge(over)
      body.merge('sig' => C23Wea.sign(C23Wea::RD, body, 'rs'))
    end
  end

  # ------------------------------------------------------------------------------------------------------------------ workflow
  t('d41 workflow: valid_workflow_body? refuses a budget whose caps are not a name -> uint map (even with no cost to cap)') do
    next true if D41.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    body = ->(caps) { c.body_h([c.step_h('a')], [], caps: caps) }
    D41.eq('empty caps', m.valid_workflow_body?(body.call({})), true) &&
      D41.eq('one cap', m.valid_workflow_body?(body.call({ 'tok' => 1 })), true) &&
      D41.eq('eight caps', m.valid_workflow_body?(body.call(c.many(8))), true) &&
      D41.eq('negative cap', m.valid_workflow_body?(body.call({ 'tok' => -1 })), false) &&
      D41.eq('string cap', m.valid_workflow_body?(body.call({ 'tok' => 'x' })), false) &&
      D41.eq('bad cap name', m.valid_workflow_body?(body.call({ 'bad name' => 1 })), false) &&
      D41.eq('nine caps', m.valid_workflow_body?(body.call(c.many(9))), false)
  end

  t('d41 workflow: receipts are refused for a broken shape, a foreign signer field and a wrong sequence number, each on its own') do
    next true if D41.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    one = c.body_h([c.step_h('a')])
    two = c.body_h([c.step_h('a'), c.step_h('b')])
    # shape-invalid (extra member) but the signature, signer, workflow, sequence and clock are all fine: the extra member is
    # not part of the signed body
    r0 = c.rcpt(one, 'a', 0, nil).merge('zz' => 1)
    shape = m.admit_step(c.inp(one, [r0], c.req_h('a')))
    # a signer member other than rs_signer, signed by rs_signer's key over that body: only the signer comparison refuses it
    s0 = D41.resign(c.rcpt(one, 'a', 0, nil), 'signer' => c.pub('other'))
    signer = m.admit_step(c.inp(one, [s0], c.req_h('a')))
    # receipt 1 carries seq 2 with the right prev hash and a valid signature: only the sequence check refuses it
    a0 = c.rcpt(two, 'a', 0, nil)
    seq = m.admit_step(c.inp(two, [a0, c.rcpt(two, 'b', 2, a0)], c.req_h('b')))
    # the same chain with seq 1 is fine (the step b receipt is then found: already_done)
    seq_ok = m.admit_step(c.inp(two, [a0, c.rcpt(two, 'b', 1, a0)], c.req_h('b')))
    # a wrong prev hash with a valid signature: only the chain check refuses it
    wrong_prev = m.admit_step(c.inp(two, [a0, D41.resign(c.rcpt(two, 'b', 1, a0), 'prev' => c.dg('x'))], c.req_h('b')))
    D41.eq('extra member', shape, c.res('deny', 'bad_receipt', 'a', 0)) &&
      D41.eq('foreign signer member', signer, c.res('deny', 'bad_receipt', 'a', 0)) &&
      D41.eq('seq 2 at index 1', seq, c.res('deny', 'bad_receipt', 'b', 1)) &&
      D41.eq('seq 1 at index 1', seq_ok, c.res('deny', 'already_done', 'b')) &&
      D41.eq('wrong prev hash', wrong_prev, c.res('deny', 'bad_receipt', 'b', 1))
  end

  t('d41 workflow: a first receipt that carries a prev hash is refused even when the shape check is bypassed (seam)') do
    next true if D41.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    one = c.body_h([c.step_h('a')])
    r0 = D41.resign(c.rcpt(one, 'a', 0, nil), 'prev' => c.dg('x'))
    got = Seam.with(AtlasPca, { :k5_valid_receipt_shape? => ->(_r) { true } }) { m.admit_step(c.inp(one, [r0], c.req_h('a'))) }
    D41.eq('prev on the first receipt', got, c.res('deny', 'bad_receipt', 'a', 0))
  end

  t('d41 workflow: k5_verify_body needs a String signer before it asks k3 (seam)') do
    next true if D41.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    Seam.with(AtlasPca, { :k3_verify_body => ->(*_a) { true } }) do
      D41.eq('integer signer', m.k5_verify_body(c::FD, {}, 5, 'x'), false) && D41.eq('nil signer', m.k5_verify_body(c::FD, {}, nil, 'x'), false) &&
        D41.eq('string signer', m.k5_verify_body(c::FD, {}, 'abc', 'x'), true)
    end
  end

  t('d41 workflow: the body principal must be the pinned principal, whatever key signed the body') do
    next true if D41.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    # signed by 'p' (the pinned principal) but the body names 'q' as its principal
    b = c.body_h([c.step_h('a')], [], root: c.dg('root')).merge('principal' => c.pub('q'))
    sw = { 'body' => b, 'sig' => c.sign(c::FD, b, 'p') }
    D41.eq('admit', m.admit_step(c.inp(b, [], c.req_h('a'))), c.res('deny', 'bad_signature', 'a')) &&
      D41.eq('bind', m.bind_promises(c.inp(b, [], c.req_h('a'))), c.res('deny', 'bad_signature', 'a')) &&
      D41.eq('plan root', c.pra(sw), false) &&
      D41.eq('control', c.pra({ 'body' => c.body_h([c.step_h('a')], [], root: c.dg('root')),
                                'sig' => c.sign(c::FD, c.body_h([c.step_h('a')], [], root: c.dg('root')), 'p') }), true)
  end

  t('d41 workflow: an edge must start at a declared step, not merely at a name the ancestor map lists (seam)') do
    next true if D41.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    e = 'edge does not follow a dependency'
    steps = [c.st('a'), c.st('b')]
    got = Seam.with(AtlasPca, { :wf_ancestors => ->(_b) { { 'a' => {}, 'b' => { 'z' => true } } } }) do
      [m.wf_dag_error({ 'steps' => steps, 'edges' => [c.eg('z', 'b')] }), m.wf_dag_error({ 'steps' => steps, 'edges' => [c.eg('a', 'b')] })]
    end
    D41.eq('unknown from, listed as an ancestor', got[0], e) && D41.eq('known from, not an ancestor', got[1], e)
  end

  t('d41 workflow: admission refuses a request, principal, signer or clock that is not well-formed, with bad_workflow') do
    next true if D41.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    b = c.body_h([c.step_h('a')])
    good = c.inp(b, [], c.req_h('a'))
    bad = c.res('deny', 'bad_workflow', nil)
    rows = { 'request with an extra member' => good.merge('request' => c.req_h('a').merge('zz' => 1)),
             'principal not base64url' => good.merge('principal' => 'x'),
             'rs_signer not base64url' => good.merge('rs_signer' => 'x'),
             'negative now' => good.merge('now' => -1), 'float now' => good.merge('now' => 3000.0),
             'now past the safe range' => good.merge('now' => 2**53), 'nil now' => good.merge('now' => nil) }
    D41.eq('control', m.admit_step(good), c.res('allow', nil, 'a')) &&
      rows.all? { |label, inp| D41.eq("admit #{label}", m.admit_step(inp), bad) && D41.eq("bind #{label}", m.bind_promises(inp), bad) }
  end

  t('d41 workflow: an edge unit must equal the unit the edge declares, even when it equals the request unit') do
    next true if D41.skip?('workflow.rb')

    c = C23Wea
    m = AtlasPca
    run = lambda do |edge_unit|
      b = c.body_h([c.step_h('a'), c.step_h('b', deps: ['a'])], [c.edge_h('a', 'x', 'b', 'p', unit: edge_unit)])
      m.admit_step(c.inp(b, [c.rcpt(b, 'a', 0, nil, outputs: { 'x' => c.out_h(1, unit: 'usd') })],
                         c.req_h('b', params: { 'p' => 1 }, units: { 'p' => 'usd' })))
    end
    D41.eq('edge declares no unit', run.call(nil), c.res('deny', 'edge_unit', 'b', 0)) &&
      D41.eq('edge declares another unit', run.call('eur'), c.res('deny', 'edge_unit', 'b', 0)) &&
      D41.eq('all three agree', run.call('usd'), c.res('allow', nil, 'b'))
  end

  # ------------------------------------------------------------------------------------------------------------------ break glass
  t('d41 break_glass: both domains are frozen binary strings with the exact bytes') do
    next true if D41.skip?('break_glass.rb')

    [[AtlasPca::BREAK_GLASS_DOMAIN, "atlas-pca/break-glass/v1\x00".b], [AtlasPca::BREAK_GLASS_REVIEW_DOMAIN, "atlas-pca/break-glass-review/v1\x00".b]].all? do |got, want|
      D41.eq('bytes', got.bytes, want.bytes) && D41.eq('encoding', got.encoding, Encoding::BINARY) && D41.eq('frozen', got.frozen?, true)
    end
  end

  t('d41 break_glass: a review stamped at the instant of the first use is on time') do
    next true if D41.skip?('break_glass.rb')

    reg = C30.bg_reg
    ok = [reg.accept(C30.sign_grant(C30.grant), 1000), reg.use('g1', 'h1', 'dg1', 1000, true),
          reg.review(C30.sign_review(C30.review('at' => 1000)), 'h1', 1200)]
    early = C30.bg_reg
    early.accept(C30.sign_grant(C30.grant), 1000)
    early.use('g1', 'h1', 'dg1', 1000, true)
    late = early.review(C30.sign_review(C30.review('at' => 999)), 'h1', 1200)
    D41.eq('accept', ok[0], { 'ok' => true, 'replaced' => true }) &&
      D41.eq('use', ok[1], { 'decision' => 'allow', 'id' => 'g1', 'use' => 1, 'remaining' => 1, 'review_due' => 1500 }) &&
      D41.eq('review at the first use', ok[2], { 'ok' => true, 'replaced' => true }) &&
      D41.eq('review before the first use', late, { 'ok' => false, 'code' => 'bad_time' })
  end

  # ------------------------------------------------------------------------------------------------------------------ optimistic
  t('d41 optimistic: the challenge window is closed to a time that is not a finite number') do
    next true if D41.skip?('optimistic.rb')

    m = AtlasPca
    claim = { 'issued_at' => 1000, 'challenge_window_ms' => 500 }
    D41.eq('inside', m.within_challenge_window(claim, 1500), true) && D41.eq('after', m.within_challenge_window(claim, 1501), false) &&
      D41.eq('minus infinity', m.within_challenge_window(claim, -Float::INFINITY), false) &&
      D41.eq('infinity', m.within_challenge_window(claim, Float::INFINITY), false) &&
      D41.eq('nil', m.within_challenge_window(claim, nil), false) && D41.eq('string', m.within_challenge_window(claim, '1'), false) &&
      D41.eq('status nil', m.claim_status(claim, nil), 'finalized') && D41.eq('status inside', m.claim_status(claim, 1000), 'open')
  end

  t('d41 optimistic: a slash split with a negative treasury remainder or victim compensation is a bad split') do
    next true if D41.skip?('optimistic.rb')

    base = { 'claimId' => 'c1', 'action' => 'slash', 'amount' => 10, 'from' => 'a', 'to' => 'T', 'at' => 5, 'evidenceDigest' => 'ev', 'sig' => 'S' }
    split = { 'amount' => 10, 'challengerAccount' => 'ch', 'challengerReward' => 3, 'victimCompensation' => 4, 'treasuryRemainder' => 3,
              'victimAccount' => 'v', 'treasuryAccount' => 'T' }
    rec = ->(over) { base.merge('split' => split.merge(over)) }
    got = nil
    Seam.with(AtlasPca::IntentV2, { :verify_pinned_suite => ->(*_a) { true } }) do
      sw = ->(r) { AtlasPca.settlement_wire_check(r, 'GP') }
      got = [sw.call(rec.call({})), sw.call(rec.call('challengerReward' => 6, 'victimCompensation' => 6, 'treasuryRemainder' => -2)),
             sw.call(rec.call('challengerReward' => 6, 'victimCompensation' => -2, 'treasuryRemainder' => 6)),
             sw.call(rec.call('challengerReward' => -2, 'victimCompensation' => 6, 'treasuryRemainder' => 6))]
    end
    D41.eq('sums to the amount, all non-negative', got[0], 'ok') && D41.eq('negative treasury remainder', got[1], 'split') &&
      D41.eq('negative victim compensation', got[2], 'split') && D41.eq('negative challenger reward', got[3], 'split')
  end

  # ------------------------------------------------------------------------------------------------------------------ escalation
  t('d41 escalation: a non-String principal / render_digest is refused even if the decoder were to accept it (seam)') do
    next true if D41.skip?('escalation.rb')

    e = C23Esc
    orig = AtlasPca.method(:b64d)
    d = 'must be canonical base64url (32 bytes)'
    got = nil
    Seam.with(AtlasPca, { :b64d => ->(s, *r) { s == 5 ? 'x' : orig.call(s, *r) } }) do
      got = [AtlasPca.escalation_answer_shape_error(e.base('principal' => 5)), AtlasPca.escalation_answer_shape_error(e.base('render_digest' => 5)),
             AtlasPca.escalation_answer_shape_error(e.base)]
    end
    D41.eq('principal', got[0], "principal #{d}") && D41.eq('render_digest', got[1], "render_digest #{d}") && D41.eq('control', got[2], nil)
  end

  t('d41 escalation: only a Float v / iat / expires_at is turned into its integer, nothing else is touched (seam over the safe-int test)') do
    next true if D41.skip?('escalation.rb')

    e = C23Esc
    plain = e.base
    body = plain.reject { |k, _| %w[sig pq_sig].include?(k) }
    want = e::ESC_D + AtlasPca.canon_bytes(body.merge('iat' => '7'))
    got = Seam.with(AtlasPca, { :decision_safe_int? => ->(_x) { true } }) { AtlasPca.escalation_answer_message(plain.merge('iat' => '7')) }
    D41.eq('a String iat stays a String', got, want)
  end

  # ------------------------------------------------------------------------------------------------------------------ operations
  module D41Ops
    module_function

    PC = { 'action' => { 'verb' => 'v.do' }, 'n' => 1 }.freeze

    def run(ops, result, pcactn, operation)
      opts = AtlasPca::AuthorizeOptions.new(is_revoked: ->(_p, _g) { false })
      ex = AtlasPca.create_executor(operations: ops, options: opts, audience: 'a', resolve_grant: ->(_r) { {} }, now: -> { 5 })
      Seam.with(AtlasPca, { :authorize => ->(*_a, **_k) { result } }) { ex.call(pcactn, operation) { raise 'd41 must not run' } }
    end

    def res = AtlasPca::AuthorizeResult.new(allow: false, status: 403, checks: { 'replay' => 'fail', 'sig' => 'pass' }, reason: 'R')
  end

  t('d41 operations: a replay of a PCActn that cannot be decoded is denied even if a record sits under the digest of nothing') do
    next true if D41.skip?('operations.rb')

    dig = AtlasPca.params_digest(AtlasPca.params_copy({ 'a' => 1 }))
    ops = AtlasPca::MemoryOperationStore.new
    ops.create({ 'id' => AtlasPca.hash_canonical(nil), 'state' => 'committed', 'verb' => 'v.do', 'resource' => '/r/1', 'params_digest' => dig, 'result' => 'RES' })
    r = D41Ops.res
    denied = ['denied', nil, nil, false, true, nil, 'R', r]
    operation = { 'verb' => 'v.do', 'resource' => '/r/1', 'params' => { 'a' => 1 } }
    D41.eq('undecodable text', D41Ops.run(ops, r, 'garbage', operation).to_a, denied) && D41.eq('absent', D41Ops.run(ops, r, nil, operation).to_a, denied)
  end

  t('d41 operations: a replayed operation is matched on its canonical params copy (symbol and string spellings of one key collapse)') do
    next true if D41.skip?('operations.rb')

    id = AtlasPca.hash_canonical(D41Ops::PC)
    ops = AtlasPca::MemoryOperationStore.new
    ops.create({ 'id' => id, 'state' => 'committed', 'verb' => 'v.do', 'resource' => '/r/1', 'params_digest' => AtlasPca.hash_canonical({ 'a' => 2 }),
                 'result' => 'RES' })
    r = D41Ops.res
    # {a: 1, 'a' => 2} is {'a' => 2} once copied: the last spelling wins
    got = D41Ops.run(ops, r, D41Ops::PC, { verb: 'v.do', resource: '/r/1', params: { a: 1, 'a' => 2 } }).to_a
    D41.eq('answered from the record', got, ['committed', id, 'RES', true, true, nil, nil, nil])
  end

  # ------------------------------------------------------------------------------------------------------------------ stepup
  t('d41 stepup: an error answer with a null message gives an empty message, never the class name') do
    next true if D41.skip?('stepup.rb')

    su = C29.su
    body = JSON.generate({ 'errors' => [{ 'message' => nil }] })
    msg = lambda do |status|
      cc, = C29.client(C29::Fake.new([status, body]))
      cc.pending
      :returned
    rescue su::Error => e
      [e.class.name.split('::').last, e.message]
    end
    D41.eq('500', msg.call(500), %w[ApiError] + ['']) && D41.eq('403', msg.call(403), %w[PrincipalMismatch] + [''])
  end

  t('d41 stepup: the file secret store ignores whitespace around the stored seed') do
    next true if D41.skip?('stepup.rb')

    seed = ('k' * 32).b
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'seed')
      File.write(path, "#{AtlasPca.b64e(seed)}\n")
      got = AtlasPca::StepUp::FileSecretStore.new(path).load
      File.write(path, "  #{AtlasPca.b64e(seed)} \r\n")
      got2 = AtlasPca::StepUp::FileSecretStore.new(path).load
      D41.eq('trailing newline', got, seed) && D41.eq('surrounding blanks', got2, seed)
    end
  end

  t('d41 stepup: the built-in transport gives Net::HTTP the request path, so a non-HTTP URI scheme is still spoken to as plain HTTP') do
    next true if D41.skip?('stepup.rb') || !defined?(URI::WS)

    su = C29.su
    C29.with_server([{ data: C29.http(200, 'OK', 'hi') }]) do |port, seen|
      got = su.net_transport(5).call('GET', "ws://127.0.0.1:#{port}/p?x=1", {}, nil)
      C29.ck('answer', got, [200, 'hi']) && C29.ck('request line', seen[0][:head].lines.first, "GET /p?x=1 HTTP/1.1\r\n")
    end
  end
end
