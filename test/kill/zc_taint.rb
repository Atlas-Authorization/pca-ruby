# frozen_string_literal: true

# zc taint: exact results of the taint lattice, classification, compute_taint, the gate and the in-memory registry.
module MutationKill
  module ZCTaint
    module_function

    def tn = AtlasPca::Taint
    def agent = { 'kind' => 'agent' }

    def invalid(reason) = { 'taint' => 1, 'label' => { 'kind' => 'agent' }, 'refs' => [], 'valid' => false, 'reason' => reason }

    def seam(mod, name, impl)
      orig = mod.method(name)
      mod.define_singleton_method(name, &impl)
      yield
    ensure
      mod.define_singleton_method(name, orig)
    end

    # a registry that answers every lookup with `answer`
    def fixed_registry(answer) = Class.new { define_method(:lookup) { |_d| answer } }.new
  end

  t('zc taint: level? and label_rank are exact and refuse every non-String kind') do
    next true unless ZC.gate?('taint.rb')

    tn = ZCTaint.tn
    fake = Class.new do
      def hash = 'web'.hash
      def eql?(other) = other == 'web'
    end.new
    ZC.eq('web', tn.level?('web'), true) && ZC.eq('agent', tn.level?('agent'), true) && ZC.eq('nil', tn.level?(nil), false) &&
      ZC.eq('int', tn.level?(5), false) && ZC.eq('bogus', tn.level?('bogus'), false) && ZC.eq('symbol', tn.level?(:web), false) &&
      ZC.eq('a String lookalike', tn.level?(fake), false) &&
      ZC.eq('lookalike rank', tn.label_rank({ 'kind' => fake }), 4) &&
      ZC.eq('ranks', %w[trusted first_party tool web agent].map { |k| tn.label_rank({ 'kind' => k }) }, [0, 1, 2, 3, 4]) &&
      ZC.eq('nil label', tn.label_rank(nil), 4) && ZC.eq('string label', tn.label_rank('web'), 4) && ZC.eq('int label', tn.label_rank(5), 4) &&
      ZC.eq('array label', tn.label_rank([]), 4) && ZC.eq('empty label', tn.label_rank({}), 4) &&
      ZC.eq('symbol keys are not read', tn.label_rank({ kind: 'trusted' }), 4) && ZC.eq('int kind', tn.label_rank({ 'kind' => 3 }), 4)
  end

  t('zc taint: join_label returns the higher-ranked label itself, ids only survive when both agree') do
    next true unless ZC.gate?('taint.rb')

    tn = ZCTaint.tn
    web_x = { 'kind' => 'web', 'id' => 'x' }
    tool_y = { 'kind' => 'tool', 'id' => 'y' }
    tool_x = { 'kind' => 'tool', 'id' => 'x' }
    ZC.same('higher first', tn.join_label(web_x, tool_y), web_x) && ZC.same('higher second', tn.join_label(tool_y, web_x), web_x) &&
      ZC.same('equal rank and id', tn.join_label(tool_x, { 'kind' => 'tool', 'id' => 'x' }), tool_x) &&
      ZC.eq('equal rank, different id', tn.join_label(tool_x, tool_y), { 'kind' => 'tool' }) &&
      ZC.eq('empty', tn.join_labels([]), { 'kind' => 'agent' }) &&
      ZC.same('one', tn.join_labels([web_x]), web_x)
  end

  t('zc taint: classify_ref re-classifies from server facts only') do
    next true unless ZC.gate?('taint.rb')

    tn = ZCTaint.tn
    reg = tn::InMemoryRegistry.new.record_trusted('t')
    node = Class.new { def node(id) = id == 'n1' ? { 'id' => id } : nil }.new
    boom = Class.new { def node(_id) = raise('boom') }.new
    falsy = Class.new { def node(_id) = false }.new
    ZC.eq('int', tn.classify_ref(5, reg, nil), { 'kind' => 'agent' }) && ZC.eq('nil', tn.classify_ref(nil, reg, nil), { 'kind' => 'agent' }) &&
      ZC.eq('empty', tn.classify_ref('', reg, nil), { 'kind' => 'agent' }) &&
      ZC.eq('registry', tn.classify_ref('t', reg, nil), { 'kind' => 'trusted' }) &&
      ZC.eq('graph', tn.classify_ref('n1', reg, node), { 'kind' => 'first_party' }) &&
      ZC.eq('graph miss', tn.classify_ref('n2', reg, node), { 'kind' => 'agent', 'id' => 'n2' }) &&
      ZC.eq('graph false', tn.classify_ref('n2', reg, falsy), { 'kind' => 'agent', 'id' => 'n2' }) &&
      ZC.eq('graph raises', tn.classify_ref('n1', reg, boom), { 'kind' => 'agent', 'id' => 'n1' }) &&
      ZC.eq('no graph', tn.classify_ref('zz', reg, nil), { 'kind' => 'agent', 'id' => 'zz' }) &&
      ZC.eq('127', tn.classify_ref('x' * 127, reg, nil), { 'kind' => 'agent', 'id' => 'x' * 127 }) &&
      ZC.eq('128', tn.classify_ref('x' * 128, reg, nil), { 'kind' => 'agent', 'id' => 'x' * 128 }) &&
      ZC.eq('129', tn.classify_ref('x' * 129, reg, nil), { 'kind' => 'agent' }) &&
      ZC.eq('an array answer is not a label', tn.classify_ref('zz', ZCTaint.fixed_registry([1]), nil), { 'kind' => 'agent', 'id' => 'zz' }) &&
      ZC.eq('an unknown kind is not a label', tn.classify_ref('zz', ZCTaint.fixed_registry({ 'kind' => 'bogus' }), nil), { 'kind' => 'agent', 'id' => 'zz' }) &&
      ZC.eq('a known kind is taken', tn.classify_ref('zz', ZCTaint.fixed_registry({ 'kind' => 'web' }), nil), { 'kind' => 'web' })
  end

  t('zc taint: compute_taint pre-checks, order and error message') do
    next true unless ZC.gate?('taint.rb')

    tn = ZCTaint.tn
    reg = tn::InMemoryRegistry.new.record_trusted('t')
    no_reg = 'taint: no trusted-input registry'
    malformed = 'taint: provenance is absent or malformed'
    loud = Class.new { define_method(:lookup) { |_d| raise ZC::LoudError, 'quiet' } }.new
    ZC.eq('no lookup, refs', tn.compute_taint({ 'trusted_refs' => ['a'] }, Object.new), ZCTaint.invalid(no_reg)) &&
      ZC.eq('no lookup, no refs', tn.compute_taint({}, Object.new), ZCTaint.invalid(no_reg)) &&
      ZC.eq('no registry, bad refs', tn.compute_taint({ 'trusted_refs' => 'x' }, nil), ZCTaint.invalid(no_reg)) &&
      ZC.eq('no registry, no provenance', tn.compute_taint(nil, nil), ZCTaint.invalid(no_reg)) &&
      ZC.eq('string provenance', tn.compute_taint('x', reg), ZCTaint.invalid(malformed)) &&
      ZC.eq('array provenance', tn.compute_taint([], reg), ZCTaint.invalid(malformed)) &&
      ZC.eq('int provenance', tn.compute_taint(5, reg), ZCTaint.invalid(malformed)) &&
      ZC.eq('nil provenance', tn.compute_taint(nil, reg), ZCTaint.invalid(malformed)) &&
      ZC.eq('refs not an array', tn.compute_taint({ 'trusted_refs' => 'x' }, reg), ZCTaint.invalid('taint: trusted_refs must be an array')) &&
      ZC.eq('refs not strings', tn.compute_taint({ 'trusted_refs' => ['a', 5] }, reg), ZCTaint.invalid('taint: trusted_refs must be non-empty strings')) &&
      ZC.eq('empty ref', tn.compute_taint({ 'trusted_refs' => [''] }, reg), ZCTaint.invalid('taint: trusted_refs must be non-empty strings')) &&
      ZC.eq('a raising registry reports #message', tn.compute_taint({ 'trusted_refs' => ['a'] }, loud),
            ZCTaint.invalid('taint: evaluation error (fail closed): loud-message')) &&
      ZC.eq('a mixed lineage is as bad as its worst ref', tn.compute_taint({ 'trusted_refs' => %w[t zz] }, reg),
            { 'taint' => 1.0, 'label' => { 'kind' => 'agent', 'id' => 'zz' }, 'valid' => true,
              'refs' => [{ 'ref' => 't', 'label' => { 'kind' => 'trusted' } }, { 'ref' => 'zz', 'label' => { 'kind' => 'agent', 'id' => 'zz' } }] }) &&
      ZC.eq('graph defaults to none', tn.compute_taint({ 'trusted_refs' => ['t'] }, reg),
            { 'taint' => 0.0, 'label' => { 'kind' => 'trusted' }, 'valid' => true, 'refs' => [{ 'ref' => 't', 'label' => { 'kind' => 'trusted' } }] })
  end

  t('zc taint: taint_gate verdicts, misconfiguration, fallback reason and fail-closed error') do
    next true unless ZC.gate?('taint.rb')

    tn = ZCTaint.tn
    reg = tn::InMemoryRegistry.new.record_trusted('t').record_web('w')
    prov = ->(*refs) { { 'trusted_refs' => refs } }
    misconf = { 'ok' => false, 'reason' => 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)' }
    fallback = ZCTaint.seam(tn, :compute_taint, ->(*_a) { { 'valid' => false } }) do
      ZC.eq('fallback reason', tn.taint_gate(nil, nil, nil, 1), { 'ok' => false, 'reason' => 'provenance lineage is not server-verifiable (fail closed)' })
    end
    errored = ZCTaint.seam(tn, :compute_taint, ->(*_a) { raise ZC::LoudError, 'quiet' }) do
      ZC.eq('error', tn.taint_gate(nil, nil, nil, 1), { 'ok' => false, 'reason' => 'taint gate error (fail closed): loud-message' })
    end
    ZC.eq('trusted at 0', tn.taint_gate(prov.call('t'), reg, nil, 0), { 'ok' => true }) &&
      ZC.eq('web at its own level', tn.taint_gate(prov.call('w'), reg, nil, 0.75), { 'ok' => true }) &&
      ZC.eq('web above the bound', tn.taint_gate(prov.call('w'), reg, nil, 0.5), { 'ok' => false, 'reason' => 'information-flow taint 0.75 exceeds policy max 0.5' }) &&
      ZC.eq('agent, JS number printing', tn.taint_gate(prov.call('zz'), reg, nil, 0.0), { 'ok' => false, 'reason' => 'information-flow taint 1 exceeds policy max 0' }) &&
      ZC.eq('agent at 1', tn.taint_gate(prov.call('zz'), reg, nil, 1), { 'ok' => true }) &&
      ZC.eq('invalid provenance', tn.taint_gate(nil, reg, nil, 1), { 'ok' => false, 'reason' => 'taint: provenance is absent or malformed' }) &&
      [nil, 'x', true, Float::NAN, Float::INFINITY, -Float::INFINITY, -1, -0.5].all? { |m| ZC.eq("max #{m.inspect}", tn.taint_gate(prov.call('t'), reg, nil, m), misconf) } &&
      fallback && errored
  end

  t('zc taint: the in-memory registry stores only server-vouched labels under string keys') do
    next true unless ZC.gate?('taint.rb')

    tn = ZCTaint.tn
    reg = tn::InMemoryRegistry.new
    ZC.eq('empty', reg.size, 0) && ZC.eq('missing', reg.lookup('nope'), nil) &&
      [[5, { 'kind' => 'web' }], [nil, { 'kind' => 'web' }], ['', { 'kind' => 'web' }], [:sym, { 'kind' => 'web' }], ['d', nil], ['d', 'web'], ['d', []],
       ['d', {}], ['d', { 'kind' => 'bogus' }], ['d', { 'kind' => 5 }], ['d', { kind: 'bogus' }]].all? { |dg, lb|
        ZC.same("refused #{dg.inspect} #{lb.inspect}", reg.record(dg, lb), reg) && ZC.eq("size after #{dg.inspect}", reg.size, 0)
      } &&
      ZC.same('record returns the registry', reg.record('d', { kind: 'tool', id: 'x' }), reg) &&
      ZC.eq('size', reg.size, 1) && ZC.eq('string keys', reg.lookup('d'), { 'kind' => 'tool', 'id' => 'x' }) &&
      begin
        l1 = reg.lookup('d')
        l1['kind'] = 'agent'
        ZC.eq('lookup hands out a copy', reg.lookup('d'), { 'kind' => 'tool', 'id' => 'x' }) && (!reg.lookup('d').equal?(reg.lookup('d')) || raise('shared object'))
      end &&
      ZC.eq('re-record keeps the size', reg.record('d', { 'kind' => 'web' }).size, 1) && ZC.eq('replaced', reg.lookup('d'), { 'kind' => 'web' }) &&
      ZC.eq('helpers', [reg.record_trusted('a').lookup('a'), reg.record_first_party('b').lookup('b'), reg.record_tool('c', 'ocr').lookup('c'), reg.record_web('e').lookup('e')],
            [{ 'kind' => 'trusted' }, { 'kind' => 'first_party' }, { 'kind' => 'tool', 'id' => 'ocr' }, { 'kind' => 'web' }]) &&
      ZC.eq('size after helpers', reg.size, 5)
  end
end
