# frozen_string_literal: true

# Replays the TS-reference oracles of the data-flow model, the trace rules and the detector adapters
# (test-data/ref-dataflow-py.json.gz and ref-dataflow-rs.json.gz). Tagged values are rebuilt from the JSON specs the generator
# describes; Ed25519 receipts are deterministic and compared byte for byte.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/dataflow'
require 'minitest/autorun'

class TestRefDataflow < Minitest::Test
  D = AtlasPca::Dataflow
  BY_FN = Ref.load('dataflow-py')
  RS_FN = Ref.load('dataflow-rs')

  OPS = { 'concat' => ->(*a) { a.join('|') }, 'first' => ->(a) { a }, 'count' => ->(*a) { a.length } }.freeze

  def self.ro(s) = s['readers']
  def self.set(a) = a.is_a?(Array) ? Set.new(a) : a

  def self.build(s)
    case s['k']
    when 'trusted' then D.from_trusted_query(s['value'], ro(s))
    when 'tool' then D.from_tool_output(s['name'], s['value'], ro(s))
    when 'source' then D.from_source(s['source'], s['value'], s.fetch('trusted', false), ro(s))
    when 'tag'
      c = s['cap']
      return D.tag(s['value'], c) unless c.is_a?(Hash)

      D.tag(s['value'], D::Capability.new(set(c['sources']), c['isTrusted'], c.key?('readers') ? set(c['readers']) : nil))
    when 'derive' then D.derive(s['inputs'].map { |x| build(x) }, OPS[s['op']])
    when 'raw' then s['value']
    when 'fake' then { 'value' => s['value'], 'cap' => {} }
    else raise "unknown spec #{s['k']}"
    end
  end

  def self.cap_json(c)
    out = { 'sources' => D.sorted(c.sources), 'isTrusted' => c.is_trusted }
    out['readers'] = D.sorted(c.readers) unless c.readers.nil?
    out
  end

  def self.out_t(t) = D.is_tagged?(t) ? { 'tagged' => true, 'value' => t.value }.merge(cap_json(t.cap)) : { 'tagged' => false }

  # the corpus writes sink members in snake_case; the port takes the reference's camelCase
  def self.sink_of(s)
    return s unless s.is_a?(Hash)

    a = s['accepts']
    return { 'id' => s['id'], 'accepts' => a } unless a.is_a?(Hash)

    { 'id' => s['id'], 'accepts' => { 'external' => a['external'], 'requireTrusted' => a['require_trusted'],
                                      'allowedSources' => set(a['allowed_sources']), 'deniedSources' => set(a['denied_sources']) } }
  end

  def self.governor(g)
    lambda do |act|
      raise 'no sink' if g['kind'] == 'throw'

      sink_of(g['kind'] == 'byVerb' ? g['map'].fetch(act['verb'], g['default']) : g['sink'])
    end
  end

  def self.mk(args) = args.is_a?(Array) ? args.map { |s| s.nil? ? nil : build(s) } : args

  def self.dual(q, op)
    qs = { 'tool' => ->(p) { D.from_tool_output('q', "r:#{p}") }, 'trusted' => ->(p) { D.from_trusted_query(p) }, 'raw' => ->(p) { p },
           'fake' => ->(p) { { 'value' => p, 'cap' => {} } } }
    r = D.dual_context(build(q), ->(x) { 'plan:' + x }, qs[op])
    { 'plan' => r['plan'], 'result' => out_t(r['result']) }
  end

  def self.ctx(c)
    out = { 'detector' => c['detector'], 'version' => c['version'], 'content' => c['content'], 'secret_key' => key(c['seed']), 'now' => c['now'] }
    %w[session calibration_ref].each { |k| out[k] = c[k] if c.key?(k) }
    out
  end

  def self.key(n) = AtlasPca::KeyPair.new([n].pack('C') * 32)

  def self.caps(*specs) = specs.map { |s| build(s).cap }

  def self.t(v) = { 'k' => 'trusted', 'value' => v }
  def self.l(name, v) = { 'k' => 'tool', 'name' => name, 'value' => v }

  MAP = {
    'build' => ->(x) { out_t(build(x)) },
    'toolProvenance' => ->(n) { D.tool_provenance(n) },
    'classifyFlow' => ->(a, b) { D.classify_flow(build(a), sink_of(b)) },
    'canFlow' => ->(a, b) { D.can_flow(build(a), sink_of(b)) },
    'externalSendSink' => ->(i) { D.external_send_sink(i) },
    'sensitiveSink' => ->(i) { D.sensitive_sink(i) },
    'checkAction' => ->(ac, ar, gv, ex = nil) { D.check_action(ac, mk(ar), governor(gv), ex) },
    'dualContext' => ->(q, op) { dual(q, op) },
    'lakeraReceipt' => ->(resp, c) { D.lakera_receipt(resp, ctx(c)) },
    'promptSecurityReceipt' => ->(resp, c) { D.prompt_security_receipt(resp, ctx(c)) },
    'genericReceipt' => ->(resp, c) { D.generic_receipt(resp, ctx(c)) },
    'detectorInputDigest' => ->(c) { D.detector_input_digest(c) },
    'signDetectorReceipt' => ->(b, s) { D.sign_detector_receipt(b, key(s)) },
    'detectorReceiptShapeError' => ->(r) { D.detector_receipt_shape_error(r) },
    'detectorReceiptRef' => ->(r) { D.detector_receipt_ref(r) }
  }.freeze
  # replayed by the dedicated tests below (the generator names each case by what it builds)
  SPECIAL = %w[levelOf combineCaps unionSources].freeze

  def test_every_function_is_covered
    assert_equal((MAP.keys + SPECIAL).sort, BY_FN.keys.sort)
  end

  MAP.each_key { |fn| define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], MAP[fn]) } }

  def label(c) = c['name'].split('/', 2)[1].split('#')[0]

  def test_level_of_cases
    BY_FN['levelOf'].each do |c|
      got = case label(c)
            when 'null' then D.level_of(nil)
            when 'string' then D.level_of('trusted')
            when 'mixed tool+user' then D.level_of(D.derive([D.from_tool_output('a', 1), D.from_source('user', 2)], ->(a, b) { a + b }))
            when 'empty derive' then D.level_of(D.derive([], -> { 1 }))
            else D.level_of(self.class.build(c['args'][0]))
            end
      assert_equal c['out'], got, c['name']
    end
  end

  def test_combine_and_union_cases
    by = BY_FN['combineCaps'].to_h { |c| [label(c), c] }
    cj = ->(cap) { self.class.cap_json(cap) }
    assert_equal by['empty']['out'], cj.call(D.combine_caps([]))
    three = D.combine_caps(self.class.caps(self.class.t('a'), self.class.t('b').merge('readers' => %w[x y]), self.class.t('c').merge('readers' => ['y'])))
    assert_equal by['three']['out'], cj.call(three)
    mixed = self.class.caps(self.class.t('a'), self.class.l('w', 'b'))
    assert_equal by['untrusted']['out'], cj.call(D.combine_caps(mixed))
    assert_equal BY_FN['unionSources'][0]['out'], D.sorted(D.union_sources(mixed))
  end

  # ---- trace rules ----------------------------------------------------------------------------------------------------

  RS_MAP = {
    'parseTraceRule' => ->(id, text, reason = nil) { D.parse_trace_rule(id, text, reason) },
    'parseInvariantRule' => ->(id, text, opts = nil) { D.parse_invariant_rule(id, text, Ref.snake(opts)) },
    'compileTexts' => ->(rules, table) { D.compile_trace_rules(rules.map { |i, t| D.parse_trace_rule(i, t) }, table) },
    'compileTraceRules' => ->(rules, table) { D.compile_trace_rules(rules, table) },
    'lethalTrifecta' => ->(table, edges, opts = nil) { D.lethal_trifecta(table, edges, opts) },
    'categoryId' => ->(s) { D.category_id(s) }
  }.freeze

  def test_trace_every_function_is_covered
    assert_equal RS_MAP.keys.sort, RS_FN.keys.sort
  end

  RS_MAP.each_key { |fn| define_method("test_trace_#{fn}") { Ref.run(self, RS_FN[fn], RS_MAP[fn]) } }

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 783, BY_FN.values.sum(&:length), 'dataflow-py'
    assert_equal 142, RS_FN.values.sum(&:length), 'dataflow-rs'
  end

end
