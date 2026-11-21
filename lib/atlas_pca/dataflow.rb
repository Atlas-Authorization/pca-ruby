# frozen_string_literal: true

require 'set'
require_relative 'intent_wb'
require_relative 'caveat_lang'
require_relative 'decision'

# The capability-tagged, positive data-flow model (CaMeL style), the trace rules that lower "never B after A" guardrails to
# derive caveats, the lethal-trifecta lint, and the vendor detector adapters that turn guardrail responses into signed,
# tighten-only receipts. Port of the TypeScript reference (@atlasauth/pca-dataflow and the core model it re-exports).
#
# Differences that come from the language: a Tagged value can only be made by this module (its constructor is private), so
# is_tagged? is true only for values it minted; capability sets are frozen Sets; sinks are String-keyed Hashes with the
# reference's member names {"id" => String, "accepts" => {"external", "requireTrusted", "allowedSources", "deniedSources"}}
# (the two source members a Set or Array); the sink resolver of check_action is an object with #sink_for(action) or a
# callable; Ruby has no sparse-array holes, so a nil entry in the tagged-argument list is the "an argument was not tagged"
# refusal.
module AtlasPca
  module Dataflow
    module_function

    # ---- provenance + tagged values ---------------------------------------------------------------------------------------

    TRUSTED_QUERY = 'trusted-query'

    def tool_provenance(name) = "tool:#{name}"

    # JS Array.prototype.sort() on strings orders by UTF-16 code unit
    def sorted(xs) = xs.to_a.sort_by { |x| AtlasPca.utf16_key(x.to_s) }

    # sources (lineage), is_trusted (true only if every source is trusted), readers (optional allow-list of sink ids, or nil)
    class Capability
      attr_reader :sources, :is_trusted, :readers

      def initialize(sources, is_trusted, readers = nil)
        @sources = sources
        @is_trusted = is_trusted
        @readers = readers
        freeze
      end
    end

    # A value carrying its capability. Only this module can construct one (is_tagged? is false for a look-alike).
    class Tagged
      attr_reader :value, :cap

      private_class_method :new

      def initialize(value, cap)
        @value = value
        @cap = cap
        freeze
      end
    end

    def mint(value, cap) = Tagged.send(:new, value, cap)

    def is_tagged?(x) = x.is_a?(Tagged) # rubocop:disable Naming/PredicateName

    def freeze_cap(sources, is_trusted, readers)
      Capability.new(Set.new(sources).freeze, is_trusted, readers.nil? ? nil : Set.new(readers).freeze)
    end

    # Tag a raw value with an explicit capability (escape hatch; prefer the boundary constructors).
    def tag(value, cap)
      unless cap.is_a?(Capability) && cap.sources.is_a?(Set) && [true, false].include?(cap.is_trusted)
        raise TypeError, 'tag: a capability needs a set of sources and a boolean isTrusted'
      end
      raise TypeError, 'tag: readers must be a Set when given' unless cap.readers.nil? || cap.readers.is_a?(Set)

      if cap.is_trusted
        raise TypeError, 'tag: a trusted capability needs at least one source' if cap.sources.empty?

        cap.sources.each { |src| raise TypeError, 'tag: tool output can never be trusted' if src.is_a?(String) && src.start_with?('tool:') }
      end
      mint(value, freeze_cap(cap.sources, cap.is_trusted, cap.readers))
    end

    def from_trusted_query(value, readers = nil) = tag(value, Capability.new(Set[TRUSTED_QUERY], true, readers.nil? ? nil : Set.new(readers)))

    def from_tool_output(name, value, readers = nil)
      tag(value, Capability.new(Set[tool_provenance(name)], false, readers.nil? ? nil : Set.new(readers)))
    end

    # Untrusted unless the caller vouches (is_trusted is true) at the boundary.
    def from_source(source, value, is_trusted = false, readers = nil)
      tag(value, Capability.new(Set[source], is_trusted == true, readers.nil? ? nil : Set.new(readers)))
    end

    def union_sources(caps) = caps.each_with_object(Set.new) { |c, out| out.merge(c.sources) }.freeze

    # sources = union, is_trusted = AND over a non-empty list, readers = intersection of the inputs that restrict readers.
    def combine_caps(caps)
      caps = caps.to_a
      trusted = !caps.empty? && caps.all?(&:is_trusted)
      readers = nil
      caps.each do |c|
        next if c.readers.nil?

        readers = readers.nil? ? Set.new(c.readers) : readers.select { |r| c.readers.include?(r) }.to_set
      end
      freeze_cap(union_sources(caps), trusted, readers)
    end

    # A new tagged value whose capability is combine_caps over the inputs: trust can only be lost.
    def derive(inputs, combine)
      raise TypeError, 'derive: every input must be a tagged value made by this module' unless inputs.is_a?(Array) && inputs.all? { |t| is_tagged?(t) }

      value = combine.call(*inputs.map(&:value))
      mint(value, combine_caps(inputs.map(&:cap)))
    end

    # ---- sinks + the policy interpreter -----------------------------------------------------------------------------------

    def sorted_sources(cap) = sorted(cap.sources)

    def valid_sink?(sink) = sink.is_a?(Hash) && sink['id'].is_a?(String) && !sink['id'].empty?

    # One value -> sink flow: {outcome: allow|step_up|deny, reason?, path?}. Order: value readers, denied sources, allow-list,
    # external sink, sensitive sink.
    def classify_flow(value, sink)
      unless is_tagged?(value)
        return { 'outcome' => 'deny', 'reason' => 'value carries no provenance tag made by this module (fail closed)', 'path' => [] }
      end
      unless valid_sink?(sink) && sink['accepts'].is_a?(Hash)
        return { 'outcome' => 'deny', 'reason' => 'the sink is not a valid sink (fail closed)', 'path' => sorted_sources(value.cap) }
      end

      cap = value.cap
      p = sink['accepts']
      sid = sink['id']
      if !cap.readers.nil? && !cap.readers.include?(sid)
        listed = sorted(cap.readers).join(', ')
        return { 'outcome' => 'deny', 'reason' => "value's readers capability [#{listed.empty? ? '∅' : listed}] does not include sink '#{sid}'",
                 'path' => sorted_sources(cap) }
      end
      denied = p['deniedSources']
      unless denied.nil?
        bad = sorted_sources(cap).select { |s| denied.include?(s) }
        return { 'outcome' => 'deny', 'reason' => "provenance [#{bad.join(', ')}] is forbidden at sink '#{sid}'", 'path' => bad } unless bad.empty?
      end
      allowed = p['allowedSources']
      unless allowed.nil?
        bad = sorted_sources(cap).reject { |s| allowed.include?(s) }
        unless bad.empty?
          return { 'outcome' => 'deny', 'reason' => "provenance [#{bad.join(', ')}] is not in the allow-list of sink '#{sid}'", 'path' => bad }
        end
      end
      if p['external'] == true && !cap.is_trusted
        return { 'outcome' => 'deny',
                 'reason' => "untrusted value (provenance [#{sorted_sources(cap).join(', ')}]) may not flow to external-send sink '#{sid}' " \
                             '— exfiltration / prompt-injection path',
                 'path' => sorted_sources(cap) }
      end
      if p['requireTrusted'] == true && !cap.is_trusted
        return { 'outcome' => 'step_up',
                 'reason' => "sink '#{sid}' requires trusted provenance; value provenance [#{sorted_sources(cap).join(', ')}] is untrusted " \
                             '— needs human review',
                 'path' => sorted_sources(cap) }
      end
      { 'outcome' => 'allow' }
    end

    # ok is true only for a clean allow (a step_up is not ok without a human).
    def can_flow(value, sink)
      d = classify_flow(value, sink)
      out = { 'ok' => d['outcome'] == 'allow' }
      out['reason'] = d['reason'] if d.key?('reason')
      out
    end

    SEVERITY = { 'allow' => 0, 'step_up' => 1, 'deny' => 2 }.freeze

    # a JS number as text (an integral Float prints without the fraction)
    def num_text(n) = n.is_a?(Float) && n.finite? && n == n.floor ? n.to_i.to_s : n.to_s

    # Gate an action by data flow: every tagged argument is checked against the sink it dispatches to; the worst outcome wins.
    # `policy` answers #sink_for(action) or is a callable; `expected_args` (optional) is the argument count the action has.
    def check_action(action, tagged_args, policy, expected_args = nil)
      sink = begin
        policy.respond_to?(:sink_for) ? policy.sink_for(action) : policy.call(action)
      rescue StandardError # the resolver is caller code: any failure refuses
        return { 'outcome' => 'deny', 'sink' => '(unresolved)', 'reason' => 'the sink for this action could not be resolved (fail closed)' }
      end
      unless valid_sink?(sink)
        return { 'outcome' => 'deny', 'sink' => '(unresolved)', 'reason' => 'the sink for this action is not a valid sink (fail closed)' }
      end

      sid = sink['id']
      unless tagged_args.is_a?(Array)
        return { 'outcome' => 'deny', 'sink' => sid, 'reason' => 'the tagged arguments are not a list (fail closed)' }
      end
      if !expected_args.nil? && tagged_args.length != expected_args
        return { 'outcome' => 'deny', 'sink' => sid,
                 'reason' => "expected #{num_text(expected_args)} tagged argument(s), got #{tagged_args.length} (fail closed)" }
      end

      worst = { 'outcome' => 'allow', 'sink' => sid }
      tagged_args.each_with_index do |arg, i|
        if arg.nil?
          worst = { 'outcome' => 'deny', 'sink' => sid, 'arg' => i, 'reason' => 'an argument was not tagged (fail closed)' }
          break
        end
        d = classify_flow(arg, sink)
        next unless SEVERITY[d['outcome']] > SEVERITY[worst['outcome']]

        worst = { 'outcome' => d['outcome'], 'sink' => sid, 'arg' => i }
        worst['reason'] = d['reason'] if d.key?('reason')
        worst['path'] = d['path'] if d.key?('path')
      end
      worst
    end

    # Privileged planner sees only the TRUSTED query value; the quarantined handler returns a tagged result.
    def dual_context(query, plan, quarantine)
      raise TypeError, 'dualContext: the query must be a tagged value made by this module' unless is_tagged?(query)
      unless query.cap.is_trusted
        raise ArgumentError, "dualContext: the privileged planner may only run on a TRUSTED query; got provenance [#{sorted_sources(query.cap).join(', ')}]"
      end

      p = plan.call(query.value)
      result = quarantine.call(p)
      raise TypeError, 'dualContext: the quarantined handler must return a tagged value made by this module' unless is_tagged?(result)

      { 'plan' => p, 'result' => result }
    end

    def external_send_sink(id) = { 'id' => id, 'accepts' => { 'external' => true } }
    def sensitive_sink(id) = { 'id' => id, 'accepts' => { 'requireTrusted' => true } }

    # The label in the provenance lattice of the default gate: trusted, tool (every source a tool output) or agent.
    def level_of(value)
      return 'agent' unless is_tagged?(value)

      cap = value.cap
      return 'trusted' if cap.is_trusted

      srcs = cap.sources.to_a
      !srcs.empty? && srcs.all? { |s| s.is_a?(String) && s.start_with?('tool:') } ? 'tool' : 'agent'
    end

    # ---- trace rules ------------------------------------------------------------------------------------------------------

    class TraceRuleError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    MAX_TRACE_CAVEATS = 64
    B_CHUNK = 8 # 7 + 3k expression nodes <= DERIVE_MAX_NODES (32)
    RULE_ID_RE = /\A[a-z][a-z0-9_]{0,39}\z/
    VERB_RE = %r{\A[A-Za-z0-9_.:/-]{1,256}\z}
    # JS \s / String.trim() whitespace, `.` (no line terminators) and \S, which differ from Ruby's
    WS = "\t\n\u000b\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
    S = "[#{WS}]"
    NS = "[^#{WS}]"
    DOT = "[^\n\r\u2028\u2029]"
    RULE_RE = Regexp.new("\\A#{S}*never#{S}+(#{DOT}+?)#{S}+after#{S}+(#{DOT}+?)#{S}+within#{S}+(#{NS}+)#{S}*\\z")
    DUR_RE = /\A([1-9][0-9]{0,9})(ms|s|m|h|d)\z/
    HEAD_RE = Regexp.new("\\Araise#{S}+(?:\"([^\"]*)\"|'([^']*)')#{S}+if:\\z")
    EVENT = '(ToolCall|ToolOutput|Message)'
    FLOW_RE = Regexp.new("\\A\\(([A-Za-z0-9_]+):#{S}*#{EVENT}\\)#{S}*->#{S}*\\(([A-Za-z0-9_]+):#{S}*#{EVENT}\\)\\z")
    COND_RE = Regexp.new("\\A([A-Za-z0-9_]+)#{S}+is#{S}+tool:([A-Za-z0-9_.:/-]+)(\\(#{DOT}*\\))?\\z")
    TRIM_RE = Regexp.new("\\A#{S}+|#{S}+\\z")
    UNIT = { 'ms' => 1, 's' => 1000, 'm' => 60_000, 'h' => 3_600_000, 'd' => 86_400_000 }.freeze

    def fail!(code, msg) = raise(TraceRuleError.new(code, msg))

    # a lone surrogate (invalid UTF-8 here) is a non-space character to the reference: match on a scrubbed copy
    def scrubbed(s) = s.dup.force_encoding(Encoding::UTF_8).scrub("\uFFFD")

    def rx(re, s) = s.is_a?(String) ? re.match(scrubbed(s)) : nil

    def trim(s) = scrubbed(s).gsub(TRIM_RE, '')

    def duration(t)
      m = rx(DUR_RE, t)
      fail!('duration', "'#{t}' is not a duration like 10m, 2h or 7d") unless m
      ms = m[1].to_i * UNIT[m[2]]
      fail!('window', "a window of #{t} exceeds the 30-day history the verifier keeps") if ms > AtlasPca::DERIVE_MAX_WINDOW_MS
      ms
    end

    def selector(text, side)
      s = { 'tools' => [], 'traits' => [], 'resources' => [], 'any' => false }
      text.split(',', -1).each do |raw|
        a = trim(raw)
        if a == 'any'
          s['any'] = true
        elsif a.start_with?('tool:') && VERB_RE.match?(a[5..])
          s['tools'] << a[5..]
        elsif a.start_with?('trait:') && VERB_RE.match?(a[6..])
          s['traits'] << a[6..]
        elsif a.start_with?('resource:') && AtlasPca.utf16_len(a) > 9 && AtlasPca.utf16_len(a) <= 9 + 256
          fail!('resource_on_effect', 'a resource selector can only name the earlier action (the check reads the current verb)') if side == 'never'
          s['resources'] << a[9..]
        else
          fail!('selector', "'#{a}' is not tool:<verb>, trait:<id>, resource:<prefix> or any")
        end
      end
      s
    end

    def check_id(id)
      fail!('id', "rule id '#{id}' must match ^[a-z][a-z0-9_]{0,39}$") unless id.is_a?(String) && RULE_ID_RE.match?(id)
    end

    # Parse `never <B> after <A> within <duration>`. Raises TraceRuleError.
    def parse_trace_rule(id, text, reason = nil)
      check_id(id)
      m = rx(RULE_RE, text)
      fail!('syntax', "expected 'never <selector> after <selector> within <duration>', got '#{text}'") unless m
      rule = { 'id' => id, 'never' => selector(m[1], 'never'), 'after' => selector(m[2], 'after'), 'within_ms' => duration(m[3]) }
      rule['reason'] = reason unless reason.nil?
      rule
    end

    # Import the Invariant subset `raise "<msg>" if: (x: ToolCall|ToolOutput) -> (y: ToolCall)` plus `x is tool:<name>` lines.
    # opts (String keys): 'horizon' (required), 'drop_unsupported'. Returns {"rule", "dropped"}.
    def parse_invariant_rule(id, text, opts = nil)
      o = opts.is_a?(Hash) ? opts : {}
      check_id(id)
      fail!('horizon', 'an Invariant rule has no window: pass the horizon explicitly') unless o['horizon'].is_a?(String)
      within_ms = duration(o['horizon'])
      lines = text.split("\n", -1).map { |l| trim(l) }.reject { |l| l.empty? || l.start_with?('#') }
      head = rx(HEAD_RE, lines[0] || '')
      fail!('syntax', 'the first line must be raise "<message>" if:') unless head
      flow = rx(FLOW_RE, lines[1] || '')
      unless flow
        fail!('unsupported', "the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)")
      end
      a, ta, b, tb = flow[1], flow[2], flow[3], flow[4]
      fail!('unsupported', 'only a tool call or tool output followed by a tool call can be compiled') if ta == 'Message' || tb != 'ToolCall'
      fail!('syntax', 'the two events need distinct names') if a == b
      tools = { a => [], b => [] }
      dropped = []
      (lines[2..] || []).each do |l|
        m = rx(COND_RE, l)
        if m && tools.key?(m[1]) && m[3].nil?
          tools[m[1]] << m[2]
          next
        end
        if o['drop_unsupported'] == true
          # `x is tool:name({args})` keeps the tool and drops the argument pattern: a wider match, so more refusals
          tools[m[1]] << m[2] if m && tools.key?(m[1])
          dropped << l
          next
        end
        fail!('unsupported', "'#{l}' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead")
      end
      [a, b].each do |v|
        fail!('unsatisfiable', "'#{v}' is constrained to two different tools, so the rule can never fire") if tools[v].length > 1
      end
      sel = ->(v) { { 'tools' => tools[v], 'traits' => [], 'resources' => [], 'any' => tools[v].empty? } }
      reason = head[1] || head[2] || ''
      { 'rule' => { 'id' => id, 'never' => sel.call(b), 'after' => sel.call(a), 'within_ms' => within_ms, 'reason' => reason }, 'dropped' => dropped }
    end

    def expand(sel, table, what)
      verbs = sorted(table.keys)
      out = Set.new
      out.merge(verbs) if sel['any']
      sel['tools'].each do |t|
        fail!('unknown_tool', "#{what}: tool '#{t}' is not an action in the verb table") unless table.key?(t)
        out << t
      end
      sel['traits'].each do |tr|
        hit = verbs.select { |v| table[v]['traits'].include?(tr) }
        fail!('empty_selector', "#{what}: trait '#{tr}' matches no action") if hit.empty?
        out.merge(hit)
      end
      sorted(out)
    end

    # Lower rules to derive caveats over the verifier's history. Raises TraceRuleError on anything not expressible.
    def compile_trace_rules(rules, table)
      caveats = []
      edges = []
      ids = Set.new
      rules.each do |r|
        rid = r['id']
        fail!('id', "rule id '#{rid}' is malformed or repeated") if !rid.is_a?(String) || !RULE_ID_RE.match?(rid) || ids.include?(rid)
        ids << rid
        w = r['within_ms']
        fail!('window', "rule '#{rid}': within_ms must be 1..30 days") unless AtlasPca.wb_safe_int?(w) && w >= 1 && w <= AtlasPca::DERIVE_MAX_WINDOW_MS
        w = AtlasPca.wb_int(w)
        fail!('resource_on_effect', "rule '#{rid}': a resource selector cannot name the later action") unless r['never']['resources'].empty?
        bs = expand(r['never'], table, "rule '#{rid}' never")
        as = expand(r['after'], table, "rule '#{rid}' after").map { |v| { 'verb' => v } } +
             sorted(r['after']['resources'].uniq).map { |pfx| { 'resource_prefix' => pfx } }
        fail!('empty_selector', "rule '#{rid}': a side matches nothing") if bs.empty? || as.empty?
        n = 0
        as.each do |a|
          bs.each_slice(B_CHUNK) do |chunk|
            is_b = { 'op' => 'or', 'args' => chunk.map { |v| { 'op' => 'eq', 'a' => { 'ref' => 'verb' }, 'b' => { 'const' => v } } } }
            c = {
              'type' => 'derive',
              'id' => "trace.#{rid}.#{n}",
              'defs' => [{ 'name' => 'seen', 'kind' => 'count', 'window_ms' => w }.merge(a), { 'name' => 'verb', 'kind' => 'action', 'field' => 'verb' },
                         { 'name' => 'is_b', 'kind' => 'expr', 'expr' => is_b }],
              # refused iff an A happened within the window AND this action is a B; unknown (no history, no verb) refuses too
              'check' => { 'op' => 'not', 'arg' => { 'op' => 'and', 'args' => [{ 'op' => 'gt', 'a' => { 'ref' => 'seen' }, 'b' => { 'const' => 0 } },
                                                                                { 'ref' => 'is_b' }] } }
            }
            n += 1
            e = AtlasPca.derive_error(c)
            fail!('internal', "rule '#{rid}' compiled to an invalid caveat: #{e}") if e
            caveats << c
            fail!('too_large', "more than #{MAX_TRACE_CAVEATS} caveats: split the rule set or narrow the selectors") if caveats.length > MAX_TRACE_CAVEATS
          end
          bs.each do |v|
            frm = a.key?('verb') ? { 'tool' => a['verb'] } : { 'resource' => a['resource_prefix'] }
            edges << { 'rule' => rid, 'from' => frm, 'to' => v, 'within_ms' => w }
          end
        end
      end
      { 'caveats' => caveats, 'edges' => edges, 'digest' => AtlasPca.hash_canonical({ 'd' => 'atlas-pca/trace-rules/v1', 'caveats' => caveats }) }
    end

    # ---- lethal trifecta lint ---------------------------------------------------------------------------------------------

    PRIVATE_READ_TRAITS = %w[pca.pii_access pca.financial_data_read pca.credential_access pca.regulated_data].freeze
    EXTERNAL_SEND_TRAITS = %w[pca.external_communication pca.network_egress pca.data_export pca.public_exposure].freeze

    # Private data, untrusted content and a way out in one action set; a send is cut off when every untrusted read, or every
    # private read, has an edge rule to it. A lint: it reports, it does not enforce. opts (String keys): 'untrusted',
    # 'untrusted_traits'.
    def lethal_trifecta(table, edges, opts = nil)
      o = opts.is_a?(Hash) ? opts : {}
      verbs = sorted(table.keys)
      untrusted = o['untrusted'] || []
      untrusted_traits = o['untrusted_traits'] || []
      has = ->(v, ts) { table[v]['traits'].any? { |t| ts.include?(t) } }
      read_only = lambda do |v|
        eff = table[v]['effects'] || []
        !eff.empty? && eff.all? { |e| e == 'read' }
      end
      priv = verbs.select { |v| has.call(v, PRIVATE_READ_TRAITS) }
      untr = verbs.select { |v| untrusted.include?(v) || has.call(v, untrusted_traits) || (read_only.call(v) && table[v]['traits'].include?('pca.network_egress')) }
      sends = verbs.select { |v| has.call(v, EXTERNAL_SEND_TRAITS) && !read_only.call(v) }
      findings = []
      if !priv.empty? && !untr.empty? && !sends.empty?
        ruled = ->(frm, to) { edges.any? { |e| e['from'].key?('tool') && e['from']['tool'] == frm && e['to'] == to } }
        sends.each do |s|
          fu = untr.reject { |u| ruled.call(u, s) }
          fp = priv.reject { |p| ruled.call(p, s) }
          findings << { 'send' => s, 'from_untrusted' => fu, 'from_private' => fp } if !fu.empty? && !fp.empty?
        end
      end
      { 'private_reads' => priv, 'untrusted_reads' => untr, 'sends' => sends, 'findings' => findings }
    end

    # ---- detector receipts + adapters -------------------------------------------------------------------------------------

    DETECTOR_RECEIPT_DOMAIN = "atlas-pca/detector-receipt/v1\x00"
    DETECTOR_RECEIPT_REF_DOMAIN = 'atlas-pca/detector-receipt-ref/v1'
    DETECTOR_VERDICTS = %w[suspicious no_finding].freeze
    MAX_DETECTOR_RECEIPTS = AtlasPca::MAX_DETECTOR_RECEIPTS
    ID_RE = /\A[a-z][a-z0-9_]{0,63}\z/

    # b64u(sha256(strictCanonical({d, content}))): the digest a receipt binds.
    def detector_input_digest(content) = AtlasPca.hash_canonical({ 'd' => 'atlas-pca/detector-input/v1', 'content' => content })

    def detector_receipt_ref(r) = AtlasPca.hash_canonical({ 'd' => DETECTOR_RECEIPT_REF_DOMAIN, 'receipt' => r })

    # nil when well-formed
    def detector_receipt_shape_error(r)
      return 'receipt must be an object' unless r.is_a?(Hash)

      e = AtlasPca.wb_closed_members(r, %w[v kind detector version input_digest verdict categories iat sig],
                                     %w[session calibration_ref alg pq_pk pq_sig], 'receipt')
      return e if e
      return 'not a pca-detector-receipt v1' unless r['v'].is_a?(Numeric) && r['v'] == 1 && r['kind'] == 'pca-detector-receipt'
      return 'detector id is malformed' unless AtlasPca.wb_re?(ID_RE, r['detector'])
      return 'version must be 1..64 bytes' unless AtlasPca.wb_bounded?(r['version'], 64)
      return 'input_digest must be a b64u 32-byte digest' unless AtlasPca.wb_digest?(r['input_digest'])
      return "verdict must be 'suspicious' or 'no_finding'" unless r['verdict'].is_a?(String) && DETECTOR_VERDICTS.include?(r['verdict'])

      c = r['categories']
      return 'categories must be 0..8 ids' unless c.is_a?(Array) && c.length <= 8 && c.all? { |x| AtlasPca.wb_re?(ID_RE, x) }
      return 'categories must be sorted and distinct' unless (1...c.length).all? { |i| c[i - 1] < c[i] }
      return 'a no_finding receipt carries no categories' if r['verdict'] == 'no_finding' && !c.empty?
      return 'iat must be a non-negative integer' unless AtlasPca.wb_safe_int?(r['iat']) && r['iat'] >= 0
      return 'session must be a b64u 32-byte id' if r.key?('session') && !AtlasPca.wb_digest?(r['session'])
      return 'calibration_ref must be 1..256 bytes' if r.key?('calibration_ref') && !AtlasPca.wb_bounded?(r['calibration_ref'], 256)
      return 'sig must be a string' unless r['sig'].is_a?(String)

      AtlasPca.wb_artifact_suite_error(r)
    end

    # Sign a receipt with the detector gateway's key (a KeyPair or a 32-byte Ed25519 seed). Raises on a malformed body.
    def sign_detector_receipt(body, key, alg: nil, pq: nil)
      ed = key.is_a?(AtlasPca::KeyPair) ? key : AtlasPca::KeyPair.new(key)
      signed = AtlasPca.sign_artifact(DETECTOR_RECEIPT_DOMAIN, body, ed, alg: alg, pq: pq)
      e = detector_receipt_shape_error(signed)
      raise ArgumentError, "signDetectorReceipt: #{e}" if e

      signed
    end

    # nil when the detector policy {detectors: [{id, keys (1..8 pins {pk, pq_pk?}), on_suspicious, max_age_ms, categories?}]} is well-formed.
    def detector_policy_error(p)
      return 'policy must be {detectors}' if !p.is_a?(Hash) || !AtlasPca.wb_closed_members(p, %w[detectors]).nil?
      return 'detectors must hold at most 16 entries' unless p['detectors'].is_a?(Array) && p['detectors'].length <= 16

      ids = Set.new
      p['detectors'].each do |d|
        return 'detector entry is malformed' if !d.is_a?(Hash) || !AtlasPca.wb_closed_members(d, %w[id keys on_suspicious max_age_ms], %w[categories]).nil?
        return 'detector ids must be distinct ids other than "invalid"' if !AtlasPca.wb_re?(ID_RE, d['id']) || d['id'] == 'invalid' || ids.include?(d['id'])

        ids << d['id']
        keys = d['keys']
        return "detector '#{d['id']}': keys must hold 1..8 pins" unless keys.is_a?(Array) && keys.length.between?(1, 8) &&
                                                                       keys.all? { |k| k.is_a?(Hash) && k['pk'].is_a?(String) && (!k.key?('pq_pk') || k['pq_pk'].is_a?(String)) }
        return "detector '#{d['id']}': on_suspicious must be escalate or deny" unless %w[escalate deny].include?(d['on_suspicious'])

        cats = d['categories']
        return "detector '#{d['id']}': categories must be 1+ ids" if d.key?('categories') && !(cats.is_a?(Array) && !cats.empty? && cats.all? { |c| AtlasPca.wb_re?(ID_RE, c) })
        return "detector '#{d['id']}': max_age_ms must be 1..86400000" unless AtlasPca.wb_safe_int?(d['max_age_ms']) && d['max_age_ms'].between?(1, 86_400_000)
      end
      nil
    end

    DETECTOR_RANK = { 'ok' => 2, 'escalate' => 1, 'deny' => 0 }.freeze

    def detector_receipt_problem(r, policy, digests, session, now)
      se = detector_receipt_shape_error(r)
      return "malformed: #{se}" if se

      d = policy['detectors'].find { |x| x['id'] == r['detector'] }
      return "undeclared detector '#{r['detector']}'" if d.nil?
      return "detector '#{d['id']}': no pinned key signed it" unless d['keys'].any? { |k| AtlasPca.wb_verify_artifact_sig(DETECTOR_RECEIPT_DOMAIN, r, k) }
      return "detector '#{d['id']}': the receipt is about other content" unless digests.include?(r['input_digest'])
      return "detector '#{d['id']}': bound to another session" if r.key?('session') && r['session'] != session
      return "detector '#{d['id']}': from the future" unless r['iat'] <= now
      return "detector '#{d['id']}': stale" unless now - r['iat'] <= d['max_age_ms']

      nil
    end

    # The tighten-only fold of detector receipts (total). `input`: {receipts, policy, input_digests, session?, now}. A malformed policy is
    # deny; an invalid receipt lowers the signal to escalate; a valid suspicious receipt with an acting category lowers it to the
    # detector's on_suspicious; a valid no_finding changes nothing. Returns {signal, env: {detect: {...}}, flagged, rejected}.
    def detector_signal(input)
      flagged = Set.new
      rejected = []
      signal = 'ok'
      lower = ->(s) { signal = s if DETECTOR_RANK[s] < DETECTOR_RANK[signal] }
      env = {}
      begin
        policy = input.is_a?(Hash) ? input['policy'] : nil
        pe = detector_policy_error(policy)
        return { 'signal' => 'deny', 'env' => { 'detect' => { 'invalid' => 0 } }, 'flagged' => [], 'rejected' => [{ 'index' => -1, 'reason' => "policy: #{pe}" }] } if pe

        policy['detectors'].each { |d| env[d['id']] = false }
        receipts = input.key?('receipts') && !input['receipts'].nil? ? input['receipts'] : []
        digests = input['input_digests'].is_a?(Array) ? input['input_digests'] : []
        now = input['now']
        if !receipts.is_a?(Array) || receipts.length > MAX_DETECTOR_RECEIPTS || !AtlasPca.wb_safe_int?(now)
          lower.call('escalate')
          rejected << { 'index' => -1, 'reason' => 'receipt list or clock malformed' }
        else
          receipts.each_with_index do |r, index|
            why = detector_receipt_problem(r, policy, digests, input['session'], now)
            if why
              rejected << { 'index' => index, 'reason' => why }
              lower.call('escalate')
              next
            end
            next unless r['verdict'] == 'suspicious'

            d = policy['detectors'].find { |x| x['id'] == r['detector'] }
            next if d.key?('categories') && !r['categories'].empty? && r['categories'].none? { |c| d['categories'].include?(c) }

            flagged << d['id']
            env[d['id']] = true
            lower.call(d['on_suspicious'])
          end
        end
      rescue StandardError => e
        lower.call('deny')
        rejected << { 'index' => -1, 'reason' => "evaluation error (fail closed): #{e.message}" }
      end
      env['invalid'] = rejected.length
      { 'signal' => signal, 'env' => { 'detect' => env }, 'flagged' => sorted(flagged), 'rejected' => rejected }
    end

    def obj?(v) = v.is_a?(Hash)

    # Vendor category text to a receipt category id (lowercase, non-alphanumerics to `_`); unusable text becomes `other`.
    def category_id(s)
      return 'other' unless s.is_a?(String)

      c = scrubbed(s).downcase.gsub(/[^a-z0-9]+/, '_').gsub(/\A_+|_+\z/, '').sub(/\A([0-9])/, 'c_\1')[0, 64]
      ID_RE.match?(c) ? c : 'other'
    end

    # ctx (String keys): detector, version, content, secret_key (KeyPair or seed), now, session?, calibration_ref?
    def receipt(ctx, suspicious, categories)
      cats = suspicious ? sorted(Set.new(categories))[0, 8] : []
      body = {
        'v' => 1, 'kind' => 'pca-detector-receipt', 'detector' => ctx['detector'], 'version' => ctx['version'],
        'input_digest' => detector_input_digest(ctx['content']), 'verdict' => suspicious ? 'suspicious' : 'no_finding',
        'categories' => cats, 'iat' => ctx['now']
      }
      body['session'] = ctx['session'] unless ctx['session'].nil?
      body['calibration_ref'] = ctx['calibration_ref'] unless ctx['calibration_ref'].nil?
      sign_detector_receipt(body, ctx['secret_key'])
    end

    def error_receipt(ctx) = receipt(ctx, true, ['detector_error'])

    # Lakera Guard v2 `/guard` response.
    def lakera_receipt(response, ctx)
      return error_receipt(ctx) if !obj?(response) || ![true, false].include?(response['flagged'])

      cats = Set.new
      if response.key?('breakdown')
        return error_receipt(ctx) unless response['breakdown'].is_a?(Array)

        response['breakdown'].each do |b|
          return error_receipt(ctx) if !obj?(b) || ![true, false].include?(b['detected'])

          cats << category_id(b['detector_type']) if b['detected']
        end
      end
      suspicious = response['flagged'] || !cats.empty?
      cats << 'flagged' if suspicious && cats.empty?
      receipt(ctx, suspicious, cats)
    end

    # Prompt Security `/api/protect` response (both published integration shapes accepted; clean only when no action is block or
    # modify and no violation is listed).
    def prompt_security_receipt(response, ctx)
      r = obj?(response) && obj?(response['result']) ? response['result'] : nil
      return error_receipt(ctx) if r.nil?

      p = r['prompt']
      return error_receipt(ctx) if r.key?('prompt') && !obj?(p)

      actions = r.key?('action') ? [r['action']] : []
      actions << p['action'] if obj?(p) && p.key?('action')
      return error_receipt(ctx) if actions.empty? || !actions.all? { |a| a.is_a?(String) }

      violations = obj?(p) && p.key?('violations') ? p['violations'] : nil
      return error_receipt(ctx) if obj?(p) && p.key?('violations') && !violations.is_a?(Array)

      cats = Set.new((violations || []).map { |v| category_id(v) })
      cats << 'blocked' if actions.include?('block')
      cats << 'modified' if actions.include?('modify')
      receipt(ctx, !cats.empty?, cats)
    end

    # Any detector that answers `{flagged, categories?}`.
    def generic_receipt(response, ctx)
      return error_receipt(ctx) if !obj?(response) || ![true, false].include?(response['flagged'])
      return error_receipt(ctx) if response.key?('categories') && !response['categories'].is_a?(Array)

      cats = Set.new((response['categories'] || []).map { |c| category_id(c) })
      return error_receipt(ctx) if !response['flagged'] && !cats.empty? # categories on a clean answer: ambiguous

      cats << 'flagged' if response['flagged'] && cats.empty?
      receipt(ctx, response['flagged'], cats)
    end
  end
end
