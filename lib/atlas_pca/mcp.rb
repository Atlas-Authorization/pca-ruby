# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'agentcard_card'
require_relative 'adapters'

# Model Context Protocol adapter for Proof-Carrying Authority (TypeScript reference @atlasauth/pca-mcp):
# - with_pca wraps a tool handler so each call builds a PCActn first (fast-fail on the local dry run), then runs the handler.
# - guard_tool_result carries the encoded PCActn in a tool result's _meta.
# - parse_challenges / plan_step_up / check_authorization_response_iss: the client half of MCP authorization step-up, with the
#   pca_need extension (advisory, never approves anything).
# - draft_action_schema_from_mcp / apply_schema_decisions / verb_of_tool / conform_tool_call: MCP tools to the site's signed
#   action schema and the closed-world check of a tool call.
# - pca_fetch: the agent's per-call proof for an MCP client transport, over an injected fetch callable.
# Not ported: importActionDefsFromMcp (it delegates to the optional action-kit package) and the per-call audience override
# (Agent#act owns the audience). Data (tools, schemas, challenges, step-up state) keeps the reference's camelCase members;
# option Hashes are snake_case.
module AtlasPca
  module Mcp
    UNDEF = V2JS::UNDEF
    MCP_CLIENT_REVISIONS = %w[2025-03-26 2025-06-18 2025-11-25 2026-07-28 draft].freeze
    MAX_REF_DEPTH = 8
    MAX_REF_NODES = 20_000
    NAME_RE = /\A[A-Za-z0-9_]{1,64}\z/n
    PCA_NEED_MAX_ENCODED = 2048
    NEED_KINDS = %w[scope grant discharge escalate].freeze
    NEED_MEMBERS = %w[v kind verb resource scopes grant_ref limits discharges tier policy_digest].freeze
    MAX_LIST = 16
    WS_RE = /[#{Js::WS}]/o
    NEED_PARAM_RE = /(?:\A|[#{Js::WS},])pca_need="([^"\\]*)"/o

    # Raised by with_pca's guard when the local dry run rejects a call before dispatch.
    class PcaDenied < StandardError
      attr_reader :reason, :verb, :resource

      def initialize(reason, verb, resource)
        super("PCA denied #{verb} on #{resource}: #{reason}")
        @reason = reason
        @verb = verb
        @resource = resource
      end
    end

    module_function

    def prop(o, k) = V2JS.prop(o, k)
    def undef?(v) = v.equal?(UNDEF)
    def nullish?(v) = v.nil? || undef?(v)
    def truthy?(v) = V2JS.truthy?(v)
    def strict_eq(a, b) = V2JS.strict_eq(a, b)
    def js_str(v) = V2JS.js_str(v)
    def u16len(s) = V2JS.u16len(s)
    def spread(v) = AgentcardCard.spread(v)
    def utf8_order(a, b) = V2JS.compare_utf8(a, b)

    # JS iteration ([...x], new Set(x)) of a JSON value: arrays and strings only.
    def iter(x)
      case x
      when Array then x.dup
      when String then x.chars
      else raise TypeError, 'not iterable'
      end
    end

    # ---- withPCA / guardToolResult ----

    def pca_call_of(action)
      { 'encoded' => AtlasPca.decode_pca_header(action.headers['PCA-Action']), 'pcactn' => action.pcactn, 'headers' => action.headers,
        'provenance' => action.respond_to?(:provenance) ? action.provenance : nil }
    end

    # nil when the action verifies against the agent's own root grant and every hop's envelope admits it, else the refusal
    # reason. Never raises.
    def dry_run(agent, action, params = nil)
      now = agent.respond_to?(:clock) ? agent.clock.call : Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)
      v = AtlasPca.verify_pcactn(action.pcactn, agent.chain[0], now: now, audience: agent.aud,
                                                                authorized_plan_roots: [action.pcactn['plan']['root']])
      return (Js.truthy?(v.reason) ? v.reason : 'denied') unless v.allow

      AtlasPca::Adapters.envelope_refusal(agent, action, params)
    rescue StandardError => e # fail closed
      "dry run failed (#{e.class.name.split('::').last})"
    end

    # What a tool result entering the model's context records (UNTRUSTED), when the agent keeps a provenance chain.
    def record_tool_result(agent, tool, output)
      rec = agent.respond_to?(:provenance) ? agent.provenance : nil
      rec&.tool(tool, output)
    end

    # Wrap an MCP tool handler (args, extra) -> result: build a PCActn (dry run first unless fail_fast is false), hand it to
    # on_proof(pca, args), then run the handler. A local denial returns the MCP error result instead of raising. resource is a
    # String or a callable (params -> String).
    def with_pca(agent, verb, resource, handler, fail_fast: true, on_proof: nil)
      lambda do |args, extra = nil|
        res = resource.respond_to?(:call) ? resource.call(args) : resource
        action = agent.act(verb, res, args)
        if fail_fast
          why = dry_run(agent, action, args)
          raise PcaDenied.new(why, verb, res) unless why.nil?
        end
        on_proof&.call(pca_call_of(action), args)
        out = handler.call(args, extra)
        record_tool_result(agent, verb, out)
        out
      rescue PcaDenied => e
        { 'content' => [{ 'type' => 'text', 'text' => e.message }], 'isError' => true }
      end
    end

    # Attach the encoded PCActn to a tool result's _meta, keeping content, isError and existing _meta keys.
    def guard_tool_result(pca, result)
      raise TypeError, 'guard_tool_result: result must not be null' if result.nil?

      raise TypeError, "Cannot read properties of null (reading 'encoded')" if pca.nil?

      meta = result.is_a?(Hash) ? result['_meta'] : nil
      prev = truthy?(meta) && (meta.is_a?(Hash) || meta.is_a?(Array)) ? spread(meta) : {}
      encoded = if pca.is_a?(Hash) then prop(pca, 'encoded')
                elsif pca.respond_to?(:encoded) then pca.encoded
                else UNDEF
                end
      new_meta = prev.dup
      if undef?(encoded)
        new_meta.delete('x-pca-action')
      else
        new_meta['x-pca-action'] = encoded
      end
      out = spread(result)
      out['_meta'] = new_meta
      out
    end

    # ---- the client half of step-up ----

    # Parse a WWW-Authenticate value (RFC 9110 section 11) into [{'scheme', 'params'}]. Never raises on garbage.
    def parse_challenges(header)
      out = []
      return out unless header.is_a?(String)

      n = header.length
      i = 0
      cur = nil
      token = lambda do
        s = i
        i += 1 while i < n && !" \t,=\"".include?(header[i])
        header[s...i]
      end
      i += 1 while i < n && " \t,".include?(header[i])
      while i < n
        name = token.call
        if name.empty?
          i += 1 # a stray quote or equals sign: skip it
          next
        end
        i += 1 while i < n && " \t".include?(header[i])
        if i < n && header[i] == '='
          i += 1
          i += 1 while i < n && " \t".include?(header[i])
          val = +''
          if i < n && header[i] == '"'
            i += 1
            while i < n && header[i] != '"'
              i += 1 if header[i] == '\\' && i + 1 < n
              val << header[i]
              i += 1
            end
            i += 1 # closing quote
          else
            val = token.call
          end
          key = AgentcardCard.lower(name)
          # the reference tests `key in params` on a plain object, so these two inherited names are never stored
          cur['params'][key] = val if !cur.nil? && !cur['params'].key?(key) && !%w[constructor __proto__].include?(key)
        else
          cur = { 'scheme' => AgentcardCard.lower(name), 'params' => {} }
          out << cur
        end
        i += 1 while i < n && " \t,".include?(header[i])
      end
      out
    end

    def split_scopes(s) = s.nil? ? [] : s.split(/ /, -1).reject(&:empty?)

    # Decide the next step for a response; state = {'requested', 'attempts', 'maxAttempts'?, 'pcaAware'?}. Only 403 with
    # error="insufficient_scope" on a Bearer challenge is a step-up. The scope list is the sorted union of what was requested and
    # what the challenge names; an unchanged union without a usable pca_need gives up instead of looping.
    def plan_step_up(status, www_authenticate, state)
      mx = state['maxAttempts']
      mx = 3 if mx.nil?
      bearer = nil
      bearer = parse_challenges(www_authenticate).find { |c| c['scheme'] == 'bearer' } if strict_eq(status, 403)
      return { 'action' => 'give_up', 'reason' => 'not_insufficient_scope' } if bearer.nil? || bearer['params']['error'] != 'insufficient_scope'
      return { 'action' => 'give_up', 'reason' => 'retry_limit' } unless state['attempts'].is_a?(Numeric) && state['attempts'].to_f.finite? && state['attempts'] < mx

      requested = iter(prop(state, 'requested'))
      union = (requested + split_scopes(bearer['params']['scope'])).uniq.sort_by { |x| AgentcardCard.u16key(x) }
      attempts = state['attempts'] + 1
      if state['pcaAware'] == true
        r = www_authenticate.is_a?(String) ? pca_need_from_challenge(www_authenticate) : nil
        return { 'action' => 'pca', 'need' => r['need'], 'fallbackScopes' => union, 'attempts' => attempts } if !r.nil? && r['ok']
        # a missing or malformed pca_need is not an error: fall through to the stock behaviour
      end
      return { 'action' => 'give_up', 'reason' => 'no_new_scope' } if union.all? { |s| requested.include?(s) }

      { 'action' => 'scope', 'scopes' => union, 'attempts' => attempts }
    end

    # The reason a present-but-unusable pca_need was ignored, for client logs.
    def pca_need_problem(www_authenticate)
      r = pca_need_from_challenge(www_authenticate)
      !r.nil? && !r['ok'] ? r['code'] : nil
    end

    # RFC 9207 section 2.4 as tabulated in the MCP authorization specification: a = {'recordedIssuer', 'issParameterSupported',
    # 'iss'}. Simple string comparison (no normalization); an absent iss is refused only when the server advertised support.
    def check_authorization_response_iss(a)
      raise TypeError, "Cannot read properties of #{a.nil? ? 'null' : 'undefined'} (reading 'recordedIssuer')" if nullish?(a)

      rec = prop(a, 'recordedIssuer')
      return { 'proceed' => false, 'reason' => 'no_recorded_issuer' } if !rec.is_a?(String) || rec.empty?

      iss = prop(a, 'iss')
      return(prop(a, 'issParameterSupported') == true ? { 'proceed' => false, 'reason' => 'iss_missing' } : { 'proceed' => true }) if undef?(iss)

      iss.is_a?(String) && iss.b == rec.b ? { 'proceed' => true } : { 'proceed' => false, 'reason' => 'iss_mismatch' }
    end

    # ---- the pca_need challenge parameter (decode side) ----

    def need_str?(x, mx) = x.is_a?(String) && u16len(x).between?(1, mx)
    def bad(code) = { 'ok' => false, 'code' => code }

    def validate_pca_need(x)
      return bad('bad_shape') unless x.is_a?(Hash)
      return bad('unknown_member') if x.each_key.any? { |k| !NEED_MEMBERS.include?(k) }
      return bad('bad_version') unless strict_eq(prop(x, 'v'), 1)

      kind = prop(x, 'kind')
      return bad('bad_kind') if !kind.is_a?(String) || !NEED_KINDS.include?(kind)
      return bad('bad_field') if !need_str?(prop(x, 'verb'), 128) || !need_str?(prop(x, 'resource'), 512)

      sc = prop(x, 'scopes')
      if !undef?(sc) && !(sc.is_a?(Array) && sc.length <= MAX_LIST && sc.all? { |s| need_str?(s, 128) && !s.match?(WS_RE) })
        return bad('bad_field')
      end
      return bad('bad_field') if !undef?(prop(x, 'grant_ref')) && !need_str?(x['grant_ref'], 128)
      return bad('bad_field') if !undef?(prop(x, 'policy_digest')) && !need_str?(x['policy_digest'], 128)

      tier = prop(x, 'tier')
      return bad('bad_field') if !undef?(tier) && !strict_eq(tier, 2) && !strict_eq(tier, 3)

      lim = prop(x, 'limits')
      unless undef?(lim)
        return bad('bad_field') if !lim.is_a?(Hash) || lim.length > MAX_LIST

        lim.each do |k, v|
          return bad('bad_field') if !need_str?(k, 64) || !Js.num?(v) || !(v.is_a?(Integer) || v.finite?) || v.negative?
        end
      end
      dis = prop(x, 'discharges')
      unless undef?(dis)
        return bad('bad_field') if !dis.is_a?(Array) || dis.length > MAX_LIST

        dis.each do |d|
          if !d.is_a?(Hash) || d.each_key.any? { |k| !%w[issuer claim].include?(k) } || !need_str?(prop(d, 'issuer'), 512) || !need_str?(prop(d, 'claim'), 256)
            return bad('bad_field')
          end
        end
      end
      return bad('bad_field') if !undef?(tier) && kind != 'escalate'
      return bad('bad_field') if kind == 'escalate' && undef?(tier)

      { 'ok' => true, 'need' => x }
    end

    def decode_pca_need(value)
      return bad('bad_base64') if !value.is_a?(String) || value.empty?
      return bad('too_long') if u16len(value) > PCA_NEED_MAX_ENCODED

      raw = AtlasPca.b64d(value)
      return bad('bad_base64') if raw.nil?

      raw = raw.byteslice(3..) if raw.byteslice(0, 3) == "\xEF\xBB\xBF".b # TextDecoder drops a leading BOM
      text = raw.dup.force_encoding('UTF-8')
      return bad('bad_utf8') unless text.valid_encoding?

      parsed = begin
        AtlasPca.parse_json(text, any_top: true)
      rescue StandardError # any parse failure is bad_json
        return bad('bad_json')
      end
      validate_pca_need(parsed)
    end

    def pca_need_from_challenge(header)
      return nil unless header.is_a?(String)

      m = NEED_PARAM_RE.match(header.valid_encoding? ? header : header.scrub('?'))
      m.nil? ? nil : decode_pca_need(m[1])
    end

    # ---- conformance matrix ----

    def levels(*vals) = MCP_CLIENT_REVISIONS.zip(vals).to_h

    MCP_AUTH_CLIENT_ROWS = [
      { 'id' => 'parse-www-authenticate', 'requirement' => 'Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.',
        'levels' => levels('n/a', 'MUST', 'MUST', 'MUST', 'MUST'), 'section' => 'Protected Resource Metadata Discovery Requirements' },
      { 'id' => 'step-up-on-insufficient-scope', 'requirement' => 'Respond to 403 insufficient_scope by re-authorizing with an increased scope set.',
        'levels' => levels('n/a', 'n/a', 'SHOULD', 'SHOULD', 'SHOULD'), 'section' => 'Step-Up Authorization Flow' },
      { 'id' => 'scope-union', 'requirement' => 'The new scope set is the union of the previously requested set and the challenge scopes.',
        'levels' => levels('n/a', 'n/a', 'n/a', 'SHOULD', 'SHOULD'), 'section' => 'Step-Up Authorization Flow, step 2' },
      { 'id' => 'retry-limit', 'requirement' => 'Retry no more than a few times and track upgrade attempts per resource and operation.',
        'levels' => levels('n/a', 'n/a', 'SHOULD', 'SHOULD', 'SHOULD'), 'section' => 'Step-Up Authorization Flow, step 4' },
      { 'id' => 'iss-validation-table', 'requirement' => 'Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.',
        'levels' => levels('n/a', 'n/a', 'n/a', 'MUST', 'MUST'), 'section' => 'Authorization Response Validation' },
      { 'id' => 'pca-need-ignored-by-stock-client', 'requirement' => 'A client that does not know pca_need behaves exactly as without it.',
        'levels' => levels('EXT', 'EXT', 'EXT', 'EXT', 'EXT'), 'section' => 'RFC 9110 section 11.2 (unknown auth-params are ignored)' }
    ].freeze

    # ---- MCP tools -> the site's action schema ----

    # x.slice(0, n) of a truthy JSON value: strings by UTF-16 units (a cut pair leaves a lone surrogate), arrays by items,
    # anything else throws.
    def slice_units(x, n)
      return x[0, n] if x.is_a?(Array)
      raise TypeError, 'slice is not a function' unless x.is_a?(String)
      return x if u16len(x) <= n

      units = AgentcardCard.u16key(x).unpack('n*')[0, n]
      out = String.new(encoding: Encoding::BINARY)
      i = 0
      while i < units.length
        u = units[i]
        lo = units[i + 1]
        if u.between?(0xD800, 0xDBFF) && lo&.between?(0xDC00, 0xDFFF)
          out << [0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)].pack('U').b
          i += 2
        else
          out << AgentcardCard.unit_char(u).b
          i += 1
        end
      end
      out.force_encoding('UTF-8')
    end

    def safe_int?(v) = Js.num?(v) && Js.safe_integer?(v)

    def own(o, k) = prop(o, k)

    def pointer(root, ref)
      return UNDEF unless ref.start_with?('#/')

      cur = root
      body = ref[2..]
      (body.empty? ? [''] : body.split('/', -1)).each do |raw|
        seg = raw.gsub('~1', '/').gsub('~0', '~')
        case cur
        when Hash
          return UNDEF unless cur.key?(seg)

          cur = cur[seg]
        when Array
          return UNDEF if !seg.match?(/\A(?:0|[1-9][0-9]*)\z/) || seg.to_i >= cur.length

          cur = cur[seg.to_i]
        else return UNDEF
        end
      end
      cur.is_a?(Hash) || cur.is_a?(Array) ? cur : UNDEF
    end

    def null_type?(m)
      t = m.key?('type') ? m['type'] : UNDEF
      t == 'null' || (t.is_a?(Array) && t.all? { |x| x == 'null' })
    end

    # Follow local $refs, merge allOf, collapse anyOf / oneOf to its single non-null variant (or a union of string constants);
    # whatever cannot be represented is flagged in c['todo'] and left empty (the caller declares it string).
    def flatten_schema(s, c, where, depth = 0)
      return {} unless s.is_a?(Hash) || s.is_a?(Array)

      s = {} if s.is_a?(Array) # a bare array has no schema members
      c['left'] = (c['left'] || MAX_REF_NODES) - 1
      if c['left'].negative?
        c['todo'] << "#{where}: schema expansion stopped after #{MAX_REF_NODES} nodes (declared string; refine or drop)" if c['left'] == -1
        return {}
      end
      if depth > MAX_REF_DEPTH
        c['todo'] << "#{where}: schema nesting or reference chain deeper than #{MAX_REF_DEPTH} (declared string; refine or drop)"
        return {}
      end
      cur = s
      ref = cur['$ref']
      if ref.is_a?(String)
        target = pointer(c['root'], ref)
        if undef?(target)
          c['todo'] << "#{where}: reference '#{slice_units(ref, 120)}' is not a local reference that resolves (declared string; refine or drop)"
          return {}
        end
        siblings = s.reject { |k, _| k == '$ref' }
        cur = flatten_schema(target, c, where, depth + 1).merge(siblings)
      end
      if cur['allOf'].is_a?(Array)
        rest = cur.reject { |k, _| k == 'allOf' }
        acc = {}
        cur['allOf'].map { |x| flatten_schema(x, c, where, depth + 1) }.each do |m|
          nxt = acc.merge(m)
          nxt['properties'] = spread(acc['properties']).merge(spread(m['properties']))
          nxt['required'] = (nullish?(acc['required']) ? [] : iter(acc['required'])) + (nullish?(m['required']) ? [] : iter(m['required']))
          acc = nxt
        end
        cur = acc.merge(rest)
      end
      alts = cur['anyOf']
      alts = cur['oneOf'] if nullish?(alts)
      if alts.is_a?(Array)
        rest = cur.reject { |k, _| %w[anyOf oneOf].include?(k) }
        live = alts.map { |x| flatten_schema(x, c, where, depth + 1) }.reject { |m| null_type?(m) }
        return live[0].merge(rest) if live.length == 1

        consts = live.map do |m|
          k = m.key?('const') ? m['const'] : UNDEF
          e = m.key?('enum') ? m['enum'] : UNDEF
          if k.is_a?(String) then [k]
          elsif e.is_a?(Array) && e.all?(String) then e
          end
        end
        return rest.merge('type' => 'string', 'enum' => consts.flatten.uniq) if live.length > 1 && consts.all? { |x| !x.nil? }

        c['todo'] << "#{where}: a union of #{live.length} schemas has no schema representation (declared string; refine or drop)"
        return rest
      end
      if cur.key?('const') && !cur.key?('enum') && cur['const'].is_a?(String)
        cur = cur.dup
        cur['enum'] = [cur['const']]
      end
      cur
    end

    def enum_strings(x) = x.is_a?(Array) && x.all?(String) ? x : nil

    # JSON Schema property -> parameter declaration. Sensitivity defaults to 'material'; unrepresentable shapes become string
    # placeholders flagged in todo.
    def decl_of_json_schema(name, schema, required, c)
      todo = c['todo']
      s = flatten_schema(schema, c, "action.params.#{name}")
      t = s.key?('type') ? s['type'] : UNDEF
      if t.is_a?(Array)
        i = t.index { |x| x != 'null' }
        t = i.nil? ? UNDEF : t[i]
      end
      sem = prop(s, 'x-pca-semantic')
      sen = prop(s, 'x-pca-sensitivity')
      base = { 'semantic' => nullish?(sem) ? 'unknown' : sem, 'sensitivity' => nullish?(sen) ? 'material' : sen }
      base['required'] = false unless required
      base['description'] = slice_units(s['description'], 1024) if truthy?(prop(s, 'description'))
      todo << "action.params.#{name}: semantic type" unless truthy?(sem)
      enum = enum_strings(prop(s, 'enum'))
      if t == 'integer'
        out = { 'type' => 'integer' }.merge(base)
        mn = prop(s, 'minimum')
        mnx = prop(s, 'exclusiveMinimum')
        mx = prop(s, 'maximum')
        mxx = prop(s, 'exclusiveMaximum')
        if safe_int?(mn) then out['min'] = mn
        elsif safe_int?(mnx) then out['min'] = mnx + 1
        end
        if safe_int?(mx) then out['max'] = mx
        elsif safe_int?(mxx) then out['max'] = mxx - 1
        end
        out['unit'] = s['x-pca-unit'] if truthy?(prop(s, 'x-pca-unit'))
        out['accumulates_into'] = s['x-pca-accumulates-into'] if truthy?(prop(s, 'x-pca-accumulates-into'))
        return out
      end
      return base.merge('type' => 'boolean') if t == 'boolean'
      return base.merge('type' => 'date') if t == 'string' && prop(s, 'format') == 'date'

      if t == 'string'
        out = base.merge('type' => 'string')
        out['values'] = enum unless enum.nil?
        ml = prop(s, 'maxLength')
        out['max_len'] = ml if safe_int?(ml) && ml.positive?
        return out
      end
      if t == 'array'
        it = flatten_schema(prop(s, 'items'), c, "action.params.#{name}[]")
        it_enum = enum_strings(prop(it, 'enum'))
        mi = prop(s, 'minItems')
        mx = prop(s, 'maxItems')
        if truthy?(prop(s, 'uniqueItems')) && !it_enum.nil?
          out = base.merge('type' => 'set', 'values' => it_enum)
          out['min_items'] = mi if safe_int?(mi)
          out['max_items'] = mx if safe_int?(mx)
          return out
        end
        it_t = prop(it, 'type')
        it_t = it_t.empty? ? UNDEF : it_t[0] if it_t.is_a?(Array)
        out = base.merge('type' => 'array')
        out['items'] = 'integer' if it_t == 'integer'
        out['max_items'] = mx if safe_int?(mx)
        out['min_items'] = mi if safe_int?(mi)
        return out
      end
      todo << "action.params.#{name}: type '#{js_str(t)}' has no schema representation (declared string; refine or drop)"
      base.merge('type' => 'string')
    end

    # MCP annotations give a LOWER bound on reversibility only (hints never lower a classification).
    def reversibility_from_mcp_hints(a)
      return { 'kind' => 'read', 'atLeast' => 'reversible' } if own(a, 'readOnlyHint') == true
      return { 'kind' => 'write', 'atLeast' => 'rate_limited' } if own(a, 'destructiveHint') == true

      { 'kind' => 'write', 'atLeast' => 'reversible' }
    end

    # Object.keys of a JSON value (own enumerable string keys).
    def keys_of(o)
      case o
      when Hash then Js.js_keys(o)
      when Array then o.each_index.map(&:to_s)
      when String then Array.new(AgentcardCard.u16key(o).bytesize / 2) { |i| i.to_s }
      else []
      end
    end

    # o[k] for a JSON value and an own key from keys_of.
    def get_key(o, k) = o.is_a?(Hash) ? o[k] : (o.is_a?(String) ? AgentcardCard.unit_char(AgentcardCard.u16key(o).unpack('n*')[k.to_i]) : o[k.to_i])

    # Draft action schema from an MCP tools/list: verb = <verb_prefix><tool.name>; every write verb is drafted irreversible (the
    # fail-closed default). Returns {'schema', 'todo'}: the decisions the developer must make before signing. site: {'site',
    # 'aud', 'version', 'verbPrefix'} (the schema members keep their names).
    def draft_schema_from_mcp_tools(tools, site)
      todo = []
      verbs = []
      iter(tools).each do |t|
        raise TypeError, 'a tool must not be null' if t.nil?

        root = own(t, 'inputSchema')
        c = { 'root' => undef?(root) ? nil : root, 'todo' => todo }
        name_s = js_str(own(t, 'name'))
        inp = flatten_schema(own(t, 'inputSchema'), c, "#{name_s}: inputSchema")
        props = inp['properties']
        props = {} if nullish?(props)
        req_v = inp['required']
        req = iter(nullish?(req_v) ? [] : req_v).select { |x| x.is_a?(String) }.map(&:b)
        params = {}
        keys_of(props).sort { |a, b| utf8_order(a, b) }.each do |pname|
          unless pname.b.match?(NAME_RE)
            todo << "#{name_s}: parameter '#{pname}' is not a schema name ([A-Za-z0-9_]{1,64}); rename it"
            next
          end
          params["action.params.#{pname}"] = decl_of_json_schema(pname, get_key(props, pname), req.include?(pname.b), c)
        end
        h = reversibility_from_mcp_hints(own(t, 'annotations'))
        prefix = site['verbPrefix']
        verb = (nullish?(prefix) ? '' : js_str(prefix)) + name_s
        todo << "#{verb}: reversibility (drafted irreversible)" if h['kind'] == 'write'
        entry = { 'verb' => verb, 'kind' => h['kind'], 'params' => params, 'reversibility' => h['kind'] == 'read' ? 'reversible' : 'irreversible',
                  'mcp' => undef?(own(t, 'name')) ? {} : { 'tool' => t['name'] } }
        entry['description'] = slice_units(t['description'], 1024) if truthy?(own(t, 'description'))
        verbs << entry
      end
      verbs = verbs.each_with_index.sort { |(a, i), (b, j)| (r = utf8_order(a['verb'], b['verb'])).zero? ? i <=> j : r }.map(&:first)
      schema = { 'v' => 1, 'kind' => IntentV2::ACTION_SCHEMA_KIND, 'verbs' => verbs }
      %w[site aud version].each { |k| schema[k] = site[k] if site.key?(k) }
      { 'schema' => schema, 'todo' => todo }
    end

    # The JSON media type of a request body: application/json first, else any application/*+json (keys in UTF-8 order).
    def json_body_schema(b)
      content = prop(b, 'content')
      return UNDEF unless content.is_a?(Hash) || content.is_a?(Array)

      keys = keys_of(content).sort { |a, c| utf8_order(a, c) }
      key = keys.find { |k| k.downcase == 'application/json' } || keys.find { |k| k.match?(%r{\Aapplication/[^;]*\+json(;|\z)}i) }
      key.nil? ? UNDEF : prop(get_key(content, key), 'schema')
    end

    # Draft action schema from an OpenAPI document: one verb per operation with an operationId (x-pca-verb names it, else the id).
    # The parameters are the operation's path and query parameters (path-item parameters included, the operation's own winning) plus
    # the properties of its JSON request body; local $refs are followed. Header and cookie parameters, and a name two sources share
    # (the first kept), are flagged in todo. Returns {'schema', 'todo'}; site: {'site', 'aud', 'version'}.
    def draft_schema_from_open_api(doc, site)
      raise TypeError, "Cannot read properties of #{doc.nil? ? 'null' : 'undefined'} (reading 'paths')" if nullish?(doc)

      todo = []
      verbs = []
      c = { 'root' => doc, 'todo' => todo }
      deref = lambda do |x|
        next UNDEF unless x.is_a?(Hash) || x.is_a?(Array)

        ref = prop(x, '$ref')
        next x unless ref.is_a?(String)

        t = pointer(doc, ref)
        todo << "reference '#{slice_units(ref, 120)}' is not a local reference that resolves" if undef?(t)
        t
      end
      paths = prop(doc, 'paths')
      paths = {} if nullish?(paths)
      seen = {}
      keys_of(paths).sort { |a, b| utf8_order(a, b) }.each do |path|
        ops = get_key(paths, path)
        raise TypeError, "Cannot read properties of #{ops.nil? ? 'null' : 'undefined'} (reading 'parameters')" if nullish?(ops)

        shared_v = prop(ops, 'parameters')
        shared = shared_v.is_a?(Array) ? shared_v : []
        keys_of(ops).sort { |a, b| utf8_order(a, b) }.each do |method|
          op = get_key(ops, method)
          next unless op.is_a?(Hash) && truthy?(op['operationId'])

          c['left'] = MAX_REF_NODES
          op_id = op['operationId']
          op_s = js_str(op_id)
          kind = op['x-pca-kind']
          read = truthy?(kind) ? kind == 'read' : %w[get head].include?(method.downcase)
          verb = nullish?(op['x-pca-verb']) ? op_id : op['x-pca-verb']
          todo << "#{js_str(verb)}: declared by more than one operation; give each a distinct x-pca-verb" if seen.key?(verb)
          seen[verb] = true
          params = {}
          add_name = lambda do |name, sch, required, source|
            unless name.b.match?(NAME_RE)
              todo << "#{op_s}: parameter '#{name}' is not a schema name; rename it"
              next
            end
            key = "action.params.#{name}"
            if params.key?(key)
              todo << "#{op_s}: '#{name}' is declared by both the #{source} and another source; kept the first"
              next
            end
            params[key] = decl_of_json_schema(name, sch, required, c)
          end
          body = flatten_schema(json_body_schema(deref.call(prop(op, 'requestBody'))), c, "#{op_s}: request body")
          bprops = body['properties']
          bprops = {} if nullish?(bprops)
          breq_v = body['required']
          breq = iter(nullish?(breq_v) ? [] : breq_v).select { |x| x.is_a?(String) }.map(&:b)
          keys_of(bprops).sort { |a, b| utf8_order(a, b) }.each { |name| add_name.call(name, get_key(bprops, name), breq.include?(name.b), 'request body') }
          own_params = prop(op, 'parameters')
          merged = {}
          (shared + (own_params.is_a?(Array) ? own_params : [])).each do |raw|
            q = deref.call(raw)
            next unless q.is_a?(Hash) && q['name'].is_a?(String) && q['in'].is_a?(String)

            merged["#{q['in']}:#{q['name']}"] = q
          end
          merged.keys.sort { |a, b| utf8_order(a, b) }.each do |mk|
            q = merged[mk]
            unless %w[path query].include?(q['in'])
              todo << "#{op_s}: #{q['in']} parameter '#{q['name']}' is not an action parameter (the schema sees path, query and body parameters only)"
              next
            end
            qs = prop(q, 'schema')
            qs = {} if nullish?(qs)
            extra = truthy?(prop(q, 'description')) && !truthy?(prop(qs, 'description')) ? { 'description' => q['description'] } : {}
            add_name.call(q['name'], spread(qs).merge(extra), q['in'] == 'path' || q['required'] == true, "#{q['in']} parameters")
          end
          rev_v = op['x-pca-reversibility']
          rev = nullish?(rev_v) ? (read ? 'reversible' : 'irreversible') : rev_v
          todo << "#{js_str(verb)}: reversibility (drafted irreversible)" if !read && !truthy?(rev_v)
          entry = { 'verb' => verb, 'kind' => read ? 'read' : 'write', 'params' => params, 'reversibility' => rev, 'openapi' => { 'operationId' => op_id } }
          entry['description'] = slice_units(op['description'], 1024) if truthy?(prop(op, 'description'))
          verbs << entry
        end
      end
      verbs = verbs.each_with_index.sort { |(a, i), (b, j)| (r = utf8_order(a['verb'], b['verb'])).zero? ? i <=> j : r }.map(&:first)
      schema = { 'v' => 1, 'kind' => IntentV2::ACTION_SCHEMA_KIND, 'verbs' => verbs }
      %w[site aud version].each { |k| schema[k] = site[k] if site.is_a?(Hash) && site.key?(k) }
      { 'schema' => schema, 'todo' => todo }
    end

    # Draft an action schema from a tool list, or from anything responding to #list_tools (returning {'tools' => [...]}).
    def draft_action_schema_from_mcp(source, site)
      tools = source.is_a?(Array) ? source.dup : source.list_tools['tools']
      draft_schema_from_mcp_tools(tools, site)
    end

    # Object.entries of a JSON value; null / undefined throw.
    def entries(o)
      raise TypeError, 'cannot convert undefined or null to object' if nullish?(o)

      keys_of(o).map { |k| [k, get_key(o, k)] }
    end

    # Record the developer's decisions on a draft (a new object). A decision about a verb or parameter the draft does not have
    # raises: the schema is closed, so a typo must not silently publish a looser schema.
    def apply_schema_decisions(draft, d)
      out = Marshal.load(Marshal.dump(draft))
      raise TypeError, 'the draft must be an object' unless out.is_a?(Hash)

      units = d['units']
      if truthy?(units)
        merged = spread(nullish?(out['units']) ? {} : out['units'])
        merged.update(spread(units))
        out['units'] = merged
      end
      entries(prop(d, 'verbs')).each do |verb, dv|
        vs = out['verbs']
        raise TypeError, 'the draft has no verbs list' unless vs.is_a?(Array)

        v = nil
        vs.each do |x|
          raise TypeError, 'a verb entry must not be null' if x.nil?

          if x.is_a?(Hash) && x.key?('verb') && x['verb'] == verb
            v = x
            break
          end
        end
        raise ArgumentError, "applySchemaDecisions: the draft has no verb '#{verb}'" if v.nil?
        raise TypeError, 'a decision must not be null' if nullish?(dv)

        v['reversibility'] = dv['reversibility'] if truthy?(own(dv, 'reversibility'))
        dp_all = own(dv, 'params')
        entries(nullish?(dp_all) ? {} : dp_all).each do |path, dp|
          vp = prop(v, 'params')
          raise TypeError, 'the verb has no params' if nullish?(vp)

          p = own(vp, path)
          raise ArgumentError, "applySchemaDecisions: verb '#{verb}' has no parameter '#{path}'" unless truthy?(p)

          p.update(spread(dp)) if p.is_a?(Hash) # a non-object declaration cannot take members
        end
      end
      out
    end

    def verb_of_tool_raw(schema, tool_name)
      verbs = own(schema, 'verbs')
      raise TypeError, 'schema.verbs is not an array' if schema.nil? || !verbs.is_a?(Array)

      verbs.each do |v|
        raise TypeError, 'a verb entry must not be null' if v.nil?
        return prop(v, 'verb') if strict_eq(prop(prop(v, 'mcp'), 'tool'), tool_name)
      end
      UNDEF
    end

    # The schema verb an MCP tool maps to (by mcp.tool), or nil.
    def verb_of_tool(schema, tool_name)
      v = verb_of_tool_raw(schema, tool_name)
      undef?(v) ? nil : v
    end

    # Closed-world check of a tool call against the site schema (an unmapped tool is an unknown verb).
    def conform_tool_call(schema, tool_name, args)
      verb = verb_of_tool_raw(schema, tool_name)
      if undef?(verb)
        return { 'ok' => false, 'code' => 'unknown_verb', 'reason' => "MCP tool '#{js_str(tool_name)}' is not declared by the site schema" }
      end

      AtlasPca.conform_action(schema, verb, args)
    end

    # ---- pcaFetch ----

    # The {'name', 'arguments'} of a JSON-RPC tools/call request body, or nil for anything else.
    def tool_call_of(body)
      return nil unless body.is_a?(String)

      msg = begin
        Js.parse(body)
      rescue StandardError
        return nil
      end
      return nil if !msg.is_a?(Hash) || msg['method'] != 'tools/call' || !msg['method'].is_a?(String)

      params = msg['params']
      name = params.is_a?(Hash) ? params['name'] : nil
      args = params.is_a?(Hash) ? params['arguments'] : nil
      return nil unless name.is_a?(String)

      { 'name' => name, 'arguments' => args.is_a?(Hash) ? args : {} }
    end

    # A fetch for an MCP client transport that attaches a fresh, signed PCA-Action header to every tools/call. fetch.(url, init)
    # is the wrapped callable (init = {'body', 'headers', ...}); tool_action.(name, arguments) returns {'verb', 'resource'} or nil to
    # send the call without a proof. The response is recorded in the agent's chain as UNTRUSTED tool output before it is returned:
    # a response exposing #text is recorded by its body, an event stream (or an unreadable body) by its origin.
    def pca_fetch(agent, tool_action, fetch)
      lambda do |url, init = nil|
        call = tool_call_of((init || {})['body'])
        unless call.nil?
          m = tool_action.call(call['name'], call['arguments'])
          if Js.truthy?(m)
            proof = pca_call_of(agent.act(m['verb'], m['resource'], call['arguments']))
            headers = ((init || {})['headers'] || {}).merge(proof['headers'])
            res = fetch.call(url, (init || {}).merge('headers' => headers))
            ct = begin
              h = res.respond_to?(:headers) ? res.headers : nil
              h.nil? ? '' : (h['content-type'] || h['Content-Type'] || '')
            rescue StandardError
              ''
            end
            content = { 'tool' => call['name'], 'stream' => url.to_s }
            if !ct.to_s.match?(/event-stream/i) && res.respond_to?(:text)
              begin
                content = res.text
              rescue StandardError # unreadable: keep the origin-only record
                nil
              end
            end
            record_tool_result(agent, call['name'], content)
            return res
          end
        end
        fetch.call(url, init)
      end
    end
  end
end
