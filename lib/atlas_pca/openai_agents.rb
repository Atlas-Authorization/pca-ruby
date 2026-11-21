# frozen_string_literal: true

# OpenAI Agents SDK guard for Proof-Carrying Authority (the TypeScript reference, @atlasauth/pca-openai-agents). Duck-typed: no SDK
# gem is required or loaded. A tool is a Hash (String or Symbol keys) or an object that exposes a name and either
# on_invoke_tool(ctx, json_text) or execute(input, run_context). Options are String-keyed snake_case Hashes.
#
# * with_pca_tool / pca_tools: a tool call first REQUIRES a proof-carrying action (found in the run context), VERIFIES it (fail
#   closed: PcaToolDenied, which the SDK reports to the model as a tool error) and only then runs the original.
#   Default mode 'full': 'authorize' (an AuthorizeOptions or a Hash of its members) plus 'resolve_grant' run the whole pipeline: the
#   input must hash to the signed params, grant limits, revocation and single use. mode 'signature-only' with 'verify' checks only the
#   signature, chain, audience and window, which does NOT prove the grant permits the call.
# * PcaGuardrail (pca_input_guardrail, pca_tool_guard): signature-only pre-filters that trip when the run or tool call carries no
#   valid proof. #execute returns the plain {tripwire_triggered, output_info} Hash; wrap it in your SDK's guardrail object.
# * step-up: review_tool_call, pending_step_ups, pca_needs_approval, with_approval map a risky tool to the SDK's needs_approval so
#   the run interrupts for a guardian / human co-sign.
# * attach_pca: the agent side, a tool whose every call is signed first (like the other framework adapters).
#
# Differences from the reference: the grant-form verify {'grant' => ...} has no audience opt-out (a nil audience is refused: pass a
# callable verify to accept any audience), no 'hooks', and its enforce_freshness / enforce_taint belong to authorize here; the full
# mode takes 'authorize' and 'resolve_grant' where the reference takes one options object; review_tool_call takes the 'review' callable
# (the agent's review of an intended action) because the Ruby agent has no built-in step-up review.
require 'json'
require_relative 'adapters'
require_relative 'authorize'
require_relative 'fetch'
require_relative 'gateway'
require_relative 'js_compat'

module AtlasPca
  module OpenaiAgents
    A = Adapters

    # A guarded tool refused to run. kind: missing | malformed | verify | binding | policy | replay | revoked | config.
    class PcaToolDenied < StandardError
      attr_reader :verb, :kind, :checks

      def initialize(message, verb, kind, checks = nil)
        super("PCA tool denied (#{kind}) for #{Js.string(verb)}: #{message}")
        @verb = verb
        @kind = kind
        @checks = checks
      end
    end

    module_function

    # ---- proof sources -------------------------------------------------------------------------------------------------

    def get(o, k) = A.get(o, k)

    def record?(v) = !(v.nil? || v.is_a?(String) || v == true || v == false || v.is_a?(Numeric) || v.is_a?(Symbol))

    def first(*vals) = vals.find { |v| !v.nil? }

    def proof_from_bag(bag)
      return nil unless record?(bag)

      direct = first(get(bag, 'pca'), get(bag, 'pcaProof'), get(bag, 'pca_proof'))
      direct.is_a?(String) ? direct : nil
    end

    # The encoded PCActn from run_context.context (pca / pcaProof / pca_proof), then from run_context itself.
    def proof_from_run_context(_input, run_context)
      inner = proof_from_bag(get(run_context, 'context'))
      inner.nil? ? proof_from_bag(run_context) : inner
    end

    # The call's provenance bundle: pcaProvenance / pca_provenance / PCA-Provenance on the context, then on the run context.
    def provenance_from_run_context(_input, run_context)
      [get(run_context, 'context'), run_context].each do |bag|
        next unless record?(bag)

        v = first(get(bag, 'pcaProvenance'), get(bag, 'pca_provenance'), get(bag, 'PCA-Provenance'))
        return v unless v.nil?
      end
      nil
    end

    # A proof source reading a PCA-Action header value from a headers-like Hash on the tool input.
    def proof_from_input_headers(field = 'headers', header = 'PCA-Action')
      lambda do |input, _run_context = nil|
        next nil unless record?(input)

        bag = get(input, field)
        next nil unless record?(bag)

        v = get(bag, header)
        v.is_a?(String) ? v : nil
      end
    end

    # Guardrail default: the proof from the run context passed as args['context'].
    def guardrail_proof_from_context(args)
      outer = get(args, 'context')
      inner = record?(outer) ? get(outer, 'context') : nil
      p = proof_from_bag(inner)
      p.nil? ? proof_from_bag(outer) : p
    end

    # A provenance bundle from an object, a JSON text or a base64url header value; nil when it is neither.
    def provenance_from(v)
      return nil if v.nil?
      return v if record?(v)
      return nil unless v.is_a?(String) && !v.empty?

      begin
        AtlasPca.parse_json(v, any_top: true)
      rescue StandardError # try the header form
        text = AtlasPca.decode_pca_header(v)
        begin
          text.nil? ? nil : AtlasPca.parse_json(text, any_top: true)
        rescue StandardError
          nil
        end
      end
    end

    # ---- the proof pipeline --------------------------------------------------------------------------------------------

    def to_pcactn(raw)
      return raw if raw.is_a?(Hash)
      raise TypeError, 'the proof is neither a PCActn object nor encoded text' unless raw.is_a?(String)

      begin
        Gateway.decode_pcactn(raw)
      rescue StandardError # a header value is base64url of the JSON
        text = AtlasPca.decode_pca_header(raw)
        raise ArgumentError, 'the proof is not JSON and not a strict base64url header value' if text.nil?

        Gateway.decode_pcactn(text)
      end
    end

    def verb_of(p) = get(get(p, 'action'), 'verb')

    def run_verify(verify, pcactn, audience)
      return verify.call(pcactn) if verify.respond_to?(:call)
      return { 'allow' => false, 'checks' => {}, 'reason' => 'no verifier configured' } unless verify.is_a?(Hash) && get(verify, 'grant').is_a?(Hash)

      now = get(verify, 'now')
      now = now.call if now.respond_to?(:call)
      kw = {}
      %w[authorized_plan_roots allowed_suites pq_pins].each { |k| kw[k.to_sym] = get(verify, k) unless get(verify, k).nil? }
      AtlasPca.verify_pcactn(pcactn, get(verify, 'grant'), now: now.nil? ? wall_clock : now, audience: audience,
                                                              insecure_skip_plan_root_check: get(verify, 'insecure_skip_plan_root_check') == true, **kw)
    end

    def wall_clock = (Time.now.to_f * 1000).to_i

    # Decode, bind to verb, then verify (or run the full policy). Returns {pcactn:, result:} or raises PcaToolDenied.
    def assert_proof(raw, verify, audience, verb, label, full = nil)
      raise PcaToolDenied.new('no proof-carrying action present on the call', label, 'missing') if raw.nil?

      begin
        pcactn = to_pcactn(raw)
      rescue StandardError => e
        raise PcaToolDenied.new("proof could not be decoded: #{e.message}", label, 'malformed')
      end
      got = verb_of(pcactn)
      raise PcaToolDenied.new("proof is for '#{Js.string(got)}', not this tool's '#{verb}'", got.nil? ? label : got, 'binding') if !verb.nil? && got != verb

      unless full.nil?
        d = full.call(pcactn)
        unless d['allow']
          raise PcaToolDenied.new(d['reason'], got.nil? ? label : got, d['kind'] == 'authn' ? 'verify' : d['kind'], d['checks'])
        end

        return { pcactn: pcactn, result: { 'allow' => true, 'checks' => d['checks'] } }
      end
      result = run_verify(verify, pcactn, audience)
      unless get(result, 'allow')
        reason = get(result, 'reason')
        raise PcaToolDenied.new(reason.nil? ? 'verification failed' : reason, got.nil? ? label : got, 'verify', get(result, 'checks'))
      end
      { pcactn: pcactn, result: result }
    end

    # authorize (an AuthorizeOptions, or an object with #run) for one call: {allow, kind, reason, checks}.
    def run_authorize(authorize, pcactn, op, audience, resolve_grant, now, bundle)
      operation = op.reject { |k, _| k == 'provenance' }
      if authorize.is_a?(AuthorizeOptions)
        Fetch.authorize_with(authorize, pcactn, operation: operation, audience: audience, resolve_grant: resolve_grant, now: now,
                                                provenance: authorize.provenance, provenance_bundle: bundle)
      else
        authorize.run(pcactn, operation: operation, audience: audience, resolve_grant: resolve_grant, now: now, provenance: bundle)
      end
    end

    # Binding to the operation, then authorize (replay, revocation, limits): the decision {allow, kind, reason, checks}.
    def authorize_execution(authorize, resolve_grant, audience, pcactn, op, now)
      a = get(pcactn, 'action')
      verb = get(a, 'verb')
      res = get(a, 'resource')
      if verb != op['verb'] || (!op['resource'].nil? && res != op['resource'])
        want = op['resource'].nil? ? op['verb'] : "#{op['verb']} on #{op['resource']}"
        return { 'allow' => false, 'kind' => 'binding', 'reason' => "the proof is for #{Js.string(verb)} on #{Js.string(res)}, but this call is #{want}" }
      end
      begin
        clock = now.respond_to?(:call) ? now.call : now
        r = run_authorize(authorize, pcactn, op, audience, resolve_grant, clock.nil? ? wall_clock : clock, op['provenance'])
      rescue StandardError => e # fail closed
        return { 'allow' => false, 'kind' => 'policy', 'reason' => "authorization error (fail closed): #{e.class.name.split('::').last}" }
      end
      checks = (get(r, 'checks') || {}).dup
      return { 'allow' => true, 'checks' => checks } if get(r, 'allow')

      kind = if Js.truthy?(get(r, 'missing')) && !Array(get(r, 'missing')).empty? then 'config'
             elsif get(r, 'status') == 401 then 'authn'
             elsif checks['revocation'] == 'fail' then 'revoked'
             elsif checks['replay'] == 'fail' then 'replay'
             else 'policy'
             end
      { 'allow' => false, 'kind' => kind, 'reason' => Js.truthy?(get(r, 'reason')) ? get(r, 'reason') : 'denied', 'checks' => checks }
    end

    # The authorize option as something that can run: an AuthorizeOptions, a Hash of its members, or an object with #run.
    def authorize_runner(auth)
      return auth if auth.is_a?(AuthorizeOptions) || auth.respond_to?(:run)
      return nil unless auth.is_a?(Hash)

      AuthorizeOptions.new(**auth.to_h { |k, v| [k.to_sym, v] })
    end

    # nil for signature-only mode, else the full-policy check ->(pcactn, input, run_context) { decision }.
    def full_policy(options)
      auth = options['authorize']
      mode = options['mode'].nil? ? 'full' : options['mode']
      raise TypeError, "with_pca_tool: unknown mode '#{Js.string(mode)}'" unless %w[full signature-only].include?(mode)

      if mode == 'signature-only'
        raise TypeError, "with_pca_tool: `authorize` is the full mode; drop it, or drop mode: 'signature-only'" unless auth.nil?
        raise TypeError, "with_pca_tool: mode 'signature-only' needs `verify`" if options['verify'].nil?

        return nil
      end
      if auth.nil?
        raise TypeError, "with_pca_tool: pass `authorize` (full policy, the default mode), or set mode: 'signature-only' with `verify` to check the signature only"
      end
      unless options['verify'].nil?
        raise TypeError, "with_pca_tool: `verify` checks the signature only: set mode: 'signature-only' to use it, and drop `authorize`"
      end

      audience = options['audience'].is_a?(String) ? options['audience'] : nil
      resolve_grant = options['resolve_grant']
      missing = AtlasPca.missing_authorize_components(audience: audience, resolve_grant: resolve_grant, state_store: get(auth, 'state_store'),
                                                      is_revoked: get(auth, 'is_revoked'))
      operation = options['operation']
      verb = options['verb']
      resource = options['resource']
      missing << "operation (or the guard's verb and resource)" if operation.nil? && (verb.nil? || resource.nil?)
      runner = missing.empty? ? authorize_runner(auth) : nil
      missing << 'authorize.run' if missing.empty? && runner.nil?
      raise TypeError, "with_pca_tool: full policy mode is missing #{missing.join(', ')}" unless missing.empty?

      prov = options['provenance'] || method(:provenance_from_run_context)
      now = options['now']
      lambda do |pcactn, input, run_context|
        op = if operation.nil?
               { 'verb' => verb, 'resource' => resource, 'params' => input.is_a?(Hash) ? input : {} }
             else
               operation.call(input, run_context).to_h { |k, v| [k.to_s, v] }
             end
        if op['provenance'].nil?
          bundle = provenance_from(prov.call(input, run_context))
          op['provenance'] = bundle unless bundle.nil?
        end
        authorize_execution(runner, resolve_grant, audience, pcactn, op, now)
      end
    end

    # ---- the execution guard -------------------------------------------------------------------------------------------

    def parse_args(raw)
      return raw unless raw.is_a?(String)

      begin
        AtlasPca.parse_json(raw, any_top: true)
      rescue StandardError
        nil
      end
    end

    # The callable member `name` of a tool (a Hash entry or a method), or nil.
    def callable_of(tool, name)
      if tool.is_a?(Hash)
        c = tool.key?(name) ? tool[name] : tool[name.to_sym]
        c.respond_to?(:call) ? c : nil
      elsif !tool.nil? && tool.respond_to?(name)
        tool.method(name)
      end
    end

    # A copy of tool with the given callable members replaced (a Hash is merged; an object is cloned with singleton methods).
    def with_attrs(tool, attrs)
      return tool.merge(attrs.transform_keys(&:to_s)) if tool.is_a?(Hash)

      copy = tool.clone(freeze: false)
      attrs.each { |k, fn| copy.define_singleton_method(k) { |*args, **kw| fn.call(*args, **kw) } }
      copy
    end

    # A copy of tool whose every call first requires and verifies a proof (see the file header); every other member is kept.
    #
    # Options: 'mode' ('full' default | 'signature-only'), 'verify' (a callable ->(pcactn) { {allow, reason?, checks?} } or a Hash
    # {'grant' => ..., 'now'?, 'authorized_plan_roots'?, 'allowed_suites'?, 'pq_pins'?, 'insecure_skip_plan_root_check'?}),
    # 'authorize' (AuthorizeOptions or a Hash of its members) with 'resolve_grant', 'operation' (->(input, run_context)
    # { verb, resource, params }) or the guard's 'verb' + 'resource', 'audience' (a String; a nil audience accepts any audience with a
    # callable verify; omitted refuses), 'require' (->(input, run_context) proof source), 'provenance' (->(input, run_context)),
    # 'recorder' (a provenance recorder), 'on_deny' (->(error, input)), 'on_verified' (->(result, pcactn, input)), 'now'.
    def with_pca_tool(tool, options = {})
      source = options['require'] || method(:proof_from_run_context)
      label = first(options['verb'], get(tool, 'name'), '(tool)')
      full = full_policy(options)
      verify = options['verify']
      if verify.is_a?(Hash) && (get(verify, 'enforce_freshness') || get(verify, 'enforce_taint'))
        raise TypeError, 'with_pca_tool: enforce_freshness / enforce_taint are authorize options in this SDK (use mode full)'
      end

      has_audience = options.key?('audience')
      audience = options['audience']
      on_deny = options['on_deny']
      on_verified = options['on_verified']
      recorder = options['recorder']

      guarded = lambda do |input, run_context, call|
        ctx = run_context.nil? ? {} : run_context
        raw = source.call(input, ctx)
        begin
          verified = assert_proof(raw, verify, has_audience ? audience : nil, options['verb'], label, full ? ->(p) { full.call(p, input, ctx) } : nil)
        rescue PcaToolDenied => e
          on_deny&.call(e, input)
          raise
        end
        on_verified&.call(verified[:result], verified[:pcactn], input)
        out = call.call
        if recorder
          v = verb_of(verified[:pcactn])
          recorder.tool(Js.string(v.nil? ? label : v), out)
        end
        out
      end

      orig_invoke = callable_of(tool, 'on_invoke_tool')
      unless orig_invoke.nil?
        return with_attrs(tool, 'on_invoke_tool' => lambda { |ctx, raw = nil, *rest, **kw|
          guarded.call(parse_args(raw), ctx, -> { orig_invoke.call(ctx, raw, *rest, **kw) })
        })
      end

      orig_exec = callable_of(tool, 'execute')
      with_attrs(tool, 'execute' => lambda { |input, run_context = nil|
        call = lambda do
          raise 'with_pca_tool: the wrapped tool has no execute()' if orig_exec.nil?

          orig_exec.call(input, run_context)
        end
        guarded.call(input, run_context, call)
      })
    end

    def merge_options(base, over)
      return base.dup if over.nil? || over.empty?

      own_mode = !over['authorize'].nil?
      out = {}
      # a per-tool authorize or verify replaces the shared mode (the two are exclusive)
      src, keys = if own_mode then [over, %w[authorize resolve_grant operation]]
                  elsif !over['verify'].nil? then [over, %w[verify]]
                  else [base, %w[verify authorize resolve_grant operation]]
                  end
      keys.each { |k| out[k] = src[k] unless src[k].nil? }
      mode = over['mode']
      mode = own_mode ? nil : base['mode'] if mode.nil?
      out['mode'] = mode unless mode.nil?
      %w[require verb resource on_deny on_verified provenance recorder now].each do |k|
        v = first(over[k], base[k])
        out[k] = v unless v.nil?
      end
      if over.key?('audience') then out['audience'] = over['audience']
      elsif base.key?('audience') then out['audience'] = base['audience']
      end
      out
    end

    # Guard a {name => tool} Hash (or an Array of tools, keyed by their name) with shared options. options['per'][name] overrides them
    # for one tool, options['only'] limits the guarded set; every other tool passes through unchanged (the same object).
    def pca_tools(tools, options = {})
      per = options['per']
      only = options['only']
      shared = options.reject { |k, _| %w[per only].include?(k) }
      only_set = only.nil? ? nil : only.to_a
      one = lambda do |name, t|
        next t if !only_set.nil? && !only_set.include?(name)

        with_pca_tool(t, merge_options(shared, (per || {})[name]))
      end
      return tools.to_h { |k, t| [k, one.call(k, t)] } if tools.is_a?(Hash)

      tools.map { |t| one.call(get(t, 'name'), t) }
    end

    # ---- guardrails ----------------------------------------------------------------------------------------------------

    # A signature-only proof gate. #execute(args) returns {'tripwire_triggered', 'output_info'}.
    class PcaGuardrail
      attr_reader :name

      def initialize(name, source, verify, audience, verb, label, has_audience)
        @name = name
        @source = source
        @verify = verify
        @audience = audience
        @verb = verb
        @label = label
        @has_audience = has_audience
      end

      def execute(args)
        v = OpenaiAgents.assert_proof(@source.call(args), @verify, @has_audience ? @audience : nil, @verb, @label)
      rescue PcaToolDenied => e
        info = { 'kind' => e.kind, 'verb' => e.verb, 'reason' => e.message }
        info['checks'] = e.checks unless e.checks.nil?
        { 'tripwire_triggered' => true, 'output_info' => info }
      else
        { 'tripwire_triggered' => false, 'output_info' => { 'verb' => OpenaiAgents.verb_of(v[:pcactn]) } }
      end

      # The input-guardrail function shape: (context, agent, input) -> the plain result Hash.
      def input_guardrail_function(context, agent, input) = execute({ 'agent' => agent, 'input' => input, 'context' => context })

      # The tool-guardrail function shape: data with a context carrying tool_arguments -> the plain result Hash.
      def tool_guardrail_function(data)
        ctx = OpenaiAgents.get(data, 'context')
        execute({ 'agent' => OpenaiAgents.get(data, 'agent'), 'input' => OpenaiAgents.get(ctx, 'tool_arguments'), 'context' => ctx })
      end
    end

    def guardrail(default, label, options)
      has_audience = options.key?('audience')
      verb = options['verb']
      PcaGuardrail.new(options['name'] || default, options['require'] || method(:guardrail_proof_from_context), options['verify'],
                       has_audience ? options['audience'] : nil, verb, verb.nil? ? label : verb, has_audience)
    end

    # An input guardrail: trips at the top of a run when the run context carries no valid proof. Options: 'verify' (required),
    # 'require', 'audience', 'verb', 'name'.
    def pca_input_guardrail(options = {}) = guardrail('pca-input-guardrail', '(run)', options)

    # The same gate scoped to a tool call; prefer with_pca_tool with 'authorize' for the real check.
    def pca_tool_guard(options = {}) = guardrail('pca-tool-guard', '(run)', options)

    # ---- step-up -------------------------------------------------------------------------------------------------------

    # Review one intended tool call: options['intent'] ->(tool, input) maps it to {verb, resource, params?} (nil = unguarded, auto),
    # then options['review'] ->(agent, verb, resource, params, opts) returns {kind: 'auto'}, {kind: 'deny', reason} or
    # {kind: 'step_up', request}. Other options: 'standing', 'goal', 'now', 'renderer', 'insecure_unbound_approval'.
    # Returns {'tool', 'review'}.
    def review_tool_call(agent, tool, input, options = {})
      mapped = options['intent'].call(tool, input)
      return { 'tool' => tool, 'review' => { 'kind' => 'auto' } } if mapped.nil?

      review = options['review']
      raise TypeError, "review_tool_call: pass `review`, the agent's review of an intended action" if review.nil?

      params = get(mapped, 'params')
      opts = %w[now goal standing renderer insecure_unbound_approval].to_h { |k| [k, options[k]] }.reject { |_, v| v.nil? }
      { 'tool' => tool, 'review' => review.call(agent, get(mapped, 'verb'), get(mapped, 'resource'), params.nil? ? input : params, opts) }
    end

    # The step-up requests among review_tool_call results (auto / deny filtered out).
    def pending_step_ups(reviews)
      reviews.select { |r| get(get(r, 'review'), 'kind') == 'step_up' }.map { |r| { 'tool' => get(r, 'tool'), 'request' => get(get(r, 'review'), 'request') } }
    end

    REVIEW_KEYS = %w[intent review standing goal now renderer insecure_unbound_approval].freeze

    # The SDK's needs_approval callback ->(run_context, input, call_id = nil) { bool } from risk review: auto -> false; step-up not
    # yet co-signed -> options['on_step_up'].call({tool, request}) and true (the run interrupts); an already approved step-up (options
    # ['approved'].call(request)) -> false; deny -> true unless 'deny_needs_approval' is false (the approver then rejects it).
    def pca_needs_approval(agent, options = {})
      name = options['tool_name'].nil? ? '(tool)' : options['tool_name']
      approved = options['approved']
      on_step_up = options['on_step_up']
      deny_needs_approval = options['deny_needs_approval'].nil? ? true : options['deny_needs_approval']
      review_opts = options.select { |k, _| REVIEW_KEYS.include?(k) }
      lambda do |_run_context, input, _call_id = nil|
        r = review_tool_call(agent, name, input, review_opts)['review']
        case get(r, 'kind')
        when 'auto' then false
        when 'deny' then deny_needs_approval
        else
          next false if approved && approved.call(get(r, 'request'))

          on_step_up&.call({ 'tool' => name, 'request' => get(r, 'request') })
          true
        end
      end
    end

    # A copy of tool with needs_approval from PCA risk review (the tool's name seeds the intent lookup unless 'tool_name' is given).
    def with_approval(tool, agent, options = {})
      name = options['tool_name']
      if name.nil?
        n = get(tool, 'name')
        name = Js.truthy?(n) ? n : '(tool)'
      end
      with_attrs(tool, 'needs_approval' => pca_needs_approval(agent, options.merge('tool_name' => name)))
    end

    # ---- agent side ----------------------------------------------------------------------------------------------------

    # A copy of an SDK tool whose every call first builds a signed PCActn from its JSON arguments (fast-fail PcaDenied on a failing
    # dry run), hands it to on_proof.call(pca, params) and runs the original. Arguments that are not a JSON object are refused.
    def attach_pca(agent, verb, resource, tool, on_proof: nil, fail_fast: true)
      orig = callable_of(tool, 'on_invoke_tool') or raise TypeError, 'attach_pca: the tool has no on_invoke_tool'
      with_attrs(tool, 'on_invoke_tool' => lambda { |ctx, raw = nil, *rest, **kw|
        params = parse_args(raw)
        raise TypeError, 'attach_pca: tool arguments must be a JSON object' unless params.is_a?(Hash)

        run = lambda do |p, pca|
          on_proof&.call(pca, p)
          orig.call(ctx, raw, *rest, **kw)
        end
        A.guard(agent, verb, resource, run, fail_fast: fail_fast).call(params)
      })
    end

    # Wrap a whole set of tools (the reference's withPCATools): `tools` is a Hash of name => tool, `specs` a Hash of name => {'verb',
    # 'resource' (a String or ->(args) { String }), 'fail_fast'? (default true), 'on_proof'? ->(pca, args)}; each listed tool is wrapped
    # with attach_pca, unlisted tools pass through. A spec naming another audience than the agent's is refused (an agent signs for its own).
    def with_pca_tools(agent, tools, specs)
      raise TypeError, 'with_pca_tools: tools must be a Hash of name => tool' unless tools.is_a?(Hash)

      specs = {} if specs.nil?
      tools.to_h do |name, tool|
        spec = specs[name] || specs[name.to_s] || (name.respond_to?(:to_sym) ? specs[name.to_sym] : nil)
        next [name, tool] if spec.nil?

        spec = spec.to_h { |k, v| [k.to_s, v] }
        raise ArgumentError, "with_pca_tools: tool '#{name}' names another audience than the agent's" if !spec['aud'].nil? && spec['aud'] != agent.aud

        [name, attach_pca(agent, spec['verb'], spec['resource'], tool, on_proof: spec['on_proof'], fail_fast: spec['fail_fast'] != false)]
      end
    end
  end
end
