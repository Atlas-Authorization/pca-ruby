# frozen_string_literal: true

# PROVENANCE BY DEFAULT (argument provenance): an agent cannot be steered by injected content into choosing who, where or how
# much. Port of the TypeScript reference arg-provenance.ts (decideArgProvenance, provLeaves, occursAsToken, isReadOnlyAction,
# provEnvelopeError, createProvenanceRecorder, principalDirectProvenance) and of the gate authorize runs (`provenance_flow`).
#
# A MEDIATOR (the agent harness, a gateway, an MCP client: whatever sees the bytes enter the model's context and holds a key the
# model cannot reach) appends one signed receipt per context segment to a per-session hash chain: the principal's own message
# (`principal`), a tool result (`tool`), a retrieved document (`retrieval`), a fetched page (`web`) and finally the action the
# model chose (`action`, bound to the exact operation digest). The verifier re-derives every label from that chain; nothing
# the agent writes can lower one. A sensitive action (anything not confirmed read-only; an unknown action is sensitive) whose
# choice or any argument does not derive from the principal is `escalate`; a forged or malformed chain is `deny`.
#
# Not to be confused with the K9 build-provenance gate (provenance_gate.rb) or the Intent Layer v2 rule 17 check `provenance`:
# this check is named `provenance_flow`.
#
# Inputs and outputs are String-keyed Hashes with the TypeScript field names (snake_case where the shared vectors use it:
# `principal_plan`, `principal_control`, `observed`). Token matching runs over UTF-8 bytes: a byte >= 0x80 maps to a UTF-16 code
# unit >= 0x80 (both word characters) and a valid UTF-8 needle only matches at character boundaries, so the result equals the
# reference's UTF-16 scan. Every decide function is total: malformed input fails closed.
require 'json'
require 'securerandom'

module AtlasPca
  PROV_RECEIPT_DOMAIN = "atlas-pca/prov-receipt/v1\x00"
  PROV_RECEIPT_REF_DOMAIN = 'atlas-pca/prov-receipt-ref/v1'
  PROV_ACTION_DOMAIN = 'atlas-pca/prov-action/v1'
  # Request header carrying a bundle (base64url of its JSON); the JSON body member is `pca_provenance`.
  PROV_HEADER = 'PCA-Provenance'
  PROV_RACK_HEADER = 'HTTP_PCA_PROVENANCE'
  MAX_PROV_RECEIPTS = 256
  MAX_PROV_CONTENT_BYTES = 65_536
  MAX_PROV_LEAVES = 4096
  MAX_PROV_DEPTH = 32
  MAX_PROV_ENVELOPE_PINS = 16
  PROV_ORIGINS = %w[principal tool retrieval web action].freeze
  # The label lattice: trusted < first_party < tool < web < agent.
  PROV_LEVELS = %w[trusted first_party tool web agent].freeze
  PROV_RANK = PROV_LEVELS.each_with_index.to_h.freeze
  # The level a segment of each origin carries (`action` contributes nothing: it is the model's own output).
  PROV_ORIGIN_LEVEL = { 'principal' => 'trusted', 'tool' => 'tool', 'retrieval' => 'tool', 'web' => 'web' }.freeze
  PROV_FLOORS = %w[first_party tool agent].freeze
  # Traits a read-only action may carry and still be non-sensitive.
  READ_SAFE_TRAITS = %w[pca.financial_data_read pca.pii_access pca.regulated_data].freeze
  PROV_RECEIPT_FIELDS = %w[v kind mediator kid session seq prev origin source content_digest issued_at sig].freeze
  PROV_CONTENT_KEY_RE = /\A(?:0|[1-9][0-9]{0,8})\z/

  module_function

  def prov_join(a, b) = PROV_RANK[a] >= PROV_RANK[b] ? a : b

  def prov_sort(xs) = xs.uniq.sort_by(&:b)

  # The digest an `action` receipt binds: the exact operation (verb, resource, params).
  def prov_action_digest(op)
    wb_hash({ 'd' => PROV_ACTION_DOMAIN, 'verb' => op['verb'], 'resource' => op['resource'], 'params' => op['params'] })
  end

  # Content address of a receipt (signature included).
  def prov_receipt_ref(r) = wb_artifact_ref(PROV_RECEIPT_REF_DOMAIN, 'r', r)

  # A well-formed mediator pin {mediator, kid, pk, pq_pk?}?
  def prov_mediator_pin?(k)
    k.is_a?(Hash) && wb_closed_members(k, %w[mediator kid pk], ['pq_pk']).nil? && wb_bounded?(k['mediator'], 256) &&
      wb_bounded?(k['kid'], 64) && wb_digest?(k['pk']) && wb_pin_pq_ok?(wb_get(k, 'pq_pk'))
  end

  # Wire validation of one receipt; nil = well-formed.
  def prov_receipt_wire_error(r)
    return 'a receipt must be an object' unless r.is_a?(Hash)

    m = wb_closed_members(r, PROV_RECEIPT_FIELDS, WB_SUITE_MEMBERS, 'receipt')
    return m if m
    return 'a receipt must be {v: 1, kind: "pca-prov"}' unless wb_strict_eq?(r['v'], 1) && r['kind'] == 'pca-prov'
    return "'mediator' must be a non-empty string (<= 256 bytes)" unless wb_bounded?(r['mediator'], 256)
    return "'kid' must be a non-empty string (<= 64 bytes)" unless wb_bounded?(r['kid'], 64)
    return "'session' must be canonical base64url (32 bytes)" unless wb_digest?(r['session'])
    return "'seq' must be a non-negative safe integer" unless wb_safe_int?(r['seq']) && r['seq'] >= 0
    return "'prev' must be null or canonical base64url (32 bytes)" unless r['prev'].nil? || wb_digest?(r['prev'])
    return "'origin' must be one of #{PROV_ORIGINS.join(', ')}" unless PROV_ORIGINS.include?(r['origin'])
    return "'source' must be a non-empty string (<= 256 bytes)" unless wb_bounded?(r['source'], 256)
    return "'content_digest' must be canonical base64url (32 bytes)" unless wb_digest?(r['content_digest'])
    return "'issued_at' must be a non-negative safe integer" unless wb_safe_int?(r['issued_at']) && r['issued_at'] >= 0
    return "'sig' must be a string" unless r['sig'].is_a?(String)

    wb_artifact_suite_error(r)
  end

  # Validate action facts {effects?, traits?, params?}; nil = well-formed.
  def prov_action_info_error(a)
    return 'action info must be an object' unless a.is_a?(Hash)

    m = wb_closed_members(a, [], %w[effects traits params], 'action info')
    return m if m

    %w[effects traits].each do |k|
      v = wb_get(a, k)
      next if v.equal?(WB_UNDEF)
      return "action info '#{k}' must be a list of strings" unless v.is_a?(Array) && v.length <= 64 && v.all? { |x| wb_bounded?(x, 128) }
    end
    ps = wb_get(a, 'params')
    unless ps.equal?(WB_UNDEF)
      return "action info 'params' must be an object" unless ps.is_a?(Hash)

      wb_js_keys(ps).each do |k|
        return "action info param '#{k}' must map to first_party | tool | agent" unless wb_bounded?(k, 128) && PROV_FLOORS.include?(ps[k])
      end
    end
    nil
  end

  # Is an action with these facts non-sensitive (it only reads)? Unknown (nil) facts are sensitive.
  def read_only_action?(a)
    return false unless a.is_a?(Hash) && a['effects'].is_a?(Array) && !a['effects'].empty?
    return false unless a['effects'].all? { |e| e == 'read' }

    traits = a.key?('traits') ? a['traits'] : []
    traits.is_a?(Array) && traits.all? { |t| READ_SAFE_TRAITS.include?(t) }
  end

  def prov_word_byte?(c) = (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 95 || c >= 0x80

  # Does `needle` occur in `text` as a whole token? Exact, case-sensitive, no normalization; an empty needle never occurs.
  def occurs_as_token(text, needle)
    return false unless text.is_a?(String) && needle.is_a?(String) && !needle.empty?

    t = text.b
    n = needle.b
    head_word = prov_word_byte?(n.getbyte(0))
    tail_word = prov_word_byte?(n.getbyte(n.bytesize - 1))
    i = t.index(n)
    until i.nil?
      ok_b = !head_word || i.zero? || !prov_word_byte?(t.getbyte(i - 1))
      e = i + n.bytesize
      ok_a = !tail_word || e == t.bytesize || !prov_word_byte?(t.getbyte(e))
      return true if ok_b && ok_a

      i = t.index(n, i + 1)
    end
    false
  end

  # The text of every leaf of a value (strings as is, other scalars in strict canonical form, object keys included); nil when
  # too deep, too large or not canonical.
  def prov_leaves(v)
    out = []
    prov_walk(v, 0, out) ? out : nil
  end

  def prov_walk(x, depth, out)
    return false if depth > MAX_PROV_DEPTH || out.length > MAX_PROV_LEAVES

    case x
    when String then out << x
    when Array then x.each { |y| return false unless prov_walk(y, depth + 1, out) }
    when Hash
      wb_js_keys(x).each do |k|
        out << k
        return false unless prov_walk(x[k], depth + 1, out)
      end
    else
      begin
        out << canonicalize(wb_jsnorm(x))
      rescue StandardError
        return false
      end
    end
    out.length <= MAX_PROV_LEAVES
  end

  def prov_operation_ok?(op)
    op.is_a?(Hash) && wb_bounded?(op['verb'], 256) && op['resource'].is_a?(String) && op['params'].is_a?(Hash)
  end

  def prov_bad(code, reason) = { 'code' => code, 'reason' => reason }

  # A caller's operation (String or Symbol keys) as {verb, resource, params} with a private canonical copy of the params.
  def prov_op_of(op, what)
    verb = op.is_a?(Hash) ? arg_member(op, 'verb') : nil
    resource = op.is_a?(Hash) ? arg_member(op, 'resource') : nil
    params = op.is_a?(Hash) ? arg_member(op, 'params') : nil
    raise ArgumentError, "#{what}: the operation needs verb, resource and params" unless wb_bounded?(verb, 256) && resource.is_a?(String) && params.is_a?(Hash)

    { 'verb' => verb, 'resource' => resource, 'params' => params_copy(params) }
  end

  # Verify a bundle against the pins and the operation: the chain view, or a deny {code, reason}.
  def prov_verify_chain(bundle, op, pins)
    unverified = { 'verified' => false, 'context' => 'agent', 'path' => ['unlabelled'], 'texts' => [] }
    return unverified if bundle.nil? || bundle.equal?(WB_UNDEF)
    return prov_bad('malformed_bundle', 'the bundle must be an object') unless bundle.is_a?(Hash)

    m = wb_closed_members(bundle, %w[v kind receipts], ['contents'], 'bundle')
    return prov_bad('malformed_bundle', m) if m
    unless wb_strict_eq?(bundle['v'], 1) && bundle['kind'] == 'pca-provenance'
      return prov_bad('malformed_bundle', 'the bundle must be {v: 1, kind: "pca-provenance"}')
    end

    rs = bundle['receipts']
    unless rs.is_a?(Array) && !rs.empty? && rs.length <= MAX_PROV_RECEIPTS
      return prov_bad('malformed_bundle', "the bundle must hold 1..#{MAX_PROV_RECEIPTS} receipts")
    end

    rs.each_with_index do |r, i|
      e = prov_receipt_wire_error(r)
      return prov_bad('malformed_bundle', "receipt #{i}: #{e}") if e
    end
    contents = bundle.key?('contents') ? bundle['contents'] : {}
    return prov_bad('malformed_bundle', "'contents' must be an object") unless contents.is_a?(Hash)

    first = rs[0]
    rs.each_with_index do |r, i|
      return prov_bad('broken_chain', "receipt #{i} has seq #{wb_js_str(r['seq'])}") unless r['seq'] == i
      unless r['session'] == first['session'] && r['mediator'] == first['mediator'] && r['kid'] == first['kid']
        return prov_bad('broken_chain', "receipt #{i} belongs to another session or mediator")
      end
      linked = i.zero? ? r['prev'].nil? : r['prev'] == prov_receipt_ref(rs[i - 1])
      return prov_bad('broken_chain', "receipt #{i} does not link to its predecessor") unless linked
      return prov_bad('broken_chain', "receipt #{i} is older than its predecessor") if i.positive? && r['issued_at'] < rs[i - 1]['issued_at']
    end
    last = rs[-1]
    unless last['origin'] == 'action' && last['source'] == op['verb'] && last['content_digest'] == prov_action_digest(op)
      return prov_bad('unbound_action', 'the last receipt is not the action receipt of this operation')
    end

    wb_js_keys(contents).each do |k|
      text = contents[k]
      r = wb_re?(PROV_CONTENT_KEY_RE, k) ? rs[k.to_i] : nil
      return prov_bad('malformed_bundle', "contents '#{k}' does not name a principal receipt") if r.nil? || r['origin'] != 'principal'
      unless text.is_a?(String) && text.bytesize <= MAX_PROV_CONTENT_BYTES
        return prov_bad('malformed_bundle', "contents '#{k}' must be a string of at most #{MAX_PROV_CONTENT_BYTES} bytes")
      end

      d = begin
        wb_hash(text)
      rescue StandardError
        return prov_bad('content_mismatch', "contents '#{k}' is not canonical text")
      end
      return prov_bad('content_mismatch', "contents '#{k}' does not hash to its receipt") if d != r['content_digest']
    end

    pin = pins.find { |p| p['mediator'] == first['mediator'] && p['kid'] == first['kid'] }
    # a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top
    return unverified if pin.nil?

    rs.each_with_index do |r, i|
      return prov_bad('bad_signature', "receipt #{i} does not verify under the pinned mediator key") unless wb_verify_artifact_sig(PROV_RECEIPT_DOMAIN, r, pin)
    end
    before = rs[0...-1].reject { |r| r['origin'] == 'action' }
    context = before.empty? ? 'agent' : 'trusted'
    path = []
    before.each do |r|
      context = prov_join(context, PROV_ORIGIN_LEVEL[r['origin']])
      path << "#{r['origin']}:#{r['source']}" unless r['origin'] == 'principal'
    end
    path << 'unlabelled' if before.empty?
    { 'verified' => true, 'context' => context, 'path' => prov_sort(path), 'texts' => wb_js_keys(contents).map { |k| contents[k] } }
  end

  # The provenance decision for one operation. `input` (String keys): bundle (absent / nil = none), operation {verb, resource,
  # params}, mediators (pins), action (facts; absent = unknown = sensitive), principal_plan, principal_control, observed.
  # Steps, first failure wins: inputs, the bundle chain (deny on forgery), observations, control, labels, floors, decision.
  # Returns {outcome: pass|escalate|deny, code?, reason?, sensitive, verified, control, labels, tainted, path}. Never raises.
  def decide_arg_provenance(input)
    base = { 'sensitive' => true, 'verified' => false, 'control' => 'agent', 'labels' => {}, 'tainted' => [], 'path' => [] }
    deny = ->(code, reason) { base.merge('outcome' => 'deny', 'code' => code, 'reason' => reason) }
    begin
      return deny.call('malformed_config', 'input must be an object') unless input.is_a?(Hash)

      pins = input['mediators']
      unless pins.is_a?(Array) && pins.all? { |p| prov_mediator_pin?(p) }
        return deny.call('malformed_config', 'mediator pins must be a list of {mediator, kid, pk, pq_pk?}')
      end
      op = input['operation']
      return deny.call('malformed_operation', 'the operation needs a verb, a resource and a params object') unless prov_operation_ok?(op)

      action = wb_get(input, 'action')
      unless action.equal?(WB_UNDEF)
        e = prov_action_info_error(action)
        return deny.call('malformed_action', e) if e
      end
      obs = input['observed'].nil? ? [] : input['observed']
      obs_ok = obs.is_a?(Array) && obs.all? { |o| o.is_a?(Hash) && %w[tool retrieval web].include?(o['origin']) && wb_bounded?(o['source'], 256) }
      return deny.call('malformed_config', 'observations must be a list of {origin, source}') unless obs_ok

      sensitive = !read_only_action?(action.equal?(WB_UNDEF) ? nil : action)
      base['sensitive'] = sensitive
      ch = prov_verify_chain(wb_get(input, 'bundle'), op, pins)
      return deny.call(ch['code'], ch['reason']) if ch.key?('code')

      base['verified'] = ch['verified']
      context = ch['context']
      path = ch['path'].dup
      obs.each do |o|
        context = prov_join(context, PROV_ORIGIN_LEVEL[o['origin']])
        path << "#{o['origin']}:#{o['source']}"
      end
      base['path'] = prov_sort(path)
      plan = input['principal_plan'] == true
      control = plan || input['principal_control'] == true ? 'trusted' : context
      base['control'] = control
      labels = {}
      prov_sort(op['params'].keys).each do |p|
        if plan
          labels[p] = 'trusted'
          next
        end
        leaves = prov_leaves(op['params'][p])
        if leaves.nil?
          labels[p] = context
          next
        end
        l = 'trusted'
        leaves.each do |leaf|
          # a leaf the principal typed verbatim is the principal's choice whatever else the context held
          lv = context == 'trusted' || ch['texts'].any? { |t| occurs_as_token(t, leaf) } ? 'trusted' : context
          l = prov_join(l, lv)
        end
        labels[p] = l
      end
      base['labels'] = labels
      floors = action.is_a?(Hash) && action['params'].is_a?(Hash) ? action['params'] : {}
      tainted = labels.keys.select do |p|
        f = floors.key?(p) ? floors[p] : (sensitive ? 'first_party' : 'agent')
        PROV_RANK[labels[p]] > PROV_RANK[f]
      end
      base['tainted'] = prov_sort(tainted)
      # no segment origin maps to first_party, so a control label is trusted or untrusted
      bad_control = sensitive && control != 'trusted'
      return base.merge('outcome' => 'pass') if !bad_control && base['tainted'].empty?

      t = base['tainted']
      code = if bad_control && !t.empty? then 'untrusted_control_and_args'
             elsif bad_control then 'untrusted_control'
             else 'untrusted_args'
             end
      parts = []
      parts << "the choice of #{op['verb']} derives from untrusted content" if bad_control
      parts << "#{t.join(', ')} #{t.length == 1 ? 'derives' : 'derive'} from untrusted content" unless t.empty?
      where = base['path'].empty? ? '' : " [#{base['path'].join(', ')}]"
      base.merge('outcome' => 'escalate', 'code' => code, 'reason' => "#{parts.join('; ')}#{where}: the principal must confirm (prompt-injection path)")
    rescue StandardError, SystemStackError => e
      deny.call('malformed_config', "evaluation error (fail closed): #{e.class}")
    end
  end

  # The grant envelope member `provenance` {mode?: enforce | insecure_off, mediators?: Pin[] (<= 16)}; nil when well-formed.
  # `insecure_off` is the documented dangerous opt-out: injected content can then steer the grant's sensitive actions.
  def prov_envelope_error(p)
    return 'provenance must be an object' unless p.is_a?(Hash)

    m = wb_closed_members(p, [], %w[mode mediators], 'provenance')
    return m if m

    mode = wb_get(p, 'mode')
    return "provenance.mode must be 'enforce' or 'insecure_off'" unless mode.equal?(WB_UNDEF) || %w[enforce insecure_off].include?(mode)

    ms = wb_get(p, 'mediators')
    unless ms.equal?(WB_UNDEF) || (ms.is_a?(Array) && ms.length <= MAX_PROV_ENVELOPE_PINS && ms.all? { |k| prov_mediator_pin?(k) })
      return 'provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}'
    end

    nil
  end

  # The default bundle of a Rack request: header PCA-Provenance (strict unpadded base64url of strict JSON), else the JSON body
  # member `pca_provenance`. An unreadable header raises (the gate then denies); an unparsable body is no bundle.
  def default_provenance_bundle(env)
    raw = env[PROV_RACK_HEADER]
    unless raw.nil? || raw.empty?
      text = decode_pca_header(raw)
      raise Malformed, 'PCA-Provenance is not canonical base64url' if text.nil?

      return parse_json(text, any_top: true)
    end
    input = env['rack.input']
    return nil if input.nil?

    body = begin
      input.read
    ensure
      input.rewind if input.respond_to?(:rewind)
    end
    return nil if body.nil? || body.empty?

    obj = begin
      parse_json(body.dup.force_encoding('UTF-8'))
    rescue StandardError
      nil
    end
    obj.is_a?(Hash) ? obj['pca_provenance'] : nil
  end

  # The gate authorize runs as check `provenance_flow` (see AtlasPca.authorize `provenance:`). `opts` holds the verifier's
  # `mediators` (pins), `actions` (->(operation) { facts | nil }), `observed` (->(pcactn, operation, session) { [...] }) and
  # `bundle` (->(pcactn, operation) { bundle }, raising = unreadable); `bundle` given explicitly wins over opts['bundle'].
  # `flags` = {'plan' => bool, 'control' => bool}. Returns [status, reason] (status pass | fail | not-enforced).
  def provenance_flow_check(opts, grant, pcactn, op, bundle, flags)
    env = read_envelope(grant)
    pe = env.is_a?(Hash) && env.key?('provenance') ? env['provenance'] : WB_UNDEF
    unless pe.equal?(WB_UNDEF)
      e = prov_envelope_error(pe)
      return ['fail', "the grant's provenance member is malformed: #{e}"] if e
      # the principal's signed, documented-dangerous opt-out
      return ['not-enforced', nil] if pe['mode'] == 'insecure_off'
    end
    return ['fail', 'no operation is bound to this request (fail closed)'] unless op.is_a?(Hash) && op['verb'].is_a?(String) && op['resource'].is_a?(String)

    o = opts.is_a?(Hash) ? opts.to_h { |k, v| [k.to_s, v] } : {}
    if bundle.nil? && o['bundle'].respond_to?(:call)
      begin
        bundle = o['bundle'].call(pcactn, op)
      rescue StandardError
        return ['fail', 'the provenance bundle is unreadable (fail closed)']
      end
    end
    own = o['mediators'].nil? ? [] : o['mediators']
    pins = own.is_a?(Array) ? own + (pe.is_a?(Hash) && pe['mediators'].is_a?(Array) ? pe['mediators'] : []) : own
    action = WB_UNDEF
    begin
      action = o['actions'].call(op) if o['actions'].respond_to?(:call)
      action = WB_UNDEF if action.nil?
      session = bundle.is_a?(Hash) && bundle['receipts'].is_a?(Array) && bundle['receipts'][0].is_a?(Hash) ? bundle['receipts'][0]['session'] : nil
      observed = o['observed'].respond_to?(:call) ? o['observed'].call(pcactn, op, session.is_a?(String) ? session : nil) : []
    rescue StandardError
      return ['fail', 'the action facts or observations could not be read (fail closed)']
    end
    input = { 'bundle' => bundle, 'operation' => op, 'mediators' => pins, 'principal_plan' => flags['plan'] == true,
              'principal_control' => flags['control'] == true, 'observed' => observed }
    input['action'] = action unless action.equal?(WB_UNDEF)
    d = decide_arg_provenance(input)
    return ['pass', nil] if d['outcome'] == 'pass'

    ['fail', d['outcome'] == 'escalate' ? "escalate: #{d['reason']}" : "#{d['code']}: #{d['reason']}"]
  end

  # The mediator side: one recorder per agent session. Run it where the bytes enter the model's context (the harness that
  # builds the prompt, a gateway, an MCP client), with a key the model cannot reach, and pin `recorder.pin` at the verifier
  # (or name it in the grant envelope's `provenance.mediators`).
  #
  #   rec = AtlasPca::ProvenanceRecorder.new(mediator: 'my-harness', kid: 'k1', key: harness_key)
  #   rec.principal(user_message)            # TRUSTED
  #   rec.tool('crm.lookup', tool_output)     # UNTRUSTED
  #   bundle = rec.for_action(verb: 'email.send', resource: 'mail', params: { 'to' => 'bob@acme.example' })
  #   # send the bundle as header PCA-Provenance (AtlasPca.b64e of its canonical JSON) or body member pca_provenance
  class ProvenanceRecorder
    attr_reader :session, :pin

    # key: an AtlasPca::KeyPair (Ed25519, generated when absent); alg / pq: a PQ or hybrid suite (AtlasPca::PqKeyPair);
    # session: canonical base64url of 32 bytes (random when absent); now: ->() { epoch ms }.
    def initialize(mediator:, kid:, key: nil, session: nil, now: nil, alg: nil, pq: nil)
      unless AtlasPca.wb_bounded?(mediator, 256) && AtlasPca.wb_bounded?(kid, 64)
        raise ArgumentError, 'ProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required'
      end

      @key = key || KeyPair.generate
      @session = session || AtlasPca.b64e(SecureRandom.random_bytes(32))
      raise ArgumentError, 'ProvenanceRecorder: session must be canonical base64url of 32 bytes' unless AtlasPca.wb_digest?(@session)

      @mediator = mediator
      @kid = kid
      @alg = alg
      @pq = pq
      @now = now || -> { (Time.now.to_f * 1000).to_i }
      @chain = []
      @contents = {}
      @pin = { 'mediator' => mediator, 'kid' => kid, 'pk' => @key.public }
      @pin['pq_pk'] = pq.public if !alg.nil? && alg != 'ed25519' && pq
      @lock = Mutex.new
    end

    # The principal's own message (TRUSTED).
    def principal(text) = segment('principal', 'user', text)
    # A tool result (UNTRUSTED). Non-string output is recorded as its JSON text.
    def tool(name, output) = segment('tool', name, output)
    # A retrieved document (UNTRUSTED).
    def retrieval(source, content) = segment('retrieval', source, content)
    # A fetched web page or HTTP response (UNTRUSTED).
    def web(url, content) = segment('web', url, content)

    # Record the chosen action ({verb, resource, params}, String or Symbol keys) and return the bundle to present with it.
    def for_action(op)
      o = AtlasPca.prov_op_of(op, 'for_action')
      @lock.synchronize do
        if @chain.length >= MAX_PROV_RECEIPTS
          raise ArgumentError, "provenance: the session holds #{MAX_PROV_RECEIPTS} receipts; start a new session with the principal's message"
        end

        append('action', o['verb'], AtlasPca.prov_action_digest(o))
        b = { 'v' => 1, 'kind' => 'pca-provenance', 'receipts' => @chain.dup }
        b['contents'] = @contents.dup unless @contents.empty?
        b
      end
    end

    # Every receipt so far.
    def receipts = @lock.synchronize { @chain.dup }

    def inspect = "#<AtlasPca::ProvenanceRecorder mediator=#{@mediator} kid=#{@kid}>" # never print the key

    private

    def text_of(c)
      return c if c.is_a?(String)

      JSON.generate(c)
    rescue StandardError
      c.to_s
    end

    # The reference clip exactly: while over 256 UTF-8 bytes, keep the first floor(len / 2) UTF-16 units (at least 1). A cut
    # inside a surrogate pair leaves a lone surrogate, which the strict canonicalizer refuses: the source cannot be recorded
    # (Malformed, as for any unsignable receipt), exactly as the reference throws.
    def clip(s)
      s = s.dup.force_encoding(Encoding::UTF_8).scrub("\uFFFD")
      n = AtlasPca.utf16_len(s)
      loop do
        c = AtlasPca.utf16_slice(s, n)
        if c.bytesize <= 256
          raise Malformed, 'lone surrogate' unless c.valid_encoding?

          return c.empty? ? '-' : c
        end

        n = [1, n / 2].max
      end
    end

    def segment(origin, source, content)
      text = text_of(content).dup.force_encoding(Encoding::UTF_8)
      @lock.synchronize do
        r = append(origin, source.to_s, AtlasPca.wb_hash(text))
        @contents[r['seq'].to_s] = text if origin == 'principal' && text.bytesize <= MAX_PROV_CONTENT_BYTES
        r
      end
    end

    def append(origin, source, digest)
      prev = @chain[-1]
      issued = [prev.nil? ? 0 : prev['issued_at'], @now.call.to_i].max
      body = { 'v' => 1, 'kind' => 'pca-prov', 'mediator' => @mediator, 'kid' => @kid, 'session' => @session, 'seq' => @chain.length,
               'prev' => prev.nil? ? nil : AtlasPca.prov_receipt_ref(prev), 'origin' => origin, 'source' => clip(source),
               'content_digest' => digest, 'issued_at' => issued }
      r = AtlasPca.sign_artifact(PROV_RECEIPT_DOMAIN, body, @key, alg: @alg, pq: @pq)
      @chain << r
      r
    end
  end

  # The bundle for an operation that came straight from the principal (the application's own UI acting on the user's explicit
  # input, no model in between): one principal segment holding the operation's canonical JSON, then the action.
  def principal_direct_provenance(recorder, op)
    o = prov_op_of(op, 'principal_direct_provenance')
    recorder.principal(canonicalize(o))
    recorder.for_action(o)
  end
end
