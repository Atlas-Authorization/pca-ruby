# frozen_string_literal: true

require 'digest'
require_relative 'js_compat'
require_relative 'actions_import_common'

module AtlasPca
  # The objective risk functional. Every input of the heuristic r is a pure function of COMMITTED facts and of the CANONICAL ACTION (verb +
  # resource + params): nothing the agent merely asserts (features, labels, scope, confidence) is read. Agent and verifier recompute the same
  # r; the grant commits the registry, graph, embedder and goal, and a mismatch fails closed (r = 1). The result feeds Risk.risk_score, so the
  # policy VM sees the unchanged risk inputs. The digests are SERVER-ONLY and use the LENIENT canonical hash (any finite double, printed as
  # ECMAScript prints it), never the strict wire form. Actions, goal commitments, contexts and results are Hashes with String keys and the
  # reference's member names; a registry, graph and embedder are the objects below.
  module ObjectiveRisk
    METRIC = 'half-chord-v1'
    DEFAULT_EPSILON = 1.0 / 4096
    NATIVE_SCHEME = 'pca-native-hash-ngram-v1'
    DEFAULT_MAX_PARAM_LEAVES = 256
    DEFAULT_NATIVE_CONFIG = { 'dims' => 256, 'ngramMin' => 2, 'ngramMax' => 4, 'seed' => 'pca-native-v1',
                              'fieldWeights' => { 'verb' => 4, 'resource' => 2, 'param' => 1 } }.freeze
    WORST_INPUTS = { 'semanticDistance' => 1, 'reversibility' => 0, 'blastRadius' => 1, 'taint' => 1, 'confidence' => 0, 'age' => 1 }.freeze
    MAX_SAFE = 9_007_199_254_740_991

    # The embedding (or a vector) was refused.
    class EmbeddingError < StandardError; end

    # An embedder maps the CANONICAL ACTION to an integer vector; it never sees agent-supplied features. `model_id` is a committed identity
    # (a hash of the native config or of the BYO descriptor). The block must return `dims` safe integers and may raise.
    class Embedder
      attr_reader :model_id, :config, :dims

      def initialize(model_id:, config:, dims:, &embed)
        @model_id = model_id
        @config = config
        @dims = dims
        @embed = embed
      end

      def embed(action) = @embed.call(action)
    end

    # A committed registry of verified inverses.
    class InMemoryInverseRegistry
      def initialize(trusted_verifiers = [])
        @m = {}
        @trusted = ObjectiveRisk.u16_sort(trusted_verifiers.uniq)
      end

      def register(verb, entry)
        e = entry.dup
        e['verification'] = e['verification'].dup if Js.truthy?(e['verification']) && e['verification'].is_a?(Hash)
        @m[verb] = e
        self
      end

      def lookup(verb) = @m.key?(verb) ? @m[verb].dup : nil
      def trusted_verifiers = @trusted

      def digest
        entries = ObjectiveRisk.u16_sort_by(@m.keys) { |k| k }.map do |verb|
          e = @m[verb]
          { 'verb' => verb, 'inverseKind' => ObjectiveRisk.defined(e, 'inverseKind'), 'fidelity' => ObjectiveRisk.defined(e, 'fidelity'),
            'verification' => e['verification'].nil? ? nil : e['verification'] }
        end
        ActionsImportCommon.hash_canonical_lenient({ 'v' => 1, 'trusted' => @trusted, 'entries' => entries })
      end
    end

    # An adjacency model with a content digest the grant commits.
    class ResourceGraph
      def initialize
        @nodes = {}
        @out = {}
      end

      def add_node(n)
        @nodes[n['id']] = n
        @out[n['id']] = [] unless @out.key?(n['id'])
        self
      end

      def add_edge(e)
        raise 'edge endpoints must exist' unless @nodes.key?(e['from']) && @nodes.key?(e['to'])

        @out[e['from']] << e
        self
      end

      def size = @nodes.length
      def node(id) = @nodes[id]

      # BFS reachable set (including `start`), edge-kind and depth restricted, sorted (UTF-16 order).
      def reachable(start, scope = nil)
        return [] unless @nodes.key?(start)

        kinds = scope.is_a?(Hash) && Js.truthy?(scope['edgeKinds']) ? scope['edgeKinds'].to_a : nil
        md = scope.is_a?(Hash) ? scope['maxDepth'] : nil
        max_depth = md.nil? ? Float::INFINITY : Immune.to_num(md)
        seen = { start => true }
        frontier = [start]
        d = 0
        while d < max_depth && !frontier.empty?
          nxt = []
          frontier.each do |u|
            (@out[u] || []).each do |e|
              next unless (kinds.nil? || kinds.include?(e['kind'])) && !seen.key?(e['to'])

              seen[e['to']] = true
              nxt << e['to']
            end
          end
          frontier = nxt
          d += 1
        end
        ObjectiveRisk.u16_sort(seen.keys)
      end

      def digest
        n = ObjectiveRisk.u16_sort_by(@nodes.values.map { |x| { 'id' => x['id'], 'harm' => x['harm'].nil? ? {} : x['harm'] } }) { |x| x['id'] }
        e = @out.values.flatten(1).map { |x| { 'from' => x['from'], 'to' => x['to'], 'kind' => ObjectiveRisk.defined(x, 'kind') } }
        e = ObjectiveRisk.u16_sort_by(e) { |x| "#{x['from']}\u0000#{x['to']}\u0000#{x['kind']}" }
        ActionsImportCommon.hash_canonical_lenient({ 'v' => 1, 'n' => n, 'e' => e })
      end
    end

    module_function

    # ---- helpers

    def lenient(v) = ActionsImportCommon.lenient(v)
    def hash_of(v) = ActionsImportCommon.hash_canonical_lenient(v)
    def fin?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)
    def clamp01(x) = fin?(x) ? (x < 0 ? 0 : (x > 1 ? 1 : x)) : 1

    def safe_int?(x) = (x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor)) && x.abs <= MAX_SAFE
    def ok_int?(x, lo, hi) = safe_int?(x) && x >= lo && x <= hi

    # a member that must be defined (an undefined member has no canonical form)
    def defined(h, k)
      raise TypeError, 'canonicalize: undefined is not serializable' unless h.is_a?(Hash) && h.key?(k)

      h[k]
    end

    # JavaScript's default string order: UTF-16 code units
    def u16_key(s) = s.valid_encoding? ? s.encode('UTF-16BE').unpack('n*') : s.b.bytes
    def u16_sort(strs) = strs.sort_by { |s| u16_key(s) }
    def u16_sort_by(xs, &key) = xs.each_with_index.sort_by { |x, i| [u16_key(key.call(x)), i] }.map(&:first)

    # JS `x.k` for the members read here: a null object throws, a non-object has no members.
    def jget(o, k)
      raise TypeError, "Cannot read properties of null (reading '#{k}')" if o.nil?

      o.is_a?(Hash) ? o[k] : nil
    end

    def num(x) = x.is_a?(Numeric) ? x : Immune.to_num(x)
    def nan?(x) = x.is_a?(Float) && x.nan?

    # String#toLowerCase: the full Unicode mapping with the final-sigma rule (Ruby's downcase has no context rules).
    def js_lower(s)
      return s.downcase unless s.include?("Σ")

      chars = s.each_char.to_a
      ignorable = ->(c) { c.match?(/\p{Case_Ignorable}/) }
      cased = ->(c) { c.match?(/\p{Cased}/) }
      chars.each_with_index.map do |c, i|
        next c.downcase unless c == "Σ"

        j = i - 1
        j -= 1 while j >= 0 && ignorable.call(chars[j])
        before = j >= 0 && cased.call(chars[j])
        j = i + 1
        j += 1 while j < chars.length && ignorable.call(chars[j])
        after = j < chars.length && cased.call(chars[j])
        before && !after ? "ς" : "σ"
      end.join
    end

    # ---- canonical action

    def norm_value(v)
      case v
      when String then v.unicode_normalize(:nfc)
      when Array then v.map { |x| norm_value(x) }
      when Hash
        out = {}
        v.each do |k, x|
          nk = k.unicode_normalize(:nfc)
          raise TypeError, 'canonicalAction: duplicate key after NFC normalization' if out.key?(nk)

          out[nk] = norm_value(x)
        end
        out
      else v
      end
    end

    # Canonical form: verb trimmed + lowercased, all strings and keys NFC, params validated by the canonical encoder (rejects non-finite
    # numbers). Raises TypeError on anything without a stable encoding.
    def canonical_action(a)
      raise TypeError, 'canonicalAction: verb/resource must be strings' unless a.is_a?(Hash) && a['verb'].is_a?(String) && a['resource'].is_a?(String)

      verb = js_lower(Js.trim(a['verb'].unicode_normalize(:nfc)))
      resource = Js.trim(a['resource'].unicode_normalize(:nfc))
      raise TypeError, 'canonicalAction: empty verb/resource' if verb.empty? || resource.empty?

      params = norm_value(a['params'].nil? ? {} : a['params'])
      raise TypeError, 'canonicalAction: params must be an object' unless params.is_a?(Hash)

      c = { 'verb' => verb, 'resource' => resource, 'params' => params }
      lenient(c) # validate
      c
    end

    def canonical_action_json(c) = lenient(c)
    def canonical_action_digest(c) = hash_of(c)

    # ---- reversibility: a committed registry of verified inverses

    # Reversible iff the registry holds an inverse whose verification came from a TRUSTED verifier AND the inverse verb is itself authorized
    # by the capability. Anything else is irreversible. Inverses of inverses are not chased.
    def reversibility(action, registry, authorized_kinds)
      e = registry.lookup(jget(action, 'verb'))
      ver = e.nil? ? nil : e['verification']
      trusted = Js.truthy?(ver) ? registry.trusted_verifiers.include?(ver.is_a?(Hash) ? ver['verifierId'] : nil) : false
      return { 'class' => 'irreversible', 'value' => 0 } if e.nil? || !trusted || !authorized_kinds.include?(e['inverseKind'])

      e['fidelity'] == 'exact' ? { 'class' => 'reversible', 'value' => 1, 'inverseKind' => e['inverseKind'] } : { 'class' => 'compensable', 'value' => 0.5, 'inverseKind' => e['inverseKind'] }
    end

    # ---- blast radius: reachability over a committed resource graph

    # {'count', 'reachable', 'normalized' (count / graph size; an unknown resource is 1), 'harm' => per-dimension sums of finite positive harm}.
    def blast_radius(action, graph, scope = nil)
      reachable = graph.reachable(jget(action, 'resource'), scope)
      return { 'count' => 0, 'reachable' => reachable, 'normalized' => 1, 'harm' => {} } if reachable.empty? || graph.size.zero?

      harm = {}
      reachable.each do |id|
        h = graph.node(id)&.fetch('harm', nil)
        (h.nil? ? {} : h).each { |d, v| harm[d] = (harm[d] || 0) + v if fin?(v) && v > 0 }
      end
      { 'count' => reachable.length, 'reachable' => reachable, 'normalized' => reachable.length.to_f / graph.size, 'harm' => harm }
    end

    # ---- committed embeddings

    # Largest |component| such that dot products of two `dims`-vectors stay exact in a double.
    def max_component(dims) = Math.sqrt(MAX_SAFE.to_f / (2 * [1, dims].max)).floor

    def validate_vector(v, dims)
      raise EmbeddingError, "vector must have exactly #{Js.string(dims)} components" unless v.is_a?(Array) && v.length == dims

      lim = max_component(dims)
      v.each do |x|
        raise EmbeddingError, 'vector components must be safe integers' unless safe_int?(x)
        raise EmbeddingError, 'vector component out of range' if x.abs > lim
      end
      v.map { |x| x.is_a?(Float) ? x.to_i : x } # -0 becomes 0
    end

    def validate_native_config(c)
      fw = jget(c, 'fieldWeights')
      raise RangeError, 'native config: dims must be an integer in [8, 65536]' unless ok_int?(jget(c, 'dims'), 8, 65_536)
      unless ok_int?(c['ngramMin'], 1, 8) && ok_int?(c['ngramMax'], c['ngramMin'], 8)
        raise RangeError, 'native config: need 1 <= ngramMin <= ngramMax <= 8'
      end
      raise RangeError, 'native config: seed required' unless c['seed'].is_a?(String) && !c['seed'].empty?

      %w[verb resource param].each do |k|
        raise RangeError, "native config: fieldWeights.#{k} must be an integer in [0, 1000]" unless ok_int?(jget(fw, k), 0, 1000)
      end
      raise RangeError, 'native config: maxParamLeaves must be an integer in [1, 1000000]' if c.key?('maxParamLeaves') && !ok_int?(c['maxParamLeaves'], 1, 1_000_000)
      raise RangeError, "native config: paramMode must be 'leaves' or 'digest'" if c.key?('paramMode') && !%w[leaves digest].include?(c['paramMode'])
    end

    # Flatten params to sorted `path=value` leaves (nested key order and array encoding are irrelevant).
    def param_leaves(v, path, out)
      case v
      when Array then v.each_with_index { |x, i| param_leaves(x, "#{path}[#{i}]", out) }
      when Hash then v.keys.sort.each { |k| param_leaves(v[k], path.empty? ? k : "#{path}.#{k}", out) }
      else out << "#{path}=#{lenient(v)}"
      end
    end

    # Code-point n-grams of the text between boundary markers, then its lower-cased word tokens.
    def text_features(prefix, text, nmin, nmax)
      out = []
      cps = "\u0002#{text}\u0003".each_char.to_a
      (nmin..nmax).each { |n| (0..cps.length - n).each { |i| out << "#{prefix}c#{n}:#{cps[i, n].join}" } }
      text.split(/[^\p{L}\p{N}]+/).each { |w| out << "#{prefix}w:#{js_lower(w)}" unless w.empty? }
      out
    end

    def text_of(a, k)
      jget(a, k) # a null action throws
      return 'undefined' unless a.is_a?(Hash) && a.key?(k)

      Js.string(a[k])
    end

    # The native embedder: for each field (verb, resource, each param leaf) code-point n-grams and word tokens; each feature f is hashed as
    # SHA-256(seed 0x1F f): bucket = big-endian u32(h[0..4]) mod dims, sign = low bit of h[4]; the bucket accumulates +-fieldWeight.
    def native_hash_embedder(config = DEFAULT_NATIVE_CONFIG)
      validate_native_config(config)
      cfg = config.merge('fieldWeights' => config['fieldWeights'].dup)
      committed = { 'scheme' => NATIVE_SCHEME }.merge(cfg)
      model_id = "native:#{hash_of(committed)}"
      prefix = Js.utf8("#{cfg['seed']}\u001f")
      fw = cfg['fieldWeights']
      Embedder.new(model_id: model_id, config: committed, dims: cfg['dims']) do |a|
        dims = cfg['dims'].to_i
        v = Array.new(dims, 0)
        add = lambda do |feat, w|
          next if w.zero?

          h = Digest::SHA256.digest(prefix + Js.utf8(feat))
          bucket = h[0, 4].unpack1('N') % dims
          v[bucket] += h.getbyte(4).even? ? w : -w
        end
        text_features('v:', text_of(a, 'verb'), cfg['ngramMin'], cfg['ngramMax']).each { |f| add.call(f, fw['verb']) }
        text_features('r:', text_of(a, 'resource'), cfg['ngramMin'], cfg['ngramMax']).each { |f| add.call(f, fw['resource']) }
        params = jget(a, 'params')
        leaves = []
        param_leaves(params, '', leaves)
        # fail CLOSED on a param-stuffed action: more leaves than the cap can never give a (diluted) favorable embedding
        cap = cfg['maxParamLeaves'].nil? ? DEFAULT_MAX_PARAM_LEAVES : cfg['maxParamLeaves']
        raise EmbeddingError, "param leaf count #{leaves.length} exceeds cap #{Js.string(cap)}" if leaves.length > cap

        if cfg['paramMode'] == 'digest'
          add.call("p#:#{hash_of({ 't' => 'pca-objrisk-params-v1', 'params' => params })}", fw['param'])
        else
          leaves.each { |leaf| text_features('p:', leaf, cfg['ngramMin'], cfg['ngramMax']).each { |f| add.call(f, fw['param']) } }
        end
        v
      end
    end

    def byo_model_id(descriptor) = "byo:#{hash_of(descriptor)}"

    # A customer-supplied model that meets the determinism contract. `infer` receives the canonical action JSON and returns the integer
    # vector; a claimed model id must equal the descriptor hash.
    def byo_embedder(descriptor, infer, claimed_model_id = nil)
      raise RangeError, 'byo: dims must be a positive integer' if !safe_int?(jget(descriptor, 'dims')) || descriptor['dims'] < 1

      q = jget(descriptor, 'quantization')
      bits = jget(q, 'bits')
      raise RangeError, 'byo: invalid quantization' if !safe_int?(bits) || bits < 2 || bits > 31 || !(num(q['scale']) > 0)
      raise RangeError, 'byo: unsupported inputEncoding' unless descriptor['inputEncoding'] == 'pca-canonical-action-json-v1'

      model_id = byo_model_id(descriptor)
      raise 'byo: modelId does not match the committed descriptor' if !claimed_model_id.nil? && claimed_model_id != model_id

      qmax = (2**(bits - 1)) - 1
      Embedder.new(model_id: model_id, config: descriptor, dims: descriptor['dims']) do |a|
        v = validate_vector(infer.call(canonical_action_json(a)), descriptor['dims'])
        v.each { |x| raise EmbeddingError, 'byo: component exceeds declared quantization range' if x.abs > qmax }
        v
      end
    end

    # Run conformance cases ({'action', 'vector'}) shipped with a model; true iff all reproduce exactly.
    def conformance_check(embedder, cases)
      raise TypeError, 'cases.every is not a function' unless cases.is_a?(Array)

      cases.all? do |c|
        v = embedder.embed(canonical_action(jget(c, 'action')))
        raise TypeError, 'v.every is not a function' unless v.is_a?(Array)

        want = jget(c, 'vector')
        v.length == want.length && v.each_with_index.all? { |x, i| x.is_a?(Numeric) && want[i].is_a?(Numeric) ? x == want[i] : x.equal?(want[i]) }
      end
    rescue StandardError
      false
    end

    # ---- goal commitment and distance

    def goal_commit_input(g)
      { 'embedderModelId' => defined(g, 'embedderModelId'), 'config' => defined(g, 'config'), 'goalVector' => defined(g, 'goalVector'),
        'metric' => defined(g, 'metric'), 'epsilon' => defined(g, 'epsilon') }
    end

    def epsilon_ok?(e)
      n = num(e)
      n > 0 && n <= 1 # NaN fails both
    end

    # Embed the goal's CANONICAL action and bind it to this embedder. Raises on invalid input.
    def commit_goal(embedder, goal_action, epsilon = DEFAULT_EPSILON)
      raise RangeError, 'epsilon must be in (0, 1]' unless epsilon_ok?(epsilon)

      goal_vector = validate_vector(embedder.embed(canonical_action(goal_action)), embedder.dims)
      g = { 'embedderModelId' => embedder.model_id, 'config' => embedder.config, 'goalVector' => goal_vector, 'metric' => METRIC, 'epsilon' => epsilon }
      g.merge('commit' => hash_of(goal_commit_input(g)))
    end

    # Verifies the commitment hashes AND is bound to exactly this embedder (id, config, dims). nil when valid, else the reason.
    def verify_goal_commitment(g, embedder)
      return 'unknown metric' if jget(g, 'metric') != METRIC
      return 'bad epsilon' unless epsilon_ok?(g['epsilon'])
      return 'goal commitment hash mismatch' if g['commit'] != hash_of(goal_commit_input(g))
      return 'embedder modelId mismatch' if g['embedderModelId'] != embedder.model_id
      return 'embedder config mismatch' if hash_of(g['config']) != hash_of(embedder.config)

      validate_vector(g['goalVector'], embedder.dims)
      nil
    rescue StandardError => e
      e.message
    end

    # Integer vectors -> sin(theta/2) = sqrt((1-cos)/2), rounded up to the grid. Only IEEE division and sqrt, in this order.
    def vector_distance(a, b, epsilon = DEFAULT_EPSILON)
      raise TypeError, "Cannot read properties of undefined (reading 'length')" unless a.is_a?(Array) && b.is_a?(Array)
      return 1 if a.length != b.length

      dot = 0.0
      na = 0.0
      nb = 0.0
      same = true
      a.each_index do |i|
        x = num(a[i]).to_f
        y = num(b[i]).to_f
        dot += x * y
        na += x * x
        nb += y * y
        same = false unless a[i].is_a?(Numeric) && b[i].is_a?(Numeric) ? a[i] == b[i] : a[i].equal?(b[i])
      end
      return 1 if na == 0 || nb == 0
      return 0 if same

      cos = dot / Math.sqrt(na * nb)
      cos = [[cos, 1.0].min, -1.0].max unless cos.nan?
      d = Math.sqrt((1 - cos) / 2)
      return 0 if d < 1e-9 # float noise floor, far below epsilon

      q = d / epsilon
      clamp01(q.finite? ? q.ceil * epsilon : q)
    end

    # Distance to the committed goal: {'ok' => true, 'value'} or {'ok' => false, 'reason'} (distance 1) on any commitment or embedding failure.
    def committed_distance_checked(action, goal, embedder)
      bad = verify_goal_commitment(goal, embedder)
      return { 'ok' => false, 'reason' => bad } if bad

      begin
        v = validate_vector(embedder.embed(action), embedder.dims)
        { 'ok' => true, 'value' => vector_distance(v, goal['goalVector'], goal['epsilon']) }
      rescue StandardError => e
        { 'ok' => false, 'reason' => e.message.empty? ? 'embedding failed' : e.message }
      end
    end

    # Accepts an agent submission, canonicalizes it, returns the distance (1 on failure).
    def committed_distance(action, goal, embedder)
      r = committed_distance_checked(canonical_action(action), goal, embedder)
      r['ok'] ? r['value'] : 1
    rescue StandardError
      1
    end

    # ---- split-conformal calibration

    # p = (1 + #{s_i >= raw}) / (n + 1); calibrated r = 1 - p. Non-decreasing in raw. An empty set or a non-finite raw is 1.
    def calibrate(raw_score, benign_scores)
      n = benign_scores.length
      return 1 if n.zero? || !fin?(raw_score)

      ge = benign_scores.count { |s| num(s) >= raw_score }
      1 - ((1 + ge).to_f / (n + 1))
    end

    # Split-conformal quantile: benign raw <= q with probability >= 1 - alpha; Infinity if n is too small; nil when the rank is below the set.
    def conformal_threshold(benign_scores, alpha)
      n = benign_scores.length
      kf = (n + 1) * (1 - num(alpha)).to_f
      knan = kf.nan?
      k = knan || kf.infinite? ? kf : kf.ceil
      return Float::INFINITY if n.zero? || (!knan && k > n)
      return nil if knan || k < 1

      js_sort_numbers(benign_scores)[k - 1]
    end

    # Digest of a calibration set, committed by the grant.
    def calibration_digest(scores) = hash_of({ 'v' => 1, 'scores' => js_sort_numbers(scores) })

    # `[...a].sort((x, y) => x - y)`: a comparison that involves NaN answers 0 (the engine's TimSort then keeps such elements where its run
    # detection and binary insertion leave them). Without NaN the order is total, so any stable sort gives it. With NaN the engine's own algorithm is
    # followed for an array of fewer than 64 elements (one counted run, then binary insertion); a longer array falls back to the plain order
    # shortcut: a NaN-bearing calibration set that long is refused upstream, when the digest is taken (the canonical form has no NaN).
    def js_sort_numbers(scores)
      a = scores.dup
      return a.sort_by { |s| num(s) } if a.none? { |s| nan?(num(s)) } || a.length >= 64

      cmp = lambda do |x, y|
        d = num(x) - num(y)
        d.respond_to?(:nan?) && d.nan? ? 0 : d
      end
      n = a.length
      return a if n < 2

      run = 2
      desc = cmp.call(a[1], a[0]).negative?
      prev = a[1]
      (2...n).each do |i|
        o = cmp.call(a[i], prev)
        break if desc ? o >= 0 : o.negative?

        prev = a[i]
        run += 1
      end
      a[0...run] = a[0...run].reverse if desc
      (run...n).each do |start|
        pivot = a[start]
        left = 0
        right = start
        while left < right
          mid = left + ((right - left) >> 1)
          if cmp.call(pivot, a[mid]).negative? then right = mid
          else left = mid + 1
          end
        end
        a[left + 1..start] = a[left...start]
        a[left] = pivot
      end
      a
    end

    # ---- harm currency

    # {'units', 'normalized' (weighted saturating normalization in [0, 1])}.
    def harm_report(units, denoms)
      num_sum = 0.0
      den = 0.0
      denoms.each do |d|
        w = num(jget(d, 'weight'))
        ceil = num(d['ceiling'])
        next unless w > 0 && ceil > 0

        u = units.is_a?(Hash) && units.key?(d['id']) ? num(units[d['id']]) : 0
        sat = u.is_a?(Float) && u.nan? ? Float::NAN : [1.0, [0, u].max / ceil.to_f].min
        num_sum += w * sat
        den += w
      end
      { 'units' => units, 'normalized' => den.zero? ? 1 : clamp01(num_sum / den) }
    end

    # ---- composition

    def reject(reasons)
      { 'r' => 1, 'valid' => false, 'reasons' => reasons, 'raw' => 1, 'inputs' => WORST_INPUTS.dup, 'reversibility' => { 'class' => 'irreversible', 'value' => 0 },
        'blast' => { 'count' => 0, 'reachable' => [], 'normalized' => 1, 'harm' => {} }, 'harm' => { 'units' => {}, 'normalized' => 1 }, 'evidenceDigest' => '' }
    end

    # Pure function of (canonical action, committed context). Any commitment mismatch (registry, graph, goal / embedder binding, calibration
    # set) or un-encodable action returns the fail-closed r = 1 with valid false. The context: 'registry', 'authorizedKinds', 'graph',
    # 'scope'?, 'embedder', 'goal', 'commitments' ({'registryDigest', 'graphDigest', 'calibrationDigest'?}), 'denominations', 'weights',
    # 'taint', 'age', 'attestedUncertainty'?, 'calibration'?.
    def objective_risk(submitted, ctx)
      begin
        action = canonical_action(submitted)
      rescue StandardError => e
        return reject(["action: #{e.message.empty? ? 'not canonicalizable' : e.message}"])
      end
      cm = ctx['commitments']
      reasons = []
      reasons << 'registry digest does not match the committed digest' if ctx['registry'].digest != cm['registryDigest']
      reasons << 'graph digest does not match the committed digest' if ctx['graph'].digest != cm['graphDigest']
      cal = ctx['calibration']
      if Js.truthy?(cal)
        if cm['calibrationDigest'].nil?
          reasons << 'calibration set used without a committed digest'
        elsif calibration_digest(cal) != cm['calibrationDigest']
          reasons << 'calibration digest does not match the committed digest'
        end
      end
      dist = committed_distance_checked(action, ctx['goal'], ctx['embedder'])
      reasons << "goal/embedder: #{dist['reason']}" unless dist['ok']
      return reject(reasons) unless reasons.empty?

      rev = reversibility(action, ctx['registry'], ctx['authorizedKinds'])
      blast = blast_radius(action, ctx['graph'], ctx['scope'])
      harm = harm_report(blast['harm'], ctx['denominations'])
      uncertainty = clamp01(ctx['attestedUncertainty'].nil? ? 0 : ctx['attestedUncertainty'])
      harm_in = !ctx['denominations'].empty? && !blast['harm'].empty? ? harm['normalized'] : 0
      inputs = { 'semanticDistance' => dist['value'], 'reversibility' => rev['value'], 'blastRadius' => [blast['normalized'], harm_in].max,
                 # a verifier that forgot (or corrupted) taint / age gets the worst value, never a throw or a NaN risk
                 'taint' => fin?(ctx['taint']) ? ctx['taint'] : 1, 'confidence' => 1 - uncertainty, 'age' => fin?(ctx['age']) ? ctx['age'] : 1 }
      raw = Risk.risk_score(inputs, ctx['weights'])
      r = Js.truthy?(cal) ? calibrate(raw, cal) : raw
      scope = ctx['scope']
      kinds = scope.is_a?(Hash) && Js.truthy?(scope['edgeKinds']) ? u16_sort(scope['edgeKinds']) : nil
      evidence = hash_of({ 'action' => canonical_action_digest(action),
                           'scope' => { 'edgeKinds' => kinds, 'maxDepth' => scope.is_a?(Hash) && !scope['maxDepth'].nil? ? scope['maxDepth'] : nil },
                           'authorized' => u16_sort(ctx['authorizedKinds'].to_a.uniq), 'registry' => cm['registryDigest'], 'graph' => cm['graphDigest'],
                           'goal' => defined(ctx['goal'], 'commit'), 'calibration' => cm['calibrationDigest'], 'inputs' => inputs })
      { 'r' => r, 'valid' => true, 'reasons' => [], 'raw' => raw, 'inputs' => inputs, 'reversibility' => rev, 'blast' => blast, 'harm' => harm, 'evidenceDigest' => evidence }
    end

    # ---- dispute-game oracle

    # The objective oracle of the contestable dispute game, backed by the objective risk functional: recomputes a disputed input from the
    # COMMITTED facts over the open-time snapshot's canonical action. It fails CLOSED: a commitment mismatch or an un-encodable action
    # makes the dispute indeterminate (valid false) rather than a fabricated worst case. The returned object answers #resolve(input, snapshot).
    def objective_risk_oracle(ctx) = Oracle.new(ctx)

    class Oracle
      def initialize(ctx) = @ctx = ctx

      def resolve(input, snapshot)
        a = snapshot.is_a?(Hash) && snapshot['action'].is_a?(Hash) ? snapshot['action']['action'] : nil
        unless a.is_a?(Hash) && a['verb'].is_a?(String) && a['resource'].is_a?(String)
          return { 'input' => input, 'valid' => false, 'reason' => 'snapshot action is missing a canonical verb/resource' }
        end

        res = ObjectiveRisk.objective_risk({ 'verb' => a['verb'], 'resource' => a['resource'], 'params' => a['params'].is_a?(Hash) ? a['params'] : {} }, @ctx)
        unless res['valid']
          reason = res['reasons'].join('; ')
          return { 'input' => input, 'valid' => false, 'reason' => reason.empty? ? 'objective risk could not be reproduced' : reason }
        end
        case input
        when 'reversibility_class' then { 'input' => input, 'class' => res['reversibility']['class'], 'valid' => true }
        when 'reversibility' then { 'input' => input, 'value' => res['inputs']['reversibility'], 'valid' => true }
        when 'blastRadius' then { 'input' => input, 'value' => res['inputs']['blastRadius'], 'valid' => true }
        when 'semanticDistance' then { 'input' => input, 'value' => res['inputs']['semanticDistance'], 'valid' => true }
        else { 'input' => input, 'valid' => false, 'reason' => "unknown disputed input: #{Js.string(input)}" }
        end
      rescue StandardError => e
        { 'input' => input, 'valid' => false, 'reason' => "objective oracle error (fail closed): #{e.message.empty? ? 'unknown' : e.message}" }
      end
    end

    # The engine of resolve_objective_risk: builds the registry, graph and native embedder from the instance's config and the committed
    # facts, and runs the functional. The instance config is {'registry' => {'trusted_verifiers', 'entries' => [{'verb', 'inverse_kind',
    # 'fidelity', 'verification'? => {'verifier_id', 'evidence_digest'}}]}, 'graph' => {'nodes', 'edges'}, 'calibration'?, ...}; a registry or
    # graph object is accepted as it is.
    module Engine
      module_function

      def build_registry(cfg)
        return cfg if cfg.is_a?(InMemoryInverseRegistry)

        reg = InMemoryInverseRegistry.new((cfg.is_a?(Hash) ? cfg['trusted_verifiers'] : nil) || [])
        ((cfg.is_a?(Hash) ? cfg['entries'] : nil) || []).each do |e|
          entry = { 'inverseKind' => e['inverse_kind'], 'fidelity' => e['fidelity'] }
          if Js.truthy?(e['verification'])
            entry['verification'] = { 'verifierId' => e['verification']['verifier_id'], 'evidenceDigest' => e['verification']['evidence_digest'] }
          end
          reg.register(e['verb'], entry)
        end
        reg
      end

      def build_graph(cfg)
        return cfg if cfg.is_a?(ResourceGraph)

        g = ResourceGraph.new
        ((cfg.is_a?(Hash) ? cfg['nodes'] : nil) || []).each { |n| g.add_node(n) }
        ((cfg.is_a?(Hash) ? cfg['edges'] : nil) || []).each { |e| g.add_edge(e) }
        g
      end

      def embedder_model_id(config) = ObjectiveRisk.native_hash_embedder(config).model_id
      def calibration_digest(calibration) = ObjectiveRisk.calibration_digest(calibration)

      def evaluate(action, opts)
        ctx = { 'registry' => build_registry(opts['registry']), 'authorizedKinds' => opts['authorizedKinds'], 'graph' => build_graph(opts['graph']),
                'scope' => opts['scope'], 'embedder' => ObjectiveRisk.native_hash_embedder(opts['embedder']['config']), 'goal' => opts['goal'],
                'commitments' => opts['commitments'], 'denominations' => opts['denominations'], 'weights' => opts['weights'], 'taint' => opts['taint'],
                'age' => opts['age'] }
        ctx['calibration'] = opts['calibration'] if opts.key?('calibration')
        ObjectiveRisk.objective_risk(action, ctx)
      end
    end
  end
end
