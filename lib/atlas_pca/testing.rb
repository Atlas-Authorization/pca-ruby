# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'authorize'
require_relative 'arg_provenance'

module AtlasPca
  # Testing kit for Proof-Carrying Authority: factories, fakes and assertion helpers so an integrator can unit-test their PCA wiring
  # with no backend and no network. test_agent mints a real agent with test defaults, make_pcactn builds real PCActns from it and
  # fake_verify runs the REAL core verifier against them. Mirrors the TypeScript reference (@atlasauth/pca-testing).
  #
  # Nothing here authorizes anything. fake_verify stands in for the resource server by rooting the check at the PCActn's own grant
  # and accepting the PCActn's own audience by default, so a clean round trip verifies; it is the real verifier, not a weakened
  # one, so tampering is caught exactly as in production. A grant lifted from the artifact is never trusted for a post-quantum root
  # (no pin exists), as in the reference.
  #
  # The adapter acceptance matrix (run_adapter_acceptance) takes a harness for your own adapter, so every adapter runs the same
  # scenarios and must equal ADAPTER_ACCEPTANCE_EXPECTED. Data is String-keyed; the harness is synchronous.
  module Testing
    # Raised by expect_verifies / expect_denied.
    class AssertionError < StandardError; end

    UNSET = Object.new.freeze

    module_function

    # A REAL agent handle with test defaults (permissions {stripe: [refund]}, limits {refund: "$500/day"}, goal "test", aud
    # "ins_test", fresh keys). Pass limits: {} for no limits.
    def test_agent(permissions: nil, limits: nil, goal: nil, aud: nil, principal: nil, holder: nil)
      AtlasPca.create_agent(
        principal: principal || KeyPair.generate, goal: goal.nil? ? 'test' : goal,
        permissions: permissions.nil? ? { 'stripe' => ['refund'] } : permissions, limits: limits.nil? ? { 'refund' => '$500/day' } : limits,
        holder: holder, aud: aud.nil? ? 'ins_test' : aud
      )
    end

    # Build a PCActn for one action: {'pcactn', 'encoded'} (the local dry-run is dropped; use a.act if you need it).
    def make_pcactn(agent, verb, resource, params = nil, counter: nil, now: nil)
      res = agent.act(verb, resource, params, counter: counter, now: now)
      { 'pcactn' => res['pcactn'], 'encoded' => res['encoded'] }
    end

    # ---- fake verifier
    NO_GRANT = 'fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant'

    # pcactn.cap_chain[0] as JavaScript reads it; raises where JavaScript would raise or find nothing.
    def lift_grant(pcactn)
      raise ArgumentError, NO_GRANT unless pcactn.is_a?(Hash)

      chain = pcactn['cap_chain']
      first = case chain
              when Array then chain.first
              when String then chain.empty? ? nil : chain[0]
              when Hash then chain['0']
              end
      raise ArgumentError, NO_GRANT unless Js.truthy?(first)

      first
    end

    # Run the real core verifier against pcactn, rooting the check at `grant` or the PCActn's own chain root and defaulting the
    # verifier audience to the PCActn's own aud (omit audience; pass nil to opt out; a mismatching string forces the audience check to
    # fail). now is epoch ms (wall clock when omitted). Returns the Verdict; raises when there is no grant to root at.
    def fake_verify(pcactn, audience: UNSET, now: nil, grant: nil)
      root = grant.nil? ? lift_grant(pcactn) : grant
      lifted = grant.nil?
      if !audience.equal?(UNSET) && !audience.nil?
        aud = audience
      else
        raise ArgumentError, 'fakeVerify: no PCActn' if audience.equal?(UNSET) && pcactn.nil?

        own = pcactn.is_a?(Hash) ? pcactn['aud'] : nil
        aud = own.is_a?(String) ? own : nil # opt-out accepts the PCActn's own audience; a non-string one fails the wire check
      end
      return Verdict.new(false, { 'wire' => false }, 'wire: the grant is not an object') unless root.is_a?(Hash)
      if lifted && root.key?('alg') && root['alg'] != 'ed25519'
        return Verdict.new(false, { 'cap_chain' => false },
                           'cap_chain: root suite needs a verifier-side PQ pin; a grant lifted from the artifact is never trusted for it')
      end

      AtlasPca.verify_pcactn(pcactn, root, now: now.nil? ? AtlasPca.now_ms : now, audience: aud, insecure_skip_plan_root_check: true)
    end

    def failing(res) = res.checks.select { |_, ok| ok == false }.keys

    # Assert that pcactn verifies: raises AssertionError naming the failing checks and the reason, else returns the Verdict.
    def expect_verifies(pcactn, **opts)
      res = fake_verify(pcactn, **opts)
      unless res.allow
        raise AssertionError, "expectVerifies: PCActn was denied. failing checks: [#{failing(res).join(', ')}]" \
                              "#{res.reason.nil? || res.reason.empty? ? '' : " — #{res.reason}"}"
      end
      res
    end

    # The inverse of expect_verifies: raises AssertionError when pcactn unexpectedly verifies.
    def expect_denied(pcactn, **opts)
      res = fake_verify(pcactn, **opts)
      raise AssertionError, "expectDenied: PCActn verified but was expected to be denied. checks: #{Js.json(res.checks)}" if res.allow

      res
    end

    # An in-memory per-holder state store (replay counter, budget): a drop-in budget store for tests. Nothing persists.
    class MemoryStateStore
      def initialize
        @m = {}
      end

      def get(key) = @m[key]

      def put(key, state)
        @m[key] = state
        nil
      end
    end

    def memory_state_store = MemoryStateStore.new

    # ---- tampering
    def decode_pcactn(s)
      raise ArgumentError, AtlasPca::ARTIFACT_SIZE_REASON if s.is_a?(String) && s.bytesize > AtlasPca::MAX_ARTIFACT_BYTES # FIRST: before any parsing

      v = AtlasPca.parse_json(s)
      raise TypeError, 'decodePCActn: not an object' unless v.is_a?(Hash)

      v
    end

    # Decode an encoded PCActn (strict profile, size-capped), let the block corrupt the Hash in place, then re-encode it so a test can
    # assert the corruption is caught. A change touching the signed body breaks leaf_signature.
    def tamper(encoded)
      rec = decode_pcactn(encoded).dup
      yield rec
      AtlasPca.canonicalize(decode_pcactn(Js.json(rec)))
    end

    # ---- adapter acceptance matrix
    ADAPTER_ACCEPTANCE_AUDIENCE = 'payments-rs'

    def outcome(status, ran, bound) = { 'status' => status, 'handlerRan' => ran, 'bound' => bound }

    # The outcome every adapter must produce per scenario: status, whether the handler ran, whether the attached operation matches.
    ADAPTER_ACCEPTANCE_EXPECTED = {
      'over_limit_predicate' => { 'status' => 403, 'handlerRan' => false, 'bound' => false },
      'over_limit_max_spend' => { 'status' => 403, 'handlerRan' => false, 'bound' => false },
      'body_differs' => { 'status' => 403, 'handlerRan' => false, 'bound' => false },
      'other_operation' => { 'status' => 403, 'handlerRan' => false, 'bound' => false },
      'escalate_unanswered' => { 'status' => 403, 'handlerRan' => false, 'bound' => false },
      'missing_revocation' => { 'status' => 403, 'handlerRan' => false, 'bound' => false },
      'missing_store' => { 'status' => 403, 'handlerRan' => false, 'bound' => false },
      'valid_first' => { 'status' => 200, 'handlerRan' => true, 'bound' => true },
      'replay_second' => { 'status' => 403, 'handlerRan' => false, 'bound' => false }
    }.freeze

    SPECIAL_SCHEMES = %w[http https ftp ws wss file].freeze

    # The pathname of `url` resolved against a base origin as a WHATWG URL parser yields it, for the shapes a request carries
    # (absolute and scheme-relative URLs, rooted and relative paths, dot segments, query, fragment). Raises ArgumentError where the
    # parser rejects the URL. shortcut: percent-encoding of the path is not reproduced (an encoded spelling never equals a route),
    # upgrade if routes ever contain non-ASCII.
    def pathname_of(url)
      s = url.scrub("�").sub(/\A[\x00-\x20]+/, '').sub(/[\x00-\x20]+\z/, '').delete("\t\n\r")
      cut = s.index(/[?#]/) || s.length
      rest = s[0, cut]
      sm = rest.match(/\A([A-Za-z][A-Za-z0-9+.\-]*):/)
      if sm
        scheme = sm[1].downcase
        rest = rest[sm[0].length..]
        if !SPECIAL_SCHEMES.include?(scheme)
          if rest.start_with?('//')
            e = rest.index('/', 2)
            path = e.nil? ? '' : rest[e..]
          elsif rest.start_with?('/')
            path = rest
          else
            return rest # opaque path: never a route
          end
        elsif scheme == 'file'
          rest = rest.tr('\\', '/')
          if rest.start_with?('//')
            e = rest.index('/', 2)
            path = e.nil? ? '/' : rest[e..]
          else
            path = rest.start_with?('/') ? rest : "/#{rest}"
          end
        else
          rest = rest.tr('\\', '/')
          if scheme == 'http' && !rest.start_with?('//') # same scheme as the base: relative
            path = rest.start_with?('/') ? rest : "/#{rest}"
          else
            rest = rest.sub(%r{\A/+}, '')
            e = rest.index('/')
            raise ArgumentError, 'Invalid URL' if (e.nil? ? rest : rest[0, e]).empty?

            path = e.nil? ? '/' : rest[e..]
          end
        end
      else
        rest = rest.tr('\\', '/')
        if rest.start_with?('//')
          t = rest[2..].sub(%r{\A/+}, '')
          e = t.index('/')
          raise ArgumentError, 'Invalid URL' if (e.nil? ? t : t[0, e]).empty?

          path = e.nil? ? '/' : t[e..]
        else
          path = rest.start_with?('/') ? rest : "/#{rest}"
        end
      end
      return '' if path.empty?

      out = []
      segs = path[1..].split('/', -1)
      segs.each_with_index do |seg, i|
        low = seg.downcase
        last = i == segs.length - 1
        if ['..', '.%2e', '%2e.', '%2e%2e'].include?(low)
          out.pop
          out << '' if last
        elsif ['.', '%2e'].include?(low)
          out << '' if last
        else
          out << seg
        end
      end
      "/#{out.join('/')}"
    end

    # The server's mapping from request to operation: a route table on method + path with the JSON body as params. req is
    # {'method', 'url', 'body'}. Returns nil for an unknown route or a body that is not an object, else {verb, resource, params}.
    def acceptance_operation(req)
      url = req['url']
      path = url.is_a?(String) ? pathname_of(url) : ''
      m = req.key?('method') ? Js.string(req['method']) : 'undefined'
      verb = case "#{m.upcase} #{path}"
             when 'POST /payments' then 'payments.send'
             when 'POST /refunds' then 'payments.refund'
             end
      return nil if verb.nil?

      body = req['body']
      return nil unless body.is_a?(Hash)

      { 'verb' => verb, 'resource' => 'payments', 'params' => body }
    end

    PROV_KEY = ("\x03".b * 32).freeze

    def prov_recorder = ProvenanceRecorder.new(mediator: 'adapter-acceptance', kid: 'k1', key: KeyPair.new(PROV_KEY))

    def fixture(limit)
      principal = KeyPair.generate
      holder = KeyPair.generate
      where = %w[predicate escalate].include?(limit) ? [{ 'field' => 'action.params.amount', 'op' => 'lte', 'value' => 100 }] : []
      envelope = {
        'predicates' => [{ 'verb' => %w[payments.send payments.refund], 'resource' => 'payments', 'where' => where }],
        'caveats' => [], 'agent_binding' => {},
        # "spend = risk": each call is priced at amount / 100 and debits the amount from a far-away budget
        'risk_policy' => { 'weights' => { 'alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0 }, 'theta1' => 1,
                           'theta2' => 1, 'kappa' => 100, 'lambda' => 0, 'rho' => 0.5, 'bMax' => 1_000_000 }
      }
      if limit == 'escalate' # a payment over 50 asks the principal; with no answer it is refused
        envelope['tighten'] = [{ 'id' => 'big_payment', 'when' => { 'field' => 'action.params.amount', 'op' => 'gt', 'value' => 50 },
                                 'signal' => 'escalate' }]
      end
      grant = AtlasPca.mint_grant(principal, holder.public, envelope, 'pay invoices')['grant']
      # a ROOT caveat outside the envelope, enforced like a delegated one
      grant = AtlasPca.mint_root(principal, holder.public, grant['caveats'] + [{ 'type' => 'max_spend', 'usd' => 100 }]) if limit == 'max_spend'
      counter = 0
      request = lambda do |signed, sent|
        params = { 'payee' => 'acme', 'amount' => signed['amount'] }
        node = { 'id' => 'n1', 'verb' => signed['verb'], 'resource' => 'payments', 'params_digest' => AtlasPca.params_digest(params),
                 'reversibility_class' => 'irreversible' }
        counter += 1
        p = AtlasPca.build_pcactn(grant: grant, chain: [grant], plan: [node], node_id: 'n1', counter: counter, signer: holder,
                                  aud: ADAPTER_ACCEPTANCE_AUDIENCE, params: params)
        prov = AtlasPca.principal_direct_provenance(prov_recorder, { 'verb' => signed['verb'], 'resource' => 'payments', 'params' => params })
        { 'method' => 'POST', 'path' => sent['path'], 'headers' => AtlasPca.pca_headers(p, provenance: prov).merge('content-type' => 'application/json'),
          'body' => { 'payee' => 'acme', 'amount' => sent['amount'] } }
      end
      options = lambda do |over = {}|
        {
          audience: ADAPTER_ACCEPTANCE_AUDIENCE,
          resolve_grant: ->(ref) { ref == grant['id'] ? grant : nil },
          state_store: AtlasPca::MemoryStateStore.new,
          is_revoked: ->(_p, _g) { false },
          plan: 'single-step',
          risk: lambda do |op, _g, _p|
            amount = ((op['params'] || op[:params]) || {})['amount']
            { 'blastRadius' => [1, (amount.is_a?(Numeric) ? amount.to_f : 0.0) / 100].min, 'semanticDistance' => 0, 'reversibility' => 0, 'taint' => 0,
              'confidence' => 1, 'age' => 0 }
          end,
          provenance: { 'mediators' => [prov_recorder.pin] }
        }.merge(over)
      end
      { 'request' => request, 'options' => options }
    end

    # Run the matrix through `harness` and return the outcomes (compare with ADAPTER_ACCEPTANCE_EXPECTED).
    #
    # harness.call(options) builds the adapter ONCE from `options` (AtlasPca.authorize keyword arguments minus the per-request ones:
    # pass them through unchanged) and returns send.call(req) for one request {'method', 'path', 'headers', 'body'}; send returns
    # {'status', 'handlerRan', 'operation'?} ('operation' = the AuthorizedOperation an allowed call attached). The adapter derives the
    # operation with acceptance_operation({'method', 'url', 'body'}), takes the proof from the PCA-Action header and the bundle from
    # PCA-Provenance.
    def run_adapter_acceptance(harness)
      out = {}
      settle = lambda do |req, o|
        ran = acceptance_operation({ 'method' => req['method'], 'url' => req['path'], 'body' => req['body'] })
        op = o['operation']
        bound = !op.nil? && !ran.nil? && AtlasPca.is_authorized_for(AuthorizeResult.new(allow: true, status: 200, operation: op, decision: 'allow'), ran)
        outcome(o['status'], o['handlerRan'], bound)
      end
      once = lambda do |name, f, req, over = {}|
        out[name] = settle.call(req, harness.call(f['options'].call(over)).call(req))
      end
      pay = ->(f, verb, signed, path, sent) { f['request'].call({ 'verb' => verb, 'amount' => signed }, { 'path' => path, 'amount' => sent }) }

      pred = fixture('predicate')
      spend = fixture('max_spend')
      esc = fixture('escalate')
      once.call('over_limit_predicate', pred, pay.call(pred, 'payments.send', 400, '/payments', 400))
      once.call('over_limit_max_spend', spend, pay.call(spend, 'payments.send', 400, '/payments', 400))
      once.call('body_differs', pred, pay.call(pred, 'payments.send', 50, '/payments', 400))
      once.call('other_operation', pred, pay.call(pred, 'payments.send', 50, '/refunds', 50))
      once.call('escalate_unanswered', esc, pay.call(esc, 'payments.send', 70, '/payments', 70))
      once.call('missing_revocation', pred, pay.call(pred, 'payments.send', 50, '/payments', 50), { is_revoked: nil })
      once.call('missing_store', pred, pay.call(pred, 'payments.send', 50, '/payments', 50), { state_store: nil })
      send = harness.call(pred['options'].call)
      valid = pay.call(pred, 'payments.send', 50, '/payments', 50)
      out['valid_first'] = settle.call(valid, send.call(valid))
      out['replay_second'] = settle.call(valid, send.call(valid))
      out
    end
  end
end
