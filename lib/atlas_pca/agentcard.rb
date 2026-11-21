# frozen_string_literal: true

require_relative 'js_compat'
require_relative 'jose'
require_relative 'oidc'
require_relative 'whatwg_url'
require_relative 'agentcard_card'
require_relative 'acp'

# Signed Agent Cards plus AgentFacts attested by PCA, the well-known hosting handlers and the registry entry, byte-identical to
# the TypeScript reference (@atlasauth/pca-agentcard). The card side (RFC 8785 canonical bytes, the A2A 1.0 schema check, signing)
# is the one in AgentcardCard: a card issued here verifies there and back. Results are Hashes shaped like the reference; handlers
# are callables over a request path. Everything fails closed: a missing signature, an unresolvable key, a tampered body, a bad or
# expired attestation or an attestation about another subject is refused. Option keys are snake_case; documents keep their
# camelCase wire keys.
#
# shortcut: validity windows are parsed as ISO 8601 (YYYY[-MM[-DD]] with an optional THH:mm[:ss[.fff]] and Z or +HH:mm); a time
# without an offset reads as UTC and the legacy free-form date spellings a JavaScript runtime also accepts are refused as not a
# valid date. Widen it if attestations come from issuers that use those.
module AtlasPca
  module Agentcard
    DEFAULT_ALG = 'EdDSA'
    AGENT_FACTS_CONTEXT = ['https://www.w3.org/ns/did/v1', 'https://nanda.ai/agentfacts/v1'].freeze
    PCA_ATTESTOR_ID = 'did:atlas:pca-attestor'
    WELL_KNOWN_AGENT_CARD_PATH = '/.well-known/agent-card.json'
    WELL_KNOWN_AGENT_FACTS_PATH = '/.well-known/agent-facts.json'
    ATTESTATION_DOMAIN = 'atlas-pca/agentfacts/attestation/v1'
    UNDEFINED = AgentcardCard::UNDEFINED

    module_function

    def undef?(v) = v.equal?(UNDEFINED)
    def get(o, k) = AgentcardCard.get(o, k)
    def member(o, k) = AgentcardCard.member(o, k)
    def nullish(v, default) = AgentcardCard.nullish(v, default)
    def truthy(v) = Js.truthy?(undef?(v) ? nil : v)

    def jcs_bytes(value) = AgentcardCard.jcs_bytes(value)
    def validate_agent_card1(card) = AgentcardCard.validate_agent_card1(card)

    # [...x] of a JSON value: an Array is copied, a String splits into characters, anything else is not iterable.
    def iter(x)
      case x
      when Array then x.dup
      when String then x.chars
      else raise TypeError, 'value is not iterable'
      end
    end

    # ---- detached JWS core ----

    def sign_detached(payload, key, alg, kid, header, standard_payload: false)
      alg = DEFAULT_ALG if alg.nil? || undef?(alg)
      k = AgentcardCard.signing_key(key, alg)
      h = { 'alg' => alg }
      if standard_payload
        h['typ'] = 'JOSE'
      else
        h['b64'] = false
        h['crit'] = ['b64']
      end
      h['kid'] = kid unless undef?(kid)
      h.merge!(header || {})
      prot = AgentcardCard.b64u(Js.utf8(Js.json(h)))
      body = standard_payload ? AgentcardCard.b64u(payload) : payload
      { 'protected' => prot, 'signature' => AgentcardCard.b64u(Jose.jws_sign(alg, k, "#{prot}.".b + body.b)) }
    end

    # {'key', 'resolver'} or {'error'}: a JWKS (kid resolved) or a single key, never both.
    def resolve_verify_key(opts)
      if truthy(member(opts, 'jwks'))
        return { 'key' => Oidc.create_local_jwk_set(opts['jwks']), 'resolver' => true }
      end
      if opts.key?('key')
        k = opts['key']
        alg = opts['alg'].nil? ? DEFAULT_ALG : opts['alg']
        return { 'key' => AgentcardCard.jwk?(k) ? AgentcardCard.import_verify_key(k, alg) : k, 'resolver' => false }
      end
      { 'error' => 'no verification key or JWKS supplied' }
    rescue StandardError => e # an unusable key is a refusal, with the library's own words
      { 'error' => "could not resolve verification key: #{e.message}" }
    end

    def verify_detached(payload, sig, resolved)
      raise TypeError, "Cannot read properties of #{sig.nil? ? 'null' : 'undefined'} (reading 'protected')" if sig.nil? || undef?(sig)
      unless sig.is_a?(Hash) && sig['protected'].is_a?(String) && sig['signature'].is_a?(String)
        return { 'ok' => false, 'reason' => 'signature is malformed' }
      end

      begin
        Jose.assert_canonical_jws_segments(sig['protected'], sig['signature']) # canonical-spelling gate BEFORE the signature check
        header = AgentcardCard.payload_header(sig['protected'])
        raw = header['b64'] == false
        body = raw ? payload : AgentcardCard.b64u(payload)
        { 'ok' => true,
          'protectedHeader' => AgentcardCard.flattened_verify(sig['protected'], body, sig['signature'], resolved['key'], resolved['resolver'], raw: raw) }
      rescue StandardError => e # every refusal reads the same
        { 'ok' => false, 'reason' => e.message }
      end
    end

    # ---- signed Agent Card ----

    def passport_ref(p, uri)
      raise TypeError, "Cannot use 'in' operator on a non-object" unless p.is_a?(Hash)

      out = {}
      out['id'] = p['id'] if p.key?('id')
      if p.key?('model_id') # a full AgentPassport: its own uri is not carried
        out['uri'] = uri unless undef?(uri)
      elsif p.key?('uri')
        out['uri'] = p['uri']
      elsif !undef?(uri)
        out['uri'] = uri
      end
      out
    end

    # An unsigned Agent Card whose metadata points at the PCA passport ('pcaPassport') and, when given, the live proof endpoint
    # ('pcaProof'). passport is a full passport or a bare {id, uri?} reference. opts: name, description, url, version, skills,
    # passport_uri, pca_proof_ref.
    def build_agent_card(passport, opts)
      card = {}
      card['name'] = opts['name'] if opts.key?('name')
      %w[description url version skills].each { |k| card[k] = opts[k] if opts.key?(k) }
      card['pcaPassport'] = passport_ref(passport, member(opts, 'passport_uri'))
      card['pcaProof'] = opts['pca_proof_ref'] if opts.key?('pca_proof_ref')
      card
    end

    # Sign a card: the passport reference is embedded and committed in the protected header, the canonical card (minus
    # 'signatures') is signed and the detached-payload signature appended. Wire-identical to AgentcardCard.issue_signed_agent_card.
    def issue_signed_agent_card(card, signing_key, opts = nil) = AgentcardCard.issue_signed_agent_card(card, signing_key, opts)

    # Validate a card against its signature(s): no signatures, an unresolvable key or ANY signature that does not verify over the
    # canonical card (minus 'signatures') refuses. opts: jwks, key, alg, schema. On success the result names the passport id the
    # signature commits to and the passport and proof pointers from the card body.
    def verify_agent_card(card, opts)
      return { 'ok' => false, 'reason' => 'agent card is not an object' } unless card.is_a?(Hash) || card.is_a?(Array)

      signatures = card.is_a?(Hash) ? card['signatures'] : nil
      return { 'ok' => false, 'reason' => 'agent card carries no signatures' } unless signatures.is_a?(Array) && !signatures.empty?

      if opts['schema'] == 'a2a-1.0'
        problems = validate_agent_card1(card)
        unless problems.empty?
          return { 'ok' => false, 'reason' => "agent card does not match the A2A 1.0 schema: #{problems.join('; ')}" }
        end
      end
      resolved = resolve_verify_key(opts)
      return { 'ok' => false, 'reason' => resolved['error'] } if resolved.key?('error')

      payload = begin
        AgentcardCard.card_bytes(card)
      rescue TypeError => e
        return { 'ok' => false, 'reason' => "agent card has no canonical form: #{e.message}" }
      end
      ref_out = nil
      signatures.each_with_index do |sig, i|
        return { 'ok' => false, 'reason' => "signature #{i} is missing" } unless truthy(sig)

        res = verify_detached(payload, sig, resolved)
        return { 'ok' => false, 'reason' => "signature #{i} did not verify: #{res['reason']}" } unless res['ok']

        ref = res['protectedHeader'][AgentcardCard::PCA_PASSPORT_HEADER]
        ref_out = ref if ref.is_a?(String) && ref_out.nil?
      end
      out = { 'ok' => true }
      out['passportRef'] = ref_out unless ref_out.nil?
      out['passport'] = card['pcaPassport'] if truthy(card['pcaPassport'])
      out['pcaProof'] = card['pcaProof'] if truthy(card['pcaProof'])
      out
    end

    # ---- dates ----

    ISO = /\A([+-][0-9]{6}|[0-9]{4})(?:-([0-9]{2})(?:-([0-9]{2}))?)?(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?(Z|[+-][0-9]{2}:[0-9]{2})?)?\z/n

    def days_from_civil(y, m, d)
      y -= 1 if m <= 2
      era = y.div(400)
      yoe = y - (era * 400)
      doy = ((153 * (m + (m > 2 ? -3 : 9))) + 2).div(5) + d - 1
      (era * 146_097) + (yoe * 365) + yoe.div(4) - yoe.div(100) + doy - 719_468
    end

    # Date.parse for the ISO 8601 spellings (epoch milliseconds), nil for anything else (NaN in the reference).
    def date_parse(str)
      return nil unless str.is_a?(String)

      m = ISO.match(str.b)
      return nil if m.nil?

      ys, mo, d, hh, mi, ss, frac, tz = m.captures
      return nil if ys == '-000000'

      y = ys.to_i
      mo_i = mo ? mo.to_i : 1
      d_i = d ? d.to_i : 1
      h_i = hh ? hh.to_i : 0
      mi_i = mi ? mi.to_i : 0
      s_i = ss ? ss.to_i : 0
      ms = frac ? "#{frac}00"[0, 3].to_i : 0
      return nil if !mo_i.between?(1, 12) || !d_i.between?(1, 31) || mi_i > 59 || s_i > 59 || h_i > 24
      return nil if h_i == 24 && (mi_i.positive? || s_i.positive? || ms.positive?)

      off = 0
      if tz && tz != 'Z'
        oh = tz[1, 2].to_i
        om = tz[4, 2].to_i
        return nil if oh > 23 || om > 59

        off = ((oh * 60) + om) * (tz[0] == '+' ? 1 : -1)
      end
      t = (((days_from_civil(y, mo_i, d_i) * 86_400) + (h_i * 3600) + (mi_i * 60) + s_i) * 1000) + ms - (off * 60_000)
      t.abs <= 8.64e15 ? t.to_f : nil
    end

    # ---- AgentFacts ----

    def statement_bytes(a)
      AtlasPca.canon_bytes({ 'd' => ATTESTATION_DOMAIN, 'issuer' => member(a, 'issuer'), 'subject' => member(a, 'subject'),
                             'attests' => member(a, 'attests'), 'validFrom' => member(a, 'validFrom'),
                             'validUntil' => a.key?('validUntil') ? a['validUntil'] : nil })
    end

    def sign_attestation(statement, key, opts)
      sig = sign_detached(statement_bytes(statement), key, opts['alg'], opts.key?('kid') ? opts['kid'] : UNDEFINED,
                          { 'attestor' => statement['issuer'] })
      statement.merge('signature' => sig)
    end

    def statement(issuer, subject, opts)
      valid_from = member(opts, 'valid_from')
      valid_from = Acp.iso_from_ms(nullish(member(opts, 'now'), Acp.now_ms)) if valid_from.nil? || undef?(valid_from)
      st = { 'issuer' => issuer, 'subject' => subject, 'attests' => member(opts, 'attests'), 'validFrom' => valid_from }
      st['validUntil'] = opts['valid_until'] if opts.key?('valid_until')
      st
    end

    # An AgentFacts document with PCA as the THIRD-PARTY ATTESTOR: the agent's selfAsserted claims are carried verbatim and
    # unsigned, the attests claims are wrapped in a signed statement (issuer, subject, validity). opts: attestor_key, attests,
    # self_asserted, attestor_id, agent_id, alg, kid, valid_from, valid_until, now, context.
    def issue_agent_facts(passport, opts)
      agent_id = member(opts, 'agent_id')
      agent_id = get(passport, 'id') if agent_id.nil? || undef?(agent_id)
      st = statement(nullish(member(opts, 'attestor_id'), PCA_ATTESTOR_ID), agent_id, opts)
      att = sign_attestation(st, member(opts, 'attestor_key'), opts)
      out = { '@context' => iter(nullish(member(opts, 'context'), AGENT_FACTS_CONTEXT)), 'id' => agent_id, 'type' => 'AgentFacts',
              'selfAsserted' => nullish(member(opts, 'self_asserted'), {}), 'attestations' => [att] }
      out.reject { |_, v| undef?(v) }
    end

    # A copy of an AgentFacts document with one more third-party attestation (several attestors vouch for different claims).
    def add_attestation(facts, opts)
      st = statement(nullish(member(opts, 'attestor_id'), PCA_ATTESTOR_ID), get(facts, 'id'), opts)
      att = sign_attestation(st, member(opts, 'attestor_key'), opts)
      existing = get(facts, 'attestations')
      prior = case existing
              when Array then existing.dup
              when String then AgentcardCard.spread(existing).values
              else raise TypeError, 'facts.attestations is not iterable'
              end
      out = AgentcardCard.spread(facts)
      out['attestations'] = prior + [att]
      out
    end

    def missing_check(a)
      { 'issuer' => a.is_a?(Hash) && a['issuer'].is_a?(String) ? a['issuer'] : '<unknown>', 'ok' => false,
        'reason' => 'no verification key or JWKS supplied' }
    end

    def verify_one(a, doc_id, now, resolved)
      issuer = a.is_a?(Hash) && a['issuer'].is_a?(String) ? a['issuer'] : '<unknown>'
      unless a.is_a?(Hash) && a['subject'].is_a?(String) && a['attests'].is_a?(Hash) && a['validFrom'].is_a?(String)
        return { 'issuer' => issuer, 'ok' => false, 'reason' => 'attestation is malformed' }
      end
      if a['subject'] != doc_id || !doc_id.is_a?(String)
        return { 'issuer' => issuer, 'ok' => false,
                 'reason' => "attestation subject '#{a['subject']}' does not match agent id '#{undef?(doc_id) ? 'undefined' : Js.string(doc_id)}'" }
      end

      start = date_parse(a['validFrom'])
      return { 'issuer' => issuer, 'ok' => false, 'reason' => 'attestation validFrom is not a valid date' } if start.nil?
      return { 'issuer' => issuer, 'ok' => false, 'reason' => 'attestation is not yet valid' } unless Acp.finite?(now) && now >= start

      if a.key?('validUntil')
        till = date_parse(a['validUntil'])
        return { 'issuer' => issuer, 'ok' => false, 'reason' => 'attestation validUntil is not a valid date' } if till.nil?
        return { 'issuer' => issuer, 'ok' => false, 'reason' => 'attestation has expired' } unless now <= till
      end
      return { 'issuer' => issuer, 'ok' => false, 'reason' => 'no verification key or JWKS supplied' } if resolved.nil?

      res = verify_detached(statement_bytes(a), member(a, 'signature'), resolved)
      return { 'issuer' => issuer, 'ok' => false, 'reason' => "signature did not verify: #{res['reason']}" } unless res['ok']

      { 'issuer' => issuer, 'ok' => true, 'attests' => a['attests'] }
    end

    # Verify an AgentFacts document, failing closed: an attestation about another subject, outside its validity window or whose
    # detached signature does not verify refuses, and any one failure fails the whole document. On success the result separates
    # the claims a third party ATTESTS from those only SELF-ASSERTED (flagged, never promoted). opts: jwks, key, alg, now (epoch ms).
    def verify_agent_facts(facts, opts)
      sa_raw = get(facts, 'selfAsserted')
      self_asserted = sa_raw.is_a?(Hash) ? sa_raw : {}
      now = nullish(member(opts, 'now'), Acp.now_ms)
      doc_id = get(facts, 'id')
      base = { 'ok' => false, 'attestations' => [], 'attested' => {}, 'selfAsserted' => self_asserted, 'claims' => {} }
      base['agentId'] = doc_id unless undef?(doc_id)
      lst = get(facts, 'attestations')
      return base.merge('reason' => 'agent facts has no attestations array') unless lst.is_a?(Array)

      resolved = nil
      unless lst.empty?
        r = resolve_verify_key(opts)
        return base.merge('reason' => r['error'], 'attestations' => lst.map { |a| missing_check(a) }) if r.key?('error')

        resolved = r
      end
      checks = []
      attested = {}
      all_ok = true
      lst.each do |a|
        c = verify_one(a, doc_id, now, resolved)
        checks << c
        unless c['ok']
          all_ok = false
          next
        end
        attested.update(c['attests'])
      end
      claims = {}
      self_asserted.each_key { |k| claims[k] = 'self-asserted' }
      attested.each_key { |k| claims[k] = 'attested' } # attested wins on overlap
      out = base.merge('ok' => all_ok, 'attestations' => checks, 'attested' => attested, 'claims' => claims)
      out['reason'] = 'one or more attestations did not verify' unless all_ok
      out
    end

    # ---- well-known hosting ----

    def json_response(value)
      { 'status' => 200, 'headers' => { 'content-type' => 'application/json', 'cache-control' => 'no-store' }, 'body' => Js.json(value) }
    end

    def normalize_path(path)
      q = path.index('?')
      no_query = q.nil? ? path : path[0, q]
      no_query.length > 1 && no_query.end_with?('/') ? no_query[0...-1] : no_query
    end

    def handler(value, path)
      target = normalize_path(path)
      response = json_response(value)
      ->(req_path) { normalize_path(req_path) == target ? response : nil }
    end

    # A handler serving the signed card at the well-known path; it returns nil for any other path so it composes in a router.
    def agent_card_handler(card, path = WELL_KNOWN_AGENT_CARD_PATH) = handler(card, path)

    # A handler serving the AgentFacts document at the well-known path; nil for any other path.
    def agent_facts_handler(facts, path = WELL_KNOWN_AGENT_FACTS_PATH) = handler(facts, path)

    # ---- registry entry ----

    SPECIAL = %w[ftp file http https ws wss].freeze
    USERINFO_ENC = "\"<>`{}?/:;=@[\\]^|"

    # new URL(path, serviceUrl).toString() for an absolute path: the base's scheme, credentials and host with the path; nil where
    # the platform URL class would refuse (an invalid base, or one that cannot be a base).
    def well_known_url(service_url, path)
      return nil unless service_url.is_a?(String)

      r = WhatwgUrl.parse(service_url)
      return nil if r.nil?

      text = service_url.scrub("�").sub(/\A[\x00-\x20]+/, '').sub(/[\x00-\x20]+\z/, '').delete("\t\n\r")
      scheme = r['scheme']
      rest = text[(text.index(':') + 1)..]
      special = SPECIAL.include?(scheme)
      return nil if !special && !rest.start_with?('//')

      body = special && scheme != 'file' ? rest.sub(%r{\A[/\\]+}, '') : rest[2..]
      authority = special ? body[%r{\A[^/\\?#]*}] : body[%r{\A[^/?#]*}]
      userinfo = ''
      if authority.include?('@') && scheme != 'file'
        user, _sep, pw = authority.rpartition('@')[0].partition(':')
        userinfo = "#{WhatwgUrl.pct(user, USERINFO_ENC)}#{pw.empty? ? '' : ":#{WhatwgUrl.pct(pw, USERINFO_ENC)}"}@"
        userinfo = '' if user.empty? && pw.empty?
      end
      "#{scheme}://#{userinfo}#{r['host']}#{path}"
    end

    # The entry for an A2A registry or NANDA index from a signed card and an AgentFacts document, with the split of claim names a
    # third party ATTESTS from those only SELF-ASSERTED. Purely structural: a registry re-verifies on ingest.
    def to_registry_entry(card, facts)
      attested = {}
      atts = get(facts, 'attestations')
      atts = [] if atts.nil? || undef?(atts) || atts.is_a?(String) # a string iterates characters, none of which carries claims
      raise TypeError, 'facts.attestations is not iterable' unless atts.is_a?(Array)

      atts.each do |a|
        Js.js_keys(a['attests']).each { |k| attested[k] = nil } if truthy(a) && a.is_a?(Hash) && a['attests'].is_a?(Hash)
      end
      sa = get(facts, 'selfAsserted')
      self_only = (sa.is_a?(Hash) ? Js.js_keys(sa) : []).reject { |k| attested.key?(k) }
      url = get(card, 'url')
      card_url = undef?(url) ? nil : well_known_url(url, WELL_KNOWN_AGENT_CARD_PATH)
      entry = { 'id' => get(facts, 'id'), 'name' => get(card, 'name') }
      %w[url version skills].each { |k| entry[k] = get(card, k) }
      entry['passport'] = card['pcaPassport'] if truthy(get(card, 'pcaPassport'))
      entry['pcaProof'] = card['pcaProof'] if truthy(get(card, 'pcaProof'))
      entry['card'] = card
      entry['agentCardUrl'] = card_url unless card_url.nil?
      entry['facts'] = facts
      entry['attestedClaims'] = attested.keys
      entry['selfAssertedClaims'] = self_only
      entry.reject { |_, v| undef?(v) }
    end
  end
end
