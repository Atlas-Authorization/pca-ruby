# frozen_string_literal: true

# The deterministic suggestion layer (native port of the suggestion rules of the TypeScript reference @atlasauth/pca-actions). A versioned
# rule set proposes traits, param roles and param tags for a draft def. Union only: a suggestion can ADD a trait, a role (to a param that
# has none) or a tag, never remove or replace anything, and it never marks a def confirmed. A suggested def is still `pca.unreviewed` for
# floor purposes; suggestions only improve the card and the review queue. `path_re` is a JavaScript regular expression (see
# actions_import_jsre).
require_relative 'actions_import_common'
require_relative 'actions_import_jsre'
require_relative 'actions_import_rules_data'
require_relative 'agent'

module AtlasPca
  module ActionsImportSuggest
    C = AtlasPca::ActionsImportCommon
    A = C::A
    J = C::J
    U16 = C::U16
    UNDEF = C::UNDEF
    Err = C::Err
    JSRE = AtlasPca::ActionsImportJsre

    SUGGEST_RULES_KIND = 'pca-suggest-rules'
    SUGGEST_RULES_DOMAIN = 'atlas-pca/suggest-rules/v1'
    RULE_ID_RE = /\ASR-[0-9]{3,4}\z/
    VERSION_RE = /\A[0-9]+\.[0-9]+\.[0-9]+\z/
    MATCH_KEYS = %w[methods path_re name_tokens name_tokens_strict param_names param_names_all param_types param_formats roles effects].freeze
    PARAM_TYPES = %w[string integer boolean date datetime duration set array object_ref].freeze
    MAX_RULES = 1024
    MAX_LIST = 64
    # a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
    NESTED_QUANTIFIER = /\([^)]*[+*][^)]*\)[+*{]|\([^)]*\|[^)]*\)[+*{]/
    BACKREF = /\\[1-9]/
    LOOKAROUND = /\(\?[<=!]/
    SEP = '|'
    INT_ROLES = %w[money.amount money.fee count.limit bytes.size].freeze
    EMPTY_SUGGESTION = { 'traits' => [], 'roles' => {}, 'tags' => {}, 'fired' => [] }.freeze

    module_function

    def one?(v) = AtlasPca::Js.num?(v) && v == 1

    def str_list?(v, mx = MAX_LIST)
      v.is_a?(Array) && !v.empty? && v.length <= mx && v.all? { |x| x.is_a?(String) && J.u16len(x).positive? && J.u16len(x) <= 64 }
    end

    # Python truthiness of a JSON value ({} and [] are falsy there; the reference reads them as truthy only through `||` fallbacks)
    def pyfalsy?(x) = x.nil? || x == false || x == 0 || x == '' || x == [] || x == {}

    # `for x in v` over a JSON value: an array's elements, an object's keys, a string's code points
    def iter(v)
      case v
      when Array then v
      when Hash then v.keys
      when String then U16.to_pua(v).each_char.map { |ch| U16.from_pua(ch) }
      else raise TypeError, 'value is not iterable'
      end
    end

    def u16sort(xs) = iter(xs).sort_by { |s| U16.units(s) }

    # None if the rule set is well formed: closed members, unique ids, safe regular expressions, known trait/role/tag names.
    def suggest_rules_error(r, known = nil)
      return 'rules must be an object' unless r.is_a?(Hash)

      r.each_key { |k| return "unknown member '#{k}'" unless %w[v kind version rules digest sig].include?(k) }
      return 'not a suggest-rules document (v 1)' if !one?(r['v']) || r['kind'] != SUGGEST_RULES_KIND
      return 'version must be semver' if !r['version'].is_a?(String) || !J.rx?(VERSION_RE, r['version'])

      rules = r['rules']
      return "rules must be 1..#{MAX_RULES} entries" if !rules.is_a?(Array) || rules.empty? || rules.length > MAX_RULES

      ids = {}
      rules.each do |rule|
        return 'a rule must be an object' unless rule.is_a?(Hash)

        rule.each_key { |k| return "rule: unknown member '#{k}'" unless %w[id match adds note].include?(k) }
        rid = rule['id']
        return 'rule ids must be unique SR-nnn' if !rid.is_a?(String) || !J.rx?(RULE_ID_RE, rid) || ids.key?(rid)

        ids[rid] = true
        w = rid
        note = rule['note']
        return "#{w}: note must be 1..200 characters" if !note.is_a?(String) || J.u16len(note).zero? || J.u16len(note) > 200

        m = rule['match']
        return "#{w}: match must be a non-empty object" if !m.is_a?(Hash) || m.empty?

        m.each_key { |k| return "#{w}: unknown match member '#{k}'" unless MATCH_KEYS.include?(k) }
        %w[methods name_tokens name_tokens_strict param_names param_names_all param_formats roles].each do |k|
          return "#{w}: match.#{k} must be 1..#{MAX_LIST} short strings" if m.key?(k) && !str_list?(m[k])
        end
        return "#{w}: methods are uppercase" if m.key?('methods') && !m['methods'].all? { |s| (u = U16.to_pua(s)) == u.upcase }
        if m.key?('param_types') && (!str_list?(m['param_types']) || !m['param_types'].all? { |t| PARAM_TYPES.include?(t) })
          return "#{w}: match.param_types is not a list of param types"
        end
        return "#{w}: match.effects must be a list of effects" if m.key?('effects') && !str_list?(m['effects'], 12)

        if m.key?('path_re')
          p = m['path_re']
          return "#{w}: path_re must be 1..128 characters" if !p.is_a?(String) || J.u16len(p).zero? || J.u16len(p) > 128

          pp = U16.to_pua(p)
          if NESTED_QUANTIFIER.match?(pp) || BACKREF.match?(pp) || LOOKAROUND.match?(pp)
            return "#{w}: path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)"
          end

          begin
            JSRE.compile_js(p)
          rescue JSRE::JsReError
            return "#{w}: path_re is not a regular expression"
          end
        end
        has_param = m.key?('param_names') || m.key?('param_names_all') || m.key?('param_formats') || m.key?('roles')
        if m.key?('param_types') && !m.key?('param_names') && !m.key?('param_formats') && !m.key?('param_names_all')
          return "#{w}: param_types needs param_names, param_names_all or param_formats"
        end
        return "#{w}: adds must be 1..16 entries" unless str_list?(rule['adds'], 16)

        rule['adds'].each do |a|
          if a.b.start_with?('tag:')
            return "#{w}: unknown tag '#{a}'" unless A::PARAM_TAGS.include?(a[4..])
            return "#{w}: a tag needs a param matcher" unless has_param
          elsif A.role?(a)
            return "#{w}: a role needs a param matcher" unless has_param
          elsif J.rx?(A::TRAIT_ID_RE, a)
            return "#{w}: unknown trait '#{a}'" if !known.nil? && !known.include?(a)
          else
            return "#{w}: '#{a}' is not a trait, role or tag:"
          end
        end
      end
      nil
    end

    # b64u sha256 of the strict canonical rule set (without digest and sig).
    def rules_digest(r)
      AtlasPca.hash_canonical({ 'd' => SUGGEST_RULES_DOMAIN, 'rules' => { 'v' => r['v'], 'kind' => r['kind'], 'version' => r['version'], 'rules' => r['rules'] } })
    end

    def seal_rules(r) = r.merge('digest' => rules_digest(r))
    def rules_message(digest) = "#{SUGGEST_RULES_DOMAIN}\0".b + AtlasPca.canon_bytes({ 'digest' => digest })

    # Sign a rule set as the rules publisher (a release step; the signature covers the digest).
    def sign_rules(r, kid, secret)
      bad = suggest_rules_error(r)
      raise Err.new('bad_rules', bad) if bad

      sealed = seal_rules(r)
      sealed.merge('sig' => { 'alg' => 'ed25519', 'kid' => kid, 'value' => AtlasPca.b64e(AtlasPca::KeyPair.new(secret.b).sign(rules_message(sealed['digest']))) })
    end

    # Verify a signed rule set against pinned publisher keys: shape, digest, signature. Never raises.
    def verify_rules(doc, pins)
      bad = suggest_rules_error(doc)
      return { 'ok' => false, 'reason' => bad } if bad
      return { 'ok' => false, 'reason' => 'digest does not match the rules' } if doc['digest'] != rules_digest(doc)

      sig = doc.fetch('sig', UNDEF)
      return { 'ok' => false, 'reason' => 'the rule set is not signed' } unless J.truthy?(sig)

      kid = sig.is_a?(Hash) ? sig.fetch('kid', UNDEF) : UNDEF
      k = iter(pins).find { |p| p.is_a?(Hash) && !kid.equal?(UNDEF) && p.key?('kid') && p['kid'] == kid }
      return { 'ok' => false, 'reason' => "no pinned rules key '#{J.js_str(kid)}'" } if k.nil?

      value = sig.is_a?(Hash) ? sig.fetch('value', UNDEF) : UNDEF
      AtlasPca.verify_b64u(k['pk'], rules_message(doc['digest']), value) ? { 'ok' => true } : { 'ok' => false, 'reason' => 'rules signature invalid' }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "rules verification error: #{e.message}" }
    end

    # ---- facts
    # Light stemmer: plural, -ing, -ed and a trailing -e fold together (`charges`, `charged`, `charging` -> `charg`).
    def stem(t)
      s = U16.to_pua(t)
      if s.length > 4 && s.end_with?('ies')
        s = "#{s[0...-3]}y"
      elsif s.match?(/(?:ss|x|z|ch|sh)es\z/) && s.length > 4
        s = s[0...-2]
      elsif s.length > 3 && s.end_with?('s') && !s.end_with?('ss')
        s = s[0...-1]
      end
      if s.length > 5 && s.end_with?('ing')
        s = s[0...-3]
      elsif s.length > 4 && s.end_with?('ed')
        s = s[0...-2]
      end
      s = s[0...-1] if s.length > 3 && s.end_with?('e')
      U16.from_pua(s)
    end

    def path_tokens(p) = U16.to_pua(p).split('/').reject { |s| s.empty? || s.include?('{') || s.include?('}') }.flat_map { |s| C.tokens_of(s) }

    def facts_of(d)
      b = d['bindings']
      b = {} if pyfalsy?(b)
      methods = []
      locs = []
      src = []
      path_src = []
      src << (d['verb'].split('.', -1)[1..] || []).flat_map { |s| C.tokens_of(s) }
      al = d['aliases']
      al = [] if pyfalsy?(al)
      al.each { |a| src << C.tokens_of(a) }
      src << C.tokens_of(d['title'])
      unless pyfalsy?(b['openapi'])
        o = b['openapi']
        src << C.tokens_of(o.fetch('operationId', UNDEF))
        methods << o['method'].upcase unless pyfalsy?(o['method'])
        unless pyfalsy?(o['path'])
          locs << o['path']
          path_src << src.length
          src << path_tokens(o['path'])
        end
      end
      unless pyfalsy?(b['http'])
        methods << b['http']['method'].upcase
        locs << b['http']['path']
        path_src << src.length
        src << path_tokens(b['http']['path'])
      end
      unless pyfalsy?(b['mcp'])
        locs << b['mcp']['tool']
        src << C.tokens_of(b['mcp']['tool'])
      end
      unless pyfalsy?(b['graphql'])
        methods << b['graphql']['op'].upcase
        locs << b['graphql']['field']
        src << C.tokens_of(b['graphql']['field'])
      end
      unless pyfalsy?(b['grpc'])
        locs << "#{b['grpc']['service']}/#{b['grpc']['method']}"
        src << C.tokens_of(b['grpc']['service'])
        src << C.tokens_of(b['grpc']['method'])
      end
      unless pyfalsy?(b['asyncapi'])
        methods << b['asyncapi']['op'].upcase
        locs << b['asyncapi']['channel']
        src << C.tokens_of(b['asyncapi']['channel'])
      end
      tokens = []
      strict = []
      src.each_with_index do |s, i|
        tokens << SEP unless tokens.empty?
        tokens.concat(s.map { |x| stem(x) })
        next if path_src.include?(i)

        strict << SEP unless strict.empty?
        strict.concat(s.map { |x| stem(x) })
      end
      params = u16sort(d['params']).map do |name|
        p = d['params'][name]
        e = { 'name' => name, 'tokens' => C.tokens_of(name).map { |x| stem(x) }, 'type' => p['type'] }
        e['format'] = p['format'] unless pyfalsy?(p['format'])
        e['role'] = p['role'] unless pyfalsy?(p['role'])
        e
      end
      { 'methods' => methods.uniq, 'locs' => locs.map { |x| U16.slice(x, 512) }, 'tokens' => tokens, 'strict' => strict, 'params' => params,
        'effects' => iter(d['effects']).uniq }
    end

    def has_seq?(hay, pat)
      return false if pat.empty?

      (0..(hay.length - pat.length)).any? { |i| hay[i, pat.length] == pat }
    end

    def pat_of(s) = C.tokens_of(s).map { |t| stem(t) }

    def role_fits?(role, typ)
      return typ == 'integer' if INT_ROLES.include?(role)
      return %w[date datetime integer].include?(typ) if role.b.start_with?('time.')

      typ == 'string'
    end

    def trait_add?(a) = !a.b.start_with?('tag:') && !A.role?(a)

    # Run the rules over a def. Only trait ids in `registry` (when given) can be suggested. Pure and deterministic.
    def suggest_with_rules(d, rules, registry = nil)
      f = facts_of(d)
      traits = []
      roles = {}
      tags = {}
      fired = []
      stems = f['tokens']
      rules['rules'].each do |rule|
        m = rule['match']
        next if J.truthy?(m['methods']) && !iter(m['methods']).any? { |x| f['methods'].include?(x) }
        next if J.truthy?(m['effects']) && !iter(m['effects']).any? { |e| f['effects'].include?(e) }
        next if J.truthy?(m['name_tokens']) && !iter(m['name_tokens']).any? { |p| has_seq?(stems, pat_of(p)) }
        next if J.truthy?(m['name_tokens_strict']) && !iter(m['name_tokens_strict']).any? { |p| has_seq?(f['strict'], pat_of(p)) }

        if J.truthy?(m['path_re'])
          rx = JSRE.compile_js(m['path_re'])
          next unless f['locs'].any? { |loc| JSRE.js_test(rx, loc) }
        end
        next if J.truthy?(m['roles']) && !f['params'].any? { |p| p.key?('role') && iter(m['roles']).include?(p['role']) }

        matched = []
        if !m['param_names'].nil? || !m['param_formats'].nil?
          pats = (pyfalsy?(m['param_names']) ? [] : iter(m['param_names'])).map { |x| pat_of(x) }
          f['params'].each do |p|
            next if J.truthy?(m['param_types']) && !iter(m['param_types']).include?(p['type'])
            next if J.truthy?(m['param_names']) && !pats.any? { |q| has_seq?(p['tokens'], q) }
            next if J.truthy?(m['param_formats']) && (!p.key?('format') || !iter(m['param_formats']).include?(p['format']))

            matched << p
          end
          next if matched.empty?
        end
        if J.truthy?(m['param_names_all'])
          ok = true
          iter(m['param_names_all']).each do |n|
            q = pat_of(n)
            unless f['params'].any? { |p| has_seq?(p['tokens'], q) && (!J.truthy?(m['param_types']) || iter(m['param_types']).include?(p['type']) || p['type'] == 'string') }
              ok = false
              break
            end
          end
          next unless ok
        end
        fired << rule['id']
        rule['adds'].each do |a|
          if a.b.start_with?('tag:')
            matched.each { |p| tags[p['name']] = (tags[p['name']] || []) | [a[4..]] }
          elsif trait_add?(a)
            traits << a if (registry.nil? || registry.key?(a)) && !traits.include?(a)
          else
            matched.each { |p| roles[p['name']] = a if !p.key?('role') && !roles.key?(p['name']) && role_fits?(a, p['type']) }
          end
        end
      end
      traits.delete('pca.unreviewed')
      { 'traits' => u16sort(traits), 'roles' => roles, 'tags' => u16sort(tags.keys).to_h { |k| [k, u16sort(tags[k])] }, 'fired' => fired }
    end

    # Union two suggestions (the restrictive direction, so no intersection is needed).
    def union_suggestions(a, b)
      tags = {}
      (a['tags'].keys | b['tags'].keys).each { |k| tags[k] = u16sort(((a['tags'][k] || []) | (b['tags'][k] || []))) }
      { 'traits' => u16sort(a['traits'] | b['traits']), 'roles' => b['roles'].merge(a['roles']), 'tags' => tags, 'fired' => a['fired'] + b['fired'] }
    end

    # Apply a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one, tags are added; nothing is
    # removed or replaced, no attestation is created, and `review.state` goes from `unreviewed` to `suggested`.
    def apply_suggestion(d, s, by)
      params = {}
      added_roles = {}
      added_tags = {}
      d['params'].each do |name, p|
        q = p
        role = s['roles'][name]
        if !role.nil? && !p.key?('role') && role_fits?(role, p['type'])
          q = q.merge('role' => role)
          added_roles[name] = role
        end
        t = s['tags'][name]
        unless t.nil?
          have = pyfalsy?(p['tags']) ? [] : p['tags']
          fresh = t.reject { |x| have.include?(x) }
          unless fresh.empty?
            q = q.merge('tags' => u16sort(have | fresh))
            added_tags[name] = fresh
          end
        end
        params[name] = q
      end
      dt = pyfalsy?(d['traits']) ? [] : d['traits']
      fresh_traits = s['traits'].reject { |t| dt.include?(t) }
      # a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
      idem = d['idempotency']
      if s['traits'].include?('pca.money_moving') && (idem.nil? || idem['mode'] == 'none')
        idem = { 'mode' => 'key_param', 'param' => 'idempotency_key' }
        params['idempotency_key'] = { 'type' => 'string', 'max_len' => 64, 'required' => false } unless params.key?('idempotency_key')
      end
      review = d['review']
      prev = pyfalsy?(review['suggested_by']) ? {} : review['suggested_by']
      prev_added = pyfalsy?(prev['added']) ? { 'traits' => [], 'roles' => {}, 'tags' => {} } : prev['added']
      added = {
        'traits' => u16sort(prev_added['traits'] | fresh_traits),
        'roles' => prev_added['roles'].merge(added_roles),
        'tags' => u16sort(prev_added['tags'].keys | added_tags.keys).to_h { |k| [k, u16sort((prev_added['tags'][k] || []) | (added_tags[k] || []))] }
      }
      rules = pyfalsy?(by['rules']) ? prev['rules'] : by['rules']
      models = (pyfalsy?(prev['models']) ? [] : prev['models']) + (pyfalsy?(by['models']) ? [] : by['models'])
      suggested_by = {}
      suggested_by['rules'] = rules unless pyfalsy?(rules)
      suggested_by['models'] = models unless models.empty?
      suggested_by['added'] = added
      state = %w[unreviewed suggested].include?(review['state']) ? 'suggested' : review['state']
      out = d.merge('params' => params)
      out['idempotency'] = idem unless idem.nil?
      out['traits'] = u16sort(dt | s['traits']) if !fresh_traits.empty? || !dt.empty?
      out['review'] = review.merge('state' => state, 'suggested_by' => suggested_by)
      out
    end

    def default_rules = AtlasPca::ActionsImportRulesData::DEFAULT_RULES_JSON
    def default_rules_sealed = seal_rules(default_rules)
  end
end
