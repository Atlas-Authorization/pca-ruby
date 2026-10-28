# frozen_string_literal: true

# Action-kit registry layer (native port): signed evolution records, principal re-approvals, the grant pin decision, signed packs
# (with shards), the rollback tracker and rule 22 over a whole v2 document. Natives verify signatures, digests and pins; they do NOT
# recompute the semantic diff. Pure and total: malformed input is a refusal.

module AtlasPca
  module ActionsRegistry
    A = AtlasPca::Actions
    IV = AtlasPca::IntentV2
    UNDEF = AtlasPca::V2JS::UNDEF

    ACTION_PACK_KIND = 'pca-action-pack'
    ACTION_PIN_ON_NEW = %w[deny escalate].freeze
    EVOLUTION_CLASSES = %w[equal narrow widen incomparable added removed].freeze
    EVOLUTION_RECORD_KIND = 'pca-evolution-record'
    REAPPROVAL_KIND = 'pca-reapproval'
    EVOLUTION_DOMAIN = "atlas-pca/action-evolution/v1\0"
    EVOLUTION_DIFF_DOMAIN = 'atlas-pca/action-evolution-diff/v1'
    REAPPROVAL_DOMAIN = "atlas-pca/action-reapproval/v1\0"
    MAX_EVOLUTION_STEPS = 32
    MAX_ESC_TIER = 3
    PACK_SIG_DOMAIN = "atlas-pca/action-pack/v1\0"
    PACK_REF_DOMAIN = 'atlas-pca/action-pack-ref/v1'
    PACK_SHARD_DOMAIN = 'atlas-pca/action-pack-shard/v1'
    RULES_DIGEST_DOMAIN = 'atlas-pca/action-rules/v1'
    PACK_SHARD_KIND = 'pca-action-pack-shard'
    STABILITIES = %w[draft beta stable].freeze
    MAX_EVOLUTION_RECORDS = 65_536

    B64U_43 = /\A[A-Za-z0-9_-]{43}\z/
    NS_RE = /\A[a-z0-9_]+(?:\.[a-z0-9_]+){0,5}\z/
    VERB_RE = /\A[a-z0-9_]+(?:\.[a-z0-9_]+){1,5}\z/
    SEMVER_RE = /\A(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\z/
    SHARD_NAME_RE = /\A[a-z0-9_]+(?:[.-][a-z0-9_]+){0,7}\z/

    module_function

    def obj?(v) = v.is_a?(Hash)
    def u16len(s) = s.encode('UTF-16LE').bytesize / 2
    def u16key(s) = s.encode('UTF-16BE').b
    def sha?(x) = x.is_a?(String) && B64U_43.match?(x)
    def is1?(v) = v.is_a?(Integer) && v == 1
    def tier?(x) = x.is_a?(Integer) && x >= 0 && x <= MAX_ESC_TIER
    def cat(s) = (s.is_a?(String) ? s : s.to_s)

    def closed(o, allowed)
      o.each_key { |k| return "unknown member '#{k}'" unless allowed.include?(k) }
      nil
    end

    def message(domain, body) = IV.send(:dmsg, domain, body)
    def canon(v) = AtlasPca.hash_canonical(v)

    # ---- evolution records --------------------------------------------------------------------------------------

    def evolution_record_error(x, signed = true)
      return 'evolution record must be an object' unless obj?(x)

      u = closed(x, %w[v kind ns verb from to class reasons] + (signed ? ['sig'] : []))
      return "evolution record: #{u}" if u
      return 'evolution record: bad v/kind' if !is1?(x['v']) || x['kind'] != EVOLUTION_RECORD_KIND
      return 'evolution record: bad ns' unless x['ns'].is_a?(String) && NS_RE.match?(x['ns'])
      return 'evolution record: bad verb' unless x['verb'].is_a?(String) && VERB_RE.match?(x['verb'])
      return 'evolution record: bad from' if !x['from'].nil? && !sha?(x['from'])
      return 'evolution record: bad to' if !x['to'].nil? && !sha?(x['to'])

      c = x['class']
      return 'evolution record: bad class' unless c.is_a?(String) && EVOLUTION_CLASSES.include?(c)
      return 'evolution record: endpoints do not match the class' if (c == 'added') != x['from'].nil? || (c == 'removed') != x['to'].nil?

      r = x['reasons']
      return 'evolution record: bad reasons' if !r.is_a?(Array) || r.length > 64 || r.any? { |e| !e.is_a?(String) || u16len(e) > 512 }

      if signed
        s = x['sig']
        return 'evolution record: bad sig' if !obj?(s) || closed(s, %w[alg kid value pq_value])
        return 'evolution record: bad sig' if !s['kid'].is_a?(String) || !(u16len(s['kid']) > 0 && u16len(s['kid']) <= 128) || !s['value'].is_a?(String) || !s['alg'].is_a?(String)
        return 'evolution record: bad sig' if s.key?('pq_value') && !s['pq_value'].is_a?(String)
      end
      begin
        AtlasPca.canon_bytes(x.reject { |k, _| k == 'sig' })
      rescue StandardError => e
        return "evolution record: #{e.message}"
      end
      nil
    rescue StandardError => e
      "evolution record: #{e.message}"
    end

    def evolution_diff_digest(r)
      canon({ 'd' => EVOLUTION_DIFF_DOMAIN, 'ns' => r.fetch('ns'), 'verb' => r.fetch('verb'), 'from' => r.fetch('from'),
              'to' => r.fetch('to'), 'class' => r.fetch('class'), 'reasons' => r.fetch('reasons') })
    end

    def verify_registry_sig(domain, body, sig, keys)
      return { 'ok' => false, 'reason' => 'the registry keys must be an array' } unless keys.is_a?(Array)

      key = keys.find { |k| obj?(k) && IV.send(:strict_eq, IV.send(:prop, k, 'kid'), IV.send(:prop, sig, 'kid')) }
      return { 'ok' => false, 'reason' => "no registry key with kid '#{sig['kid']}'" } if key.nil?
      return { 'ok' => false, 'reason' => 'the registry key pq_pk must be a string' } if key.key?('pq_pk') && !key['pq_pk'].is_a?(String)
      return { 'ok' => false, 'reason' => 'registry key pk is not canonical base64url (32 bytes)' } if IV.send(:b64d, key['pk'], 32).nil?

      ka = IV.send(:suite_of, IV.send(:prop, key, 'alg'))
      return { 'ok' => false, 'reason' => 'sig.alg does not match the pinned key suite' } if ka.nil? || ka != IV.send(:suite_of, IV.send(:prop, sig, 'alg'))

      pq = IV.send(:prop, key, 'pq_pk')
      pins = pq.equal?(UNDEF) ? nil : { key['pk'] => pq }
      unless IV.send(:verify_pinned_suite, ka, key['pk'], pq, message(domain, body), IV.send(:prop, sig, 'value'), IV.send(:prop, sig, 'pq_value'), pins)
        return { 'ok' => false, 'reason' => 'signature invalid' }
      end
      { 'ok' => true }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "verification error: #{e.message}" }
    end

    def verify_evolution_record(rec, keys)
      bad = evolution_record_error(rec)
      return { 'ok' => false, 'reason' => bad } if bad

      verify_registry_sig(EVOLUTION_DOMAIN, rec.reject { |k, _| k == 'sig' }, rec['sig'], keys)
    end

    def reapproval_valid?(r, grant_id, issuer, verb, diff)
      return false if !obj?(r) || closed(r, %w[v kind grant verb diff sig])
      return false if !is1?(r['v']) || r['kind'] != REAPPROVAL_KIND || !r.key?('grant') || r['grant'] != grant_id || r['verb'] != verb || r['diff'] != diff

      s = r['sig']
      return false if !obj?(s) || closed(s, %w[alg value]) || s['alg'] != 'ed25519' || !s['value'].is_a?(String)

      IV.send(:verify_pinned_suite, 'ed25519', issuer, UNDEF, message(REAPPROVAL_DOMAIN, r.reject { |k, _| k == 'sig' }), s['value'], UNDEF, nil) ? true : false
    rescue StandardError
      false
    end

    # ---- the pin ------------------------------------------------------------------------------------------------

    def action_pin_error(x)
      return 'actions must be an object' unless obj?(x)

      u = closed(x, %w[pack defs on_new_action max_esc preauth_esc caveats])
      return "actions: #{u}" if u

      p = x['pack']
      return 'actions.pack must be {ns, root}' if !obj?(p) || closed(p, %w[ns root])
      return 'actions.pack.ns is not a namespace' unless p['ns'].is_a?(String) && NS_RE.match?(p['ns'])
      return 'actions.pack.root must be a base64url digest' unless sha?(p['root'])
      return "actions.on_new_action must be 'deny' or 'escalate'" unless x['on_new_action'].is_a?(String) && ACTION_PIN_ON_NEW.include?(x['on_new_action'])
      return 'actions.max_esc must be an integer tier 0..3' if x.key?('max_esc') && !tier?(x['max_esc'])
      return 'actions.preauth_esc must be an integer tier 0..3' if x.key?('preauth_esc') && !tier?(x['preauth_esc'])
      return 'actions.preauth_esc exceeds actions.max_esc' if tier?(x['max_esc']) && tier?(x['preauth_esc']) && x['preauth_esc'] > x['max_esc']

      if x.key?('caveats')
        c = x['caveats']
        return 'actions.caveats must be distinct caveat kinds' if !c.is_a?(Array) || c.any? { |k| !k.is_a?(String) || !IV::SCHEMA_V2_CAVEATS.include?(k) } || c.uniq.length != c.length
      end
      if x.key?('defs')
        return 'actions.defs must be an object' unless obj?(x['defs'])

        x['defs'].each do |verb, d|
          return "actions.defs: '#{verb}' is not a verb" unless VERB_RE.match?(verb)
          return "actions.defs.#{verb} must be a base64url digest" unless sha?(d)
        end
      end
      nil
    end

    def deny(code, reason, escalate = false, needs = nil)
      out = { 'ok' => false, 'code' => code, 'escalate' => escalate, 'reason' => reason }
      out['needs_reapproval'] = needs unless needs.nil?
      out
    end

    def decide_pin(i)
      pe = action_pin_error(i['pin'])
      return deny('bad_pin', pe) if pe

      pin = i['pin']
      doc = i['doc']
      verb = i['verb']
      verbs = obj?(doc) ? doc['verbs'] : nil
      v = verbs.is_a?(Array) ? verbs.find { |x| obj?(x) && x.key?('verb') && x['verb'] == verb } : nil
      return deny('unknown_verb', "the accepted schema does not declare '#{verb}'") if v.nil?

      pk = doc['pack']
      return deny('pack_mismatch', "the schema does not come from the pinned pack '#{pin['pack']['ns']}'") if !obj?(pk) || !pk.key?('ns') || pk['ns'] != pin['pack']['ns']

      unless pin.key?('defs')
        return { 'ok' => true, 'via' => 'pack' } if pk.key?('root') && pk['root'] == pin['pack']['root']

        return deny('pack_mismatch', 'the pack root differs from the pinned root (the grant pins the pack as a whole)')
      end
      unless pin['defs'].key?(verb)
        return deny('new_action', "the grant does not name '#{verb}' (on_new_action: #{pin['on_new_action']})", pin['on_new_action'] == 'escalate')
      end

      pinned = pin['defs'][verb]
      presented = v['def']
      return deny('def_changed', 'the schema verb carries no definition digest') unless presented.is_a?(String)
      return { 'ok' => true, 'via' => 'exact' } if presented == pinned

      edges = {}
      keys = i['keys'] || []
      grant = i['grant']
      (i['records'] || []).each do |r|
        next unless verify_evolution_record(r, keys)['ok']
        next if r['ns'] != pin['pack']['ns'] || r['verb'] != verb || r['from'].nil? || r['to'].nil?

        diff = evolution_diff_digest(r)
        free = %w[equal narrow].include?(r['class'])
        approved = free || (i['reapprovals'] || []).any? { |a| reapproval_valid?(a, grant['id'], grant['issuer'], verb, diff) }
        (edges[r['from']] ||= []) << { 'to' => r['to'], 'blocked' => approved ? nil : diff }
      end
      search = lambda do |usable_only|
        parent = {}
        seen = { pinned => true }
        frontier = [pinned]
        step = 0
        while step < MAX_EVOLUTION_STEPS && !frontier.empty? && !parent.key?(presented)
          nxt = []
          frontier.each do |f|
            (edges[f] || []).each do |e|
              next if seen[e['to']] || (usable_only && !e['blocked'].nil?)

              seen[e['to']] = true
              parent[e['to']] = { 'from' => f, 'blocked' => e['blocked'] }
              nxt << e['to']
            end
          end
          frontier = nxt
          step += 1
        end
        parent
      end
      return { 'ok' => true, 'via' => 'chain' } if search.call(true).key?(presented)

      allp = search.call(false)
      if allp.key?(presented)
        first = nil
        cur = presented
        while cur != pinned
          p = allp[cur]
          first = p['blocked'] unless p['blocked'].nil?
          cur = p['from']
        end
        return deny('def_changed', 'the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve', false, first)
      end
      deny('def_changed', 'the definition differs from the pinned digest and no signed evolution record chains to it')
    rescue StandardError => e
      deny('bad_pin', "pin evaluation error (fail closed): #{e.message}")
    end

    # ---- signed packs -------------------------------------------------------------------------------------------

    def compare_versions(a, b)
      pa = SEMVER_RE.match(a)
      pb = SEMVER_RE.match(b)
      raise A::ActionKitError.new('bad_version', "'#{pa ? b : a}' is not MAJOR.MINOR.PATCH") if pa.nil? || pb.nil?

      (1..3).each do |k|
        d = pa[k].to_i - pb[k].to_i
        return d unless d.zero?
      end
      0
    end

    def rules_digest = canon({ 'd' => RULES_DIGEST_DOMAIN, 'prules' => A::PARAM_RULE_IDS.dup, 'caveats' => A::CAVEAT_KINDS.dup, 'context' => A::CONTEXT_KEYS.dup })
    def pack_digest(p) = canon({ 'd' => PACK_REF_DOMAIN, 'p' => p })
    def shard_digest(s) = canon({ 'd' => PACK_SHARD_DOMAIN, 's' => s })

    def sorted_unique_defs_error(defs)
      defs.each_with_index do |d, i|
        e = A.validate_def(d)
        return "def #{i}: #{e}" if e
        return "defs must be sorted by verb and unique (at '#{d['verb']}')" if i.positive? && !(u16key(defs[i - 1]['verb']) < u16key(d['verb']))
      end
      nil
    end

    def pack_shape_error(x, signed = true)
      return 'pack must be an object' unless obj?(x)

      e = closed(x, %w[v kind ns version stability traits_digest roles_digest rules_digest root defs source prev evolution] + (signed ? ['sig'] : []))
      return "pack: #{e}" if e
      return 'pack: bad v/kind' if !is1?(x['v']) || x['kind'] != ACTION_PACK_KIND
      return 'pack: bad ns' unless x['ns'].is_a?(String) && NS_RE.match?(x['ns'])
      return 'pack: version must be MAJOR.MINOR.PATCH' unless x['version'].is_a?(String) && SEMVER_RE.match?(x['version'])
      return 'pack: bad stability' unless x['stability'].is_a?(String) && STABILITIES.include?(x['stability'])

      %w[traits_digest roles_digest rules_digest root].each { |k| return "pack: #{k} must be a base64url digest" unless sha?(x[k]) }
      return 'pack: bad prev' if !x['prev'].nil? && !sha?(x['prev'])

      s = x['source']
      return 'pack: source must be {kind, uri, spec_digest, licence, licence_notes}' if !obj?(s) || closed(s, %w[kind uri spec_digest licence licence_notes])

      %w[kind uri spec_digest licence licence_notes].each do |k|
        v = s[k]
        return "pack: source.#{k} is not a string of 1..2048 characters" if !v.is_a?(String) || (k != 'licence_notes' && v.empty?) || u16len(v) > 2048
      end
      d = x['defs']
      if d.is_a?(Array)
        return 'pack: inline defs must number 1..4096 (larger packs are sharded)' if d.empty? || d.length > 4096

        de = sorted_unique_defs_error(d)
        return "pack: #{de}" if de
      else
        return 'pack: defs must be a list of defs or {shards}' if !obj?(d) || closed(d, ['shards']) || !d['shards'].is_a?(Array) || d['shards'].empty? || d['shards'].length > 4096

        names = {}
        d['shards'].each do |r|
          return 'pack: bad shard ref' if !obj?(r) || closed(r, %w[name digest uri])
          return 'pack: shard names must be distinct simple names' if !r['name'].is_a?(String) || !SHARD_NAME_RE.match?(r['name']) || names[r['name']]

          names[r['name']] = true
          return 'pack: bad shard digest or uri' if !sha?(r['digest']) || !r['uri'].is_a?(String) || r['uri'].empty? || u16len(r['uri']) > 2048
        end
      end
      ev = x['evolution']
      return 'pack: evolution must be a list of records' if !ev.is_a?(Array) || ev.length > MAX_EVOLUTION_RECORDS

      ev.each do |r|
        re = evolution_record_error(r)
        return "pack: #{re}" if re
      end
      if signed
        g = x['sig']
        return 'pack: bad sig' if !obj?(g) || closed(g, %w[alg kid value pq_value]) || !g['kid'].is_a?(String) || !g['value'].is_a?(String) || !g['alg'].is_a?(String)
      end
      canon(x.reject { |k, _| k == 'sig' })
      nil
    rescue StandardError => e
      "pack: #{e.message}"
    end

    def pack_defs(pack, shards = nil)
      return pack['defs'].dup if pack['defs'].is_a?(Array)

      shards ||= {}
      all = []
      pack['defs']['shards'].each do |r|
        s = shards.is_a?(Hash) ? shards[r['name']] : nil
        raise A::ActionKitError.new('missing_shard', "shard '#{r['name']}' was not supplied") if s.nil?
        raise A::ActionKitError.new('shard_digest_mismatch', "shard '#{r['name']}' does not match its digest") if shard_digest(s) != r['digest']
        if s['v'] != 1 || s['kind'] != PACK_SHARD_KIND || s['ns'] != pack['ns'] || s['version'] != pack['version'] || s['name'] != r['name'] || !s['defs'].is_a?(Array)
          raise A::ActionKitError.new('bad_shard', "shard '#{r['name']}' is not a shard of this pack")
        end

        all.concat(s['defs'])
      end
      all.sort_by { |d| u16key(d['verb']) }
    end

    def verify_pack(pack, keys, shards = nil)
      se = pack_shape_error(pack)
      return { 'ok' => false, 'reason' => se } if se

      v = verify_registry_sig(PACK_SIG_DOMAIN, pack.reject { |k, _| k == 'sig' }, pack['sig'], keys)
      return { 'ok' => false, 'reason' => "pack signature: #{v['reason']}" } unless v['ok']
      return { 'ok' => false, 'reason' => 'traits_digest does not match the trait registry' } if pack['traits_digest'] != A.traits_digest(A::CORE_REGISTRY)
      return { 'ok' => false, 'reason' => 'roles_digest does not match the vocabulary tables' } if pack['roles_digest'] != A.tables_digest
      return { 'ok' => false, 'reason' => 'rules_digest does not match the rule tables' } if pack['rules_digest'] != rules_digest

      begin
        defs = pack_defs(pack, shards)
      rescue A::ActionKitError => e
        return { 'ok' => false, 'reason' => e.message }
      end
      de = sorted_unique_defs_error(defs)
      return { 'ok' => false, 'reason' => de } if de
      return { 'ok' => false, 'reason' => 'the pack lists no defs or too many' } if defs.empty? || defs.length > 1_000_000

      digests = defs.map { |d| A.def_digest(d) }
      return { 'ok' => false, 'reason' => 'the Merkle root does not match the defs' } if A.pack_root(digests) != pack['root']

      have = digests.to_h { |d| [d, true] }
      pack['evolution'].each do |r|
        rv = verify_evolution_record(r, keys)
        return { 'ok' => false, 'reason' => "evolution record: #{rv['reason']}" } unless rv['ok']
        return { 'ok' => false, 'reason' => 'evolution record of another namespace' } if r['ns'] != pack['ns']
        return { 'ok' => false, 'reason' => "evolution record for '#{r['verb']}' names a definition that is not in the pack" } if !r['to'].nil? && !have[r['to']]
      end
      { 'ok' => true, 'defs' => defs, 'digest' => pack_digest(pack) }
    rescue StandardError => e
      { 'ok' => false, 'reason' => "pack verification error: #{e.message}" }
    end

    # Refuses rollback, fork and chain gap. The semantic diff of an upgrade is not recomputed natively.
    class PackTracker
      def initialize(keys)
        @keys = keys
        @seen = {}
      end

      def accept(pack, shards = nil)
        v = ActionsRegistry.verify_pack(pack, @keys, shards)
        return { 'ok' => false, 'code' => 'bad_pack', 'reason' => v['reason'] } unless v['ok']

        cur = @seen[pack['ns']]
        if cur.nil?
          @seen[pack['ns']] = { 'version' => pack['version'], 'digest' => v['digest'] }
          return { 'ok' => true, 'status' => 'first' }
        end
        return { 'ok' => true, 'status' => 'same' } if cur['digest'] == v['digest']

        c = ActionsRegistry.compare_versions(pack['version'], cur['version'])
        return { 'ok' => false, 'code' => 'rollback', 'reason' => 'older than the accepted version' } if c.negative?
        return { 'ok' => false, 'code' => 'fork', 'reason' => 'two different packs claim one version' } if c.zero?
        return { 'ok' => false, 'code' => 'chain_gap', 'reason' => 'prev does not name the accepted pack' } if pack['prev'] != cur['digest']

        @seen[pack['ns']] = { 'version' => pack['version'], 'digest' => v['digest'] }
        { 'ok' => true, 'status' => 'upgrade' }
      end
    end

    # ---- rule 22 over a whole document --------------------------------------------------------------------------

    CODES = %w[schema_floor_forged schema_traits_forged unknown_trait traits_digest_mismatch bad_registry].freeze

    def code_of(e) = e.nil? ? { 'ok' => true } : { 'ok' => false, 'code' => CODES.find { |c| e.include?(c) } || 'unknown' }
    def rule22_integrity(doc, pins = nil) = code_of(A.schema_floor_error(doc, pins))

    def rule22_decide(doc, verb, grant, context)
      v = (doc['verbs'] || []).find { |x| x['verb'] == verb }
      return 'deny' if v.nil? || !A.profile_error(v['floors']).nil?

      kinds = grant['caveats'].select { |k| k.is_a?(String) && A::CAVEAT_KINDS.include?(k) }
      ctx = context.select { |k| A.context_key?(k) }
      A.floor_decision({ 'caveats' => kinds, 'max_esc' => grant['max_esc'], 'preauth_esc' => grant['preauth_esc'] }, { 'context' => ctx }, v['floors'])
    rescue StandardError
      'deny'
    end
  end
end
