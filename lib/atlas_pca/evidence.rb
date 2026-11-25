# frozen_string_literal: true

require_relative '../atlas_pca'
require_relative 'explain_js'
require_relative 'authorize'
require_relative 'scitt'

# The dispute evidence bundle `pca-intent-evidence` v1 (Intent Layer v2): closed-member shape validation, the deterministic normal
# form, the commitments-only form and the digest that commits to it, the bundle reference and its anchor-log leaf, the accumulator
# cap reader, and the validators of the verifier's trust inputs (port of the TypeScript reference @atlasauth/pca-evidence).
# The full replay (verifyEvidenceBundle) is EvidenceVerify; the command line is EvidenceCli.
#
# Inputs are JSON values; the reference's JavaScript semantics (property reads on any value, `Object.keys` order, relational
# comparison, the `||` chain of the sort comparators, JSON round-trip copy) are reproduced where a hostile bundle reaches them, so
# a malformed bundle gives the same shape error, the same order or the same refusal (an exception) as the reference.
module AtlasPca
  module Evidence
    X = ExplainJs
    UNDEF = X::UNDEF

    EVIDENCE_DOMAIN = 'atlas-pca/intent-evidence/v1'
    EVIDENCE_REPORT_DOMAIN = 'atlas-pca/intent-evidence-report/v1'
    EVIDENCE_CONTENT_TYPE = 'application/pca-intent-evidence+json'
    INTENT_ANCHOR_DOMAIN = 'atlas-pca/intent-anchor/v1'

    MAX_SAFE = (2**53) - 1

    TOP_KEYS = %w[v kind subject statement session_root schema root_grant maps answers canary_labels canaries deltas pcactns verdicts
                  accumulator facts classifier offer_sets labels effects settlements revocation_epochs anchors].freeze

    module_function

    # ---- JavaScript value helpers --------------------------------------------------------------------------------------

    def hash?(v) = v.is_a?(Hash)

    # a safe integer that is not -0
    def int?(v)
      return v.abs <= MAX_SAFE if v.is_a?(Integer)

      v.is_a?(Float) && v.finite? && v == v.floor && v.abs <= MAX_SAFE && !(v.zero? && (1.0 / v).negative?)
    end

    def one?(v) = X.num?(v) && v == 1

    # JSON.parse(JSON.stringify(v)): a deep copy in which -0 becomes 0
    def plain(v)
      case v
      when Hash then v.transform_values { |x| plain(x) }
      when Array then v.map { |x| plain(x) }
      when Float then v.zero? ? 0 : v
      else v
      end
    end

    # the members `{...v}` copies: an object's own, an array's or a string's indices, nothing for any other value
    def spread(v)
      case v
      when Hash then v.dup
      when Array then v.each_with_index.to_h { |x, i| [i.to_s, x] }
      when String then X.iter(v).each_with_index.to_h { |c, i| [i.to_s, c] }
      else {}
      end
    end

    def cmp(a, b) = X.lt(a, b) ? -1 : (X.gt(a, b) ? 1 : 0)
    def sub(a, b) = X.to_num(a) - X.to_num(b)

    # `first || rest()` for numbers: zero and NaN are falsy
    def or_(first, &rest) = first != 0 && !(first.is_a?(Float) && first.nan?) ? first : rest.call

    # An Array#sort with the stable, run-detecting binary-insertion behaviour of the reference engine's sort for the
    # comparator `cmp` (a number; NaN and zero are "not less").
    def sort!(lst, &cmp)
      raise TypeError, 'sort is not a function' unless lst.is_a?(Array)

      n = lst.length
      return if n < 2

      lt = ->(x, y) { cmp.call(x, y) < 0 }
      if lt.call(lst[1], lst[0])
        run = 2
        run += 1 while run < n && lt.call(lst[run], lst[run - 1])
        lst[0, run] = lst[0, run].reverse
      else
        run = 2
        run += 1 while run < n && !lt.call(lst[run], lst[run - 1])
      end
      (run...n).each do |start|
        pivot = lst[start]
        l = 0
        r = start
        while l < r
          p = l + ((r - l) >> 1)
          if lt.call(pivot, lst[p]) then r = p
          else l = p + 1
          end
        end
        lst.insert(l, lst.delete_at(start))
      end
    end

    # `arr?.sort((a, c) => cmp(key(a), key(c)))`: absent or null is skipped; a non-array throws
    def sort_set(v)
      return if v.equal?(UNDEF) || v.nil?

      sort!(v) { |a, c| cmp(AtlasPca.hash_canonical(a), AtlasPca.hash_canonical(c)) }
    end

    # ---- shape ---------------------------------------------------------------------------------------------------------

    def closed(o, keys, where)
      return "#{where} must be an object" unless hash?(o)

      X.keys(o).each { |k| return "#{where}: unknown member \"#{k}\"" unless keys.include?(k) }
      nil
    end

    def str?(v) = v.is_a?(String)

    # Closed-member shape validation (unknown members are refused at every level the bundle owns). nil when well formed.
    def bundle_shape_error(b)
      top = closed(b, TOP_KEYS, 'bundle')
      return top if top

      x = b
      g = ->(o, k) { X.get(o, k) }
      return 'not a pca-intent-evidence v1 bundle' if !one?(g.(x, 'v')) || g.(x, 'kind') != 'pca-intent-evidence'

      subj = closed(g.(x, 'subject'), %w[pcactn_digest aud session], 'subject')
      return subj if subj

      s = g.(x, 'subject')
      return 'subject members must be strings' unless %w[pcactn_digest aud session].all? { |k| str?(g.(s, k)) }

      st = closed(g.(x, 'statement'), %w[commit opening], 'statement')
      return st if st
      return 'statement.commit must be a string' unless str?(g.(g.(x, 'statement'), 'commit'))

      sr = g.(x, 'session_root')
      return 'session_root is not a pca-intent-session v1' if !hash?(sr) || !one?(g.(sr, 'v')) || g.(sr, 'kind') != 'pca-intent-session'
      if !str?(g.(sr, 'session')) || !str?(g.(sr, 'intent_ref')) || !int?(g.(sr, 'expires_at'))
        return 'session_root is missing session / intent_ref / expires_at'
      end

      pr = g.(sr, 'principals')
      if !pr.is_a?(Array) || pr.empty? || !pr.all? { |p| hash?(p) && str?(g.(p, 'key')) }
        return 'session_root.principals must be a non-empty key list'
      end

      sc = closed(g.(x, 'schema'), %w[doc anchor], 'schema')
      return sc if sc

      doc = g.(g.(x, 'schema'), 'doc')
      return 'schema.doc is not a signed pca-action-schema' if !hash?(doc) || g.(doc, 'kind') != 'pca-action-schema' || !hash?(g.(doc, 'sig'))
      return 'root_grant must be a capability' unless hash?(g.(x, 'root_grant'))

      %w[maps answers canary_labels deltas pcactns verdicts effects revocation_epochs anchors].each do |k|
        return "#{k} must be an array" unless g.(x, k).is_a?(Array)
      end
      %w[facts classifier offer_sets labels settlements].each do |k|
        return "#{k} must be an array" if x.key?(k) && !x[k].is_a?(Array)
      end
      x['maps'].each_with_index do |m, i|
        e = closed(m, %w[seq commit map disclosed], "maps[#{i}]")
        return e if e
        return "maps[#{i}] needs an integer seq and a commit" if !int?(g.(m, 'seq')) || g.(m, 'seq') < 0 || !str?(g.(m, 'commit'))
      end
      x['canary_labels'].each_with_index do |c, i|
        e = closed(c, %w[question_id label], "canary_labels[#{i}]")
        return e if e

        lab = g.(c, 'label')
        return "canary_labels[#{i}] is malformed" if !str?(g.(c, 'question_id')) || !(X.num?(lab) && (lab == 0 || lab == 1))
      end
      cs = closed(g.(x, 'canaries'), %w[asked false_yes false_no], 'canaries')
      return cs if cs

      cn = x['canaries']
      return 'canaries counts must be non-negative integers' unless %w[asked false_yes false_no].all? { |k| int?(g.(cn, k)) && g.(cn, k) >= 0 }

      ac = closed(g.(x, 'accumulator'), %w[holder events receipts sequencer_keys], 'accumulator')
      return ac if ac

      acc = x['accumulator']
      return 'accumulator.holder must be site_local or sequenced' if !%w[site_local sequenced].include?(g.(acc, 'holder')) || !str?(g.(acc, 'holder'))
      return 'accumulator.events must be an array' unless g.(acc, 'events').is_a?(Array)

      acc['events'].each_with_index do |ev, i|
        e = closed(ev, %w[acc post pcactn_digest delta status], "accumulator.events[#{i}]")
        return e if e
        if !str?(g.(ev, 'acc')) || !int?(g.(ev, 'post')) || g.(ev, 'post') < 0 || !str?(g.(ev, 'pcactn_digest'))
          return "accumulator.events[#{i}] is malformed"
        end
        if ev.key?('delta') && !(int?(ev['delta']) && ev['delta'] >= 0)
          return "accumulator.events[#{i}].delta must be a non-negative integer"
        end
      end
      return 'accumulator.receipts must be an array' if acc.key?('receipts') && !acc['receipts'].is_a?(Array)
      return 'accumulator.sequencer_keys must be an array' if acc.key?('sequencer_keys') && !acc['sequencer_keys'].is_a?(Array)

      x['revocation_epochs'].each_with_index do |r, i|
        e = closed(r, %w[epoch revoked], "revocation_epochs[#{i}]")
        return e if e
        return "revocation_epochs[#{i}] needs an epoch and its revoked list" if !hash?(g.(r, 'epoch')) || !g.(r, 'revoked').is_a?(Array)
      end
      x['anchors'].each_with_index do |a, i|
        e = closed(a, %w[kind digest index proof signed_tree_head], "anchors[#{i}]")
        return e if e
      end
      x['effects'].each_with_index do |ef, i|
        return "effects[#{i}] needs a pcactn_digest" if !hash?(ef) || !str?(g.(ef, 'pcactn_digest'))
      end
      nil
    end

    # ---- normal form ---------------------------------------------------------------------------------------------------

    def seq_of(c)
      cvs = X.rd(c, 'caveats')
      raise TypeError, 'find is not a function' unless cvs.is_a?(Array)

      cvs.each do |k|
        next unless X.rd(k, 'type') == 'intent_session'

        seq = X.get(k, 'seq')
        return int?(seq) ? seq : MAX_SAFE
      end
      MAX_SAFE
    end

    # hashCanonical of the effect without its params opening (`const {params, ...k} = e`)
    def effect_key(e)
      raise TypeError, 'cannot destructure' if e.nil? || e.equal?(UNDEF)

      AtlasPca.hash_canonical(spread(e).reject { |k, _| k == 'params' })
    end

    # Deterministic normal form: the members that are sets (answers, deltas, PCActns, verdicts, effects, epochs, anchors, maps,
    # canary labels, ...) are sorted by a content key; `accumulator.events` is a sequence and is never reordered. Raises on a bundle
    # that cannot be put in order (a refusal, like the reference's thrown error).
    def normalize_bundle(b)
      x = plain(b)
      key = ->(v) { AtlasPca.hash_canonical(v) }
      r = ->(o, k) { X.rd(o, k) }
      sort!(r.(x, 'maps')) { |a, c| or_(sub(r.(a, 'seq'), r.(c, 'seq'))) { cmp(r.(a, 'commit'), r.(c, 'commit')) } }
      sort!(r.(x, 'answers')) do |a, c|
        or_(sub(r.(a, 'observed_at'), r.(c, 'observed_at'))) do
          or_(cmp(r.(a, 'question_id'), r.(c, 'question_id'))) { cmp(r.(a, 'sig'), r.(c, 'sig')) }
        end
      end
      sort!(r.(x, 'canary_labels')) { |a, c| or_(cmp(r.(a, 'question_id'), r.(c, 'question_id'))) { sub(r.(a, 'label'), r.(c, 'label')) } }
      sort!(r.(x, 'deltas')) { |a, c| or_(sub(seq_of(a), seq_of(c))) { cmp(r.(a, 'id'), r.(c, 'id')) } }
      sort!(r.(x, 'pcactns')) do |a, c|
        or_(sub(r.(a, 'iat'), r.(c, 'iat'))) { or_(sub(r.(a, 'counter'), r.(c, 'counter'))) { cmp(key.(a), key.(c)) } }
      end
      sort!(r.(x, 'verdicts')) { |a, c| or_(cmp(r.(a, 'pcactn_digest'), r.(c, 'pcactn_digest'))) { cmp(key.(a), key.(c)) } }
      # sorted without the params opening, so withholding an opening never reorders the commitments-only form
      sort!(r.(x, 'effects')) do |a, c|
        or_(cmp(r.(a, 'pcactn_digest'), r.(c, 'pcactn_digest'))) { cmp(effect_key(a), effect_key(c)) }
      end
      # issue order (not epoch number): a rollback, an epoch issued later with a lower number, must stay visible
      ep = ->(o, k) { r.(r.(o, 'epoch'), k) }
      sort!(r.(x, 'revocation_epochs')) do |a, c|
        or_(sub(ep.(a, 'issued_at'), ep.(c, 'issued_at'))) { or_(sub(ep.(a, 'epoch'), ep.(c, 'epoch'))) { cmp(key.(a), key.(c)) } }
      end
      sort!(r.(x, 'anchors')) do |a, c|
        or_(cmp(r.(a, 'kind'), r.(c, 'kind'))) { or_(sub(r.(a, 'index'), r.(c, 'index'))) { cmp(r.(a, 'digest'), r.(c, 'digest')) } }
      end
      %w[facts classifier offer_sets labels settlements].each { |k| sort_set(X.get(x, k)) }
      receipts = X.get(r.(x, 'accumulator'), 'receipts')
      sort!(receipts) { |a, c| cmp(key.(a), key.(c)) } if X.truthy?(receipts)
      x
    end

    # Assemble a bundle in normal form. Raises ArgumentError on a malformed part (the exporter's bug, not evidence).
    def build_evidence_bundle(parts)
      b = { 'v' => 1, 'kind' => 'pca-intent-evidence' }
      b.merge!(spread(parts))
      n = normalize_bundle(b)
      bad = bundle_shape_error(n)
      raise ArgumentError, "buildEvidenceBundle: #{bad}" if bad

      n
    end

    # [the commitments-only form, whether a committed member is undefined]: an undefined member cannot be hashed
    def commitment(b)
      n = normalize_bundle(b)
      rest = n.reject { |k, _| k == 'anchors' }
      undef_member = false
      statement = X.get(n, 'statement')
      raise TypeError, "cannot read 'commit' of undefined" if statement.nil? || statement.equal?(UNDEF)

      commit = X.get(statement, 'commit')
      rest['statement'] = {}
      if commit.equal?(UNDEF) then undef_member = true
      else rest['statement']['commit'] = commit
      end
      maps = n['maps'].map do |m|
        seq = X.rd(m, 'seq')
        mc = X.rd(m, 'commit')
        disclosed = X.get(m, 'disclosed')
        entry = {}
        [['seq', seq], ['commit', mc]].each do |k, v|
          if v.equal?(UNDEF) then undef_member = true
          else entry[k] = v
          end
        end
        entry['disclosed'] = disclosed unless disclosed.equal?(UNDEF)
        entry
      end
      rest['maps'] = maps
      rest['effects'] = n['effects'].map { |e| spread(check_obj(e)).reject { |k, _| k == 'params' } }
      [rest, undef_member]
    end

    def check_obj(e)
      raise TypeError, 'cannot destructure' if e.nil? || e.equal?(UNDEF)

      e
    end

    # The commitments-only normal form: no anchors, no statement opening, no full maps, no effect params; every signed artifact
    # and every claim stays in.
    def commitment_form(b) = commitment(b)[0]

    # The bundle's content address: the hash over the commitments-only normal form.
    def evidence_digest(b)
      form, undef_member = commitment(b)
      raise TypeError, 'canonicalize: undefined member' if undef_member

      AtlasPca.hash_canonical({ 'd' => EVIDENCE_DOMAIN, 'b' => form })
    end

    # The public reference to a bundle: its digest and subject (the bundle itself stays with the site).
    def evidence_ref(bundle)
      digest = evidence_digest(bundle)
      { 'kind' => 'pca-intent-evidence-ref', 'digest' => digest, 'subject' => spread(X.rd(bundle, 'subject')) }
    end

    # A COSE Signed Statement over the bundle reference, ready to register with a SCITT service. `subject` defaults to the bundle's
    # pcactn digest (nil also takes the default, as the reference's `??`). Raises on a malformed bundle.
    def evidence_signed_statement(bundle, alg, key, issuer, subject = nil)
      ref = evidence_ref(bundle)
      Scitt.sign_statement(ref, alg, key, issuer, 'subject' => subject.nil? ? ref['subject']['pcactn_digest'] : subject, 'content_type' => EVIDENCE_CONTENT_TYPE)
    end

    # The intent-log leaf for an anchored artifact (any kind).
    def anchor_commit(kind, digest)
      AtlasPca.hash_canonical({ 'd' => INTENT_ANCHOR_DOMAIN, 'kind' => kind, 'digest' => digest })
    end

    def evidence_anchor_commit(digest) = anchor_commit('evidence', digest)

    # ---- accumulator cap -----------------------------------------------------------------------------------------------

    def leaf_caps(conds, path)
      out = []
      X.iter(conds.nil? || conds.equal?(UNDEF) ? [] : conds).each do |c|
        if AtlasPca.leaf_condition?(c)
          next if c['field'] != path || c.key?('ref') || !X.num?(c['value'])

          if c['op'] == 'lte' then out << c['value']
          elsif c['op'] == 'lt' then out << (c['value'] - 1)
          end
        elsif AtlasPca.group_condition?(c) && c.key?('all_of')
          out.concat(leaf_caps(c['all_of'], path))
        end
      end
      out
    end

    # The cap `env.acc.<id>.post <= v` that the grant's envelope states for `verb`: per predicate the tightest bound in its `where`
    # (descending into `all_of`); across predicates (a union) the loosest. nil when a predicate admitting the verb states no bound,
    # or none admits it.
    def cap_of(grant, acc_id, verb)
      env = AtlasPca.read_envelope(grant)
      return nil unless env

      path = "env.acc.#{X.js_string(acc_id)}.post"
      cap = nil
      env['predicates'].each do |p|
        pv = X.rd(p, 'verb')
        verbs = pv.is_a?(Array) ? pv.map { |x| X.js_string(x) } : [X.js_string(pv)]
        next if !verbs.include?(verb) && !verbs.include?('*')

        caps = leaf_caps(X.get(p, 'where'), path)
        return nil if caps.empty?

        m = caps.min
        cap = cap.nil? ? m : [cap, m].max
      end
      cap
    end

    # ---- trust-input validators ----------------------------------------------------------------------------------------

    # Validate `trust.principals`: a non-empty array of closed `{key, pq_pk?}` with canonical keys. nil = valid (an absent value is
    # valid).
    def principals_trust_error(p = UNDEF)
      return nil if p.equal?(UNDEF)
      return 'trust.principals must be a non-empty array of {key, pq_pk?}' if !p.is_a?(Array) || p.empty?

      p.each_with_index do |x, i|
        return "trust.principals[#{i}] must be an object {key, pq_pk?}" unless x.is_a?(Hash)

        X.keys(x).each { |k| return "trust.principals[#{i}]: unknown member '#{k}'" if k != 'key' && k != 'pq_pk' }
        return "trust.principals[#{i}].key must be canonical base64url (32 bytes)" if AtlasPca.b64d(x['key'], 32).nil?
        return "trust.principals[#{i}].pq_pk must be canonical base64url" if x.key?('pq_pk') && AtlasPca.b64d(x['pq_pk']).nil?
      end
      nil
    end

    # Validate `trust.acc` like the core `policy.acc`: closed members, non-negative safe integers. nil = valid.
    def acc_trust_error(a = UNDEF)
      return nil if a.equal?(UNDEF)
      return 'trust.acc must be an object' unless a.is_a?(Hash)

      X.keys(a).each do |k|
        v = a[k]
        return "trust.acc: unknown member '#{k}'" if k != 'max_receipt_age_s' && k != 'max_keyset_age_s'
        return "trust.acc.#{k} must be a non-negative safe integer" unless int?(v) && v >= 0
      end
      nil
    end
  end
end
