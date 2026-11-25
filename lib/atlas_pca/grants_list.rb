# frozen_string_literal: true

# List-authorized (the TypeScript reference, @atlasauth/pca-grants): "which objects of this type may this agent touch?". Authority is
# capability AND relationship: `permits` (the grant's own predicates) decides, a relation source can only NARROW. Every page is charged
# to a read accumulator (scanned AND returned objects), pages are bound by a signed cursor (changing subject, type, filter, policy,
# relation or limit between pages is refused) and the result carries a signed receipt.
#
# A candidate source answers page({'type', 'cursor'?, 'limit'}) -> {'objects', 'next'?}; a relation source check({'subject',
# 'relation', 'object'}) -> bool and optionally list_objects({...}) -> {'objects', 'next'?}; a read accumulator charge(key, units, now) -> bool.
require_relative 'grants'

module AtlasPca
  module GrantsList
    MAX_PAGE_LIMIT = 500

    # code is 'read_budget_exhausted', 'bad_cursor' or 'bad_limit'.
    class ListError < StandardError
      attr_reader :code

      def initialize(code, message)
        super(message)
        @code = code
      end
    end

    class RelationCandidates
      def initialize(rel, subject, relation)
        @rel = rel
        @subject = subject
        @relation = relation
      end

      def page(q) = @rel.list_objects({ 'subject' => @subject, 'relation' => @relation }.merge(q))
    end

    module_function

    # Adapt a relation source's list_objects into a candidate source for one subject and relation.
    def candidates_from_relation(rel, subject, relation)
      raise TypeError, 'candidatesFromRelation: the relation source has no listObjects' unless rel.respond_to?(:list_objects)

      RelationCandidates.new(rel, subject, relation)
    end

    # Reference accumulator: `cap` units per `window_ms` fixed window per key. charge returns false when the charge would exceed the cap.
    class WindowReadAccumulator
      def initialize(cap, window_ms)
        @cap = cap
        @window = window_ms
        @used = {}
      end

      def charge(key, units, now)
        return false unless [units, now].all? { |v| Js.num?(v) && v.to_f.finite? } # a non-finite charge or clock admits nothing

        e = @used[key]
        cur = e.nil? || now - e['start'] >= @window ? { 'start' => now, 'n' => 0 } : e
        return false unless cur['n'] + units <= @cap

        cur['n'] += units
        @used[key] = cur
        true
      end
    end

    def enc_cursor(c, key) = "#{AtlasPca.b64e(Js.json(c))}.#{Grants.sign_body(LIST_CURSOR_DOMAIN, c, key)}"

    # One page of authorized objects: { 'objects', 'next_cursor'?, 'receipt' }. `relation` is { 'source', 'relation' }; `page` is
    # { 'cursor'?, 'limit' }. Raises ListError ('bad_limit', 'bad_cursor', 'read_budget_exhausted').
    def list_authorized(subject:, resource_type:, permits:, candidates:, filter_id:, policy_digest:, fresh_at_digest:, page:, reads:, now:,
                        signing_key:, relation: nil, max_scan: nil)
      limit = page['limit']
      raise ListError.new('bad_limit', "limit must be 1..#{MAX_PAGE_LIMIT}") if !Js.safe_integer?(limit) || limit < 1 || limit > MAX_PAGE_LIMIT

      limit = limit.to_i
      signer = Grants.signer_of(signing_key)
      bind_inputs = { 'subject' => subject, 'resourceType' => resource_type, 'filterId' => filter_id, 'policyDigest' => policy_digest, 'limit' => limit }
      bind_inputs['relation'] = relation unless relation.nil?
      bind = AtlasPca.list_bind(bind_inputs)
      inner = nil
      skip_in = 0
      unless page['cursor'].nil?
        c = AtlasPca.verify_list_cursor(page['cursor'], signer, bind_inputs)
        unless c['ok']
          raise ListError.new('bad_cursor', c['reason'] == 'bind' ? 'subject, type, filter, policy or limit changed between pages' : 'the page cursor is malformed, forged or from another signer')
        end

        inner = c['inner']
        skip_in = c['skip']
      end
      max_scan_n = [max_scan.nil? ? limit * 4 : max_scan, 1000].min
      key = AtlasPca.hash_canonical({ 's' => subject, 't' => resource_type })
      out = []
      scanned = 0
      # candidate pages are always `limit` long so a resume point (page start + objects already consumed) is exact
      page_start = inner
      skip = skip_in
      resume = nil
      loop do
        q = { 'type' => resource_type, 'limit' => limit }
        q['cursor'] = page_start unless page_start.nil?
        pg = candidates.page(q)
        objs = pg['objects'].to_a.first(limit)
        # charge what was SCANNED before anything is returned: enumeration by filter-heavy scans is the attack
        raise ListError.new('read_budget_exhausted', 'the read budget for this subject and type is exhausted') unless reads.charge(key, [objs.length - skip, 1].max, now)

        i = skip
        while i < objs.length && out.length < limit
          scanned += 1
          o = objs[i]
          i += 1
          next unless permits.call(o)
          next if !relation.nil? && !relation['source'].check({ 'subject' => subject, 'relation' => relation['relation'], 'object' => o })

          out << o
        end
        if i < objs.length
          resume = { 'skip' => i }
          resume['inner'] = page_start unless page_start.nil?
          break
        end
        nxt = pg['next']
        break if nxt.nil? || nxt == '' || objs.empty?

        page_start = nxt
        skip = 0
        if out.length >= limit || scanned >= max_scan_n
          resume = { 'inner' => nxt, 'skip' => 0 }
          break
        end
      end
      receipt = { 'v' => 1, 'subject' => subject, 'resource_type' => resource_type, 'policy_digest' => policy_digest, 'fresh_at' => fresh_at_digest,
                  'filter_digest' => filter_id, 'count' => out.length, 'objects_digest' => AtlasPca.objects_digest(out), 'issued_at' => now, 'signer' => signer }
      result = { 'objects' => out }
      unless resume.nil?
        cur = { 'v' => 1 }
        cur['inner'] = resume['inner'] if resume.key?('inner')
        cur['skip'] = resume['skip']
        cur['bind'] = bind
        cur['signer'] = signer
        result['next_cursor'] = enc_cursor(cur, signing_key)
      end
      result['receipt'] = receipt.merge('sig' => Grants.sign_body(LIST_RECEIPT_DOMAIN, receipt, signing_key))
      result
    end
  end
end
