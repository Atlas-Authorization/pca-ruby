# frozen_string_literal: true

require_relative '../atlas_pca'
require_relative 'policy_bridge'

module AtlasPca
  # FGA for RAG: retrieval-time, per-principal document filtering driven by the PCA policy evaluator (the pure core of the TypeScript
  # reference @atlasauth/pca-rag: aclsFromMetadata, compile_policy, principal_from_pcactn, filter_documents).
  #
  # FAIL CLOSED: a document is admitted only when a permit predicate cleanly matches one of its ACL entries (verb = relation,
  # resource = object) and no deny predicate matches. Anything unknown (no ACL, a malformed document, an incomplete policy
  # translation, an evaluator error) drops the document. Every decision is recorded, with a content digest of the whole decision set.
  #
  # Values are JSON (Hash with String keys, Array, String ...). A principal is a String id or {'id', 'attributes'?, 'env'?}. A policy is an
  # Array of predicates, {'openfga' => {'model', 'tuples'}}, {'predicates', 'denies'?, 'report'?} or an already compiled policy.
  module Rag
    module_function

    def non_empty_string?(v) = v.is_a?(String) && !v.empty?

    def doc_acl?(v) = v.is_a?(Hash) && non_empty_string?(v['relation']) && non_empty_string?(v['object'])

    def acl_array(acl)
      return acl.select { |a| doc_acl?(a) } if acl.is_a?(Array)

      doc_acl?(acl) ? [acl] : []
    end

    # A `relation:object` tag as an ACL entry; the split is at the FIRST colon, so an object id may contain colons.
    def tag_to_acl(tag)
      return nil unless tag.is_a?(String)

      i = tag.index(':')
      return nil if i.nil? || i <= 0 || i >= tag.length - 1

      { 'relation' => tag[0, i], 'object' => tag[(i + 1)..] }
    end

    # ACL entries from free-form `acl` (one entry or a list) and `tags` (`relation:object` strings) metadata.
    def acls_from_metadata(acl, tags)
      out = acl_array(acl)
      tags.each { |t| (a = tag_to_acl(t)) && out << a } if tags.is_a?(Array)
      out
    end

    # The acting identity of a verified PCActn: its LEAF capability holder (map the key to your policy's identity with opts['id']).
    # Raises on a PCActn with no capability chain, rather than producing an empty principal.
    def principal_from_pcactn(pcactn, opts = nil)
      chain = pcactn.is_a?(Hash) ? pcactn['cap_chain'] : nil
      leaf = chain.is_a?(Array) && !chain.empty? ? chain.last : nil
      holder = leaf.is_a?(Hash) ? leaf['holder'] : nil
      raise TypeError, 'principalFromPCActn: PCActn has no leaf capability holder' unless non_empty_string?(holder)

      o = opts.is_a?(Hash) ? opts : {}
      out = { 'id' => o['id'].nil? ? holder : o['id'] }
      out['attributes'] = o['attributes'] if o.key?('attributes')
      out['env'] = o['env'] if o.key?('env')
      out
    end

    def to_principal(p)
      return { 'id' => p } if p.is_a?(String)

      p.is_a?(Hash) ? p : (p.is_a?(Array) ? {} : nil) # a JavaScript array is an object with no id
    end

    def incomplete(reason) = { 'predicates' => [], 'denies' => [], 'incomplete' => true, 'incompleteReason' => reason }

    # JavaScript `x.length > 0` for a JSON value that is not null.
    def length_positive?(x)
      case x
      when Array, String then !x.empty?
      when Hash then (n = x['length']).is_a?(Numeric) && n.positive?
      else false
      end
    end

    # Compile any policy into {'predicates', 'denies', 'incomplete', 'incompleteReason'?, 'report'?} (a compiled one passes through). A
    # value that is not a policy, or a translation with errors, is INCOMPLETE: nothing is admitted.
    def compile_policy(policy)
      return incomplete('no usable policy was supplied (fail closed)') unless policy.is_a?(Hash) || policy.is_a?(Array)
      return { 'predicates' => policy, 'denies' => [], 'incomplete' => false } if policy.is_a?(Array)
      return policy if [true, false].include?(policy['incomplete'])

      if !policy.key?('openfga') && !policy['predicates'].is_a?(Array)
        return incomplete('the policy has no predicates and is not an OpenFGA policy (fail closed)')
      end
      if policy.key?('openfga')
        fga = policy['openfga']
        return incomplete('the OpenFGA policy has no model (fail closed)') unless fga.is_a?(Hash) || fga.is_a?(Array)

        f = fga.is_a?(Hash) ? fga : {} # an array has no model or tuples
        br = f.key?('tuples') ? PolicyBridge.openfga_to_pca(f['model'], f['tuples']) : PolicyBridge.openfga_to_pca(f['model'])
        report = br['report']
        errors = report.is_a?(Hash) ? report['errors'] : nil
        return { 'predicates' => br['predicates'], 'denies' => br['denies'], 'report' => report, 'incomplete' => errors.is_a?(Array) && !errors.empty? }
      end
      out = { 'predicates' => policy['predicates'], 'denies' => policy['denies'].is_a?(Array) ? policy['denies'] : [] }
      if policy.key?('report')
        report = policy['report']
        # the reference reads report.errors.length: a report without errors is a TypeError there
        raise TypeError, 'compilePolicy: report.errors is required' unless report.is_a?(Hash) && !report['errors'].nil?

        out['report'] = report
        out['incomplete'] = length_positive?(report['errors'])
      else
        out['incomplete'] = false
      end
      out
    end

    # The evaluation context for ONE ACL entry: the subject is the principal's attributes plus its id.
    def context(principal, acl)
      attrs = principal['attributes']
      subject = case attrs
                when Hash then attrs.dup
                when Array then attrs.each_with_index.to_h { |v, i| [i.to_s, v] } # object spread of an array
                when String then attrs.each_char.with_index.to_h { |c, i| [i.to_s, c] }
                else {}
                end
      subject['id'] = principal['id']
      ctx = { 'action' => { 'verb' => acl['relation'], 'resource' => acl['object'] }, 'subject' => subject }
      ctx['env'] = principal['env'] if principal.key?('env')
      ctx
    end

    def decide_document(id, acls, principal, compiled)
      if compiled['incomplete'] == true
        why = compiled['incompleteReason']
        return { 'id' => id, 'allowed' => false, 'reason' => why.is_a?(String) ? why : 'policy translation incomplete (fail closed)' }
      end
      pid = principal['id']
      return { 'id' => id, 'allowed' => false, 'reason' => 'no principal identity (fail closed)' } unless non_empty_string?(pid)
      return { 'id' => id, 'allowed' => false, 'reason' => 'no decidable ACL metadata (fail closed)' } if acls.empty?

      last = 'no relation grants access (fail closed)'
      pol = { 'predicates' => compiled['predicates'], 'denies' => compiled['denies'] }
      acls.each do |acl|
        res = begin
          PolicyBridge.decide(pol, context(principal, acl))
        rescue StandardError, SystemStackError
          last = 'evaluator error (fail closed)'
          next
        end
        if res['allowed'] == true
          d = { 'id' => id, 'allowed' => true, 'via' => acl, 'reason' => "granted: #{pid} has #{acl['relation']} on #{acl['object']}" }
          d['matched'] = res['matched'] unless res['matched'].nil?
          return d
        end
        last = res['reason'] if res['reason'].is_a?(String)
      end
      { 'id' => id, 'allowed' => false, 'reason' => last }
    end

    # The generic filter. `get_id.call(doc, i)` reads a candidate's id (nil or empty: positional `doc#i`) and `get_acls.call(doc)` its ACL
    # entries (anything that is not a list or entry yields none); either raising marks the document unreadable and drops it.
    # Returns {'documents', 'decision'}.
    def filter(principal_input, candidates, policy, get_id, get_acls)
      principal = to_principal(principal_input) || { 'id' => '' }
      compiled = compile_policy(policy)
      list = candidates.is_a?(Array) ? candidates : []
      documents = []
      decisions = []
      allowed_ids = []
      dropped_ids = []
      allowed_indexes = []
      seen = {}
      list.each_with_index do |doc, i|
        begin
          raw_id = get_id.call(doc, i)
          doc_acls = acl_array(get_acls.call(doc))
        rescue StandardError
          fid = "doc##{i}" # metadata that cannot even be read is unknown: fail closed
          decisions << { 'id' => fid, 'allowed' => false, 'reason' => 'unreadable document metadata (fail closed)' }
          dropped_ids << fid
          next
        end
        doc_id = non_empty_string?(raw_id) ? raw_id : "doc##{i}"
        doc_id = "#{doc_id}#dup#{i}" if seen.key?(doc_id) # two candidates with one id must stay distinguishable
        seen[doc_id] = true
        d = decide_document(doc_id, doc_acls, principal, compiled)
        decisions << d
        if d['allowed'] == true
          documents << doc
          allowed_ids << doc_id
          allowed_indexes << i
        else
          dropped_ids << doc_id
        end
      end
      pid = principal['id']
      base = { 'principal' => pid.is_a?(String) ? pid : '', 'considered' => list.length, 'allowedIds' => allowed_ids, 'allowedIndexes' => allowed_indexes,
               'droppedIds' => dropped_ids, 'policyIncomplete' => compiled['incomplete'] == true }
      decision = base.merge('decisions' => decisions, 'digest' => AtlasPca.hash_canonical({ 'v' => 1, 'kind' => 'pca-rag/filter' }.merge(base)))
      decision['report'] = compiled['report'] unless compiled['report'].nil?
      { 'documents' => documents, 'decision' => decision }
    end

    def doc_member(doc, key)
      raise TypeError, 'null document' if doc.nil?

      doc.is_a?(Hash) ? doc[key] : nil
    end

    # Filter JSON documents ({'id', 'acl'?, 'tags'?} Hashes) with the default readers. A nil document is unreadable (dropped).
    def filter_documents(principal, candidates, policy)
      filter(principal, candidates, policy, ->(d, _i) { doc_member(d, 'id') },
             ->(d) { acls_from_metadata(doc_member(d, 'acl'), doc_member(d, 'tags')) })
    end

    # Record every admitted document as untrusted retrieval content (a document's text can carry an injected instruction).
    def record_retrieved(recorder, docs, get_id)
      return if recorder.nil?

      docs.each_with_index do |doc, i|
        src = begin
          get_id.call(doc, i)
        rescue StandardError
          nil
        end
        recorder.retrieval(non_empty_string?(src) ? src : "doc##{i}", doc)
      end
    end

    # A retriever whose results are PCA-filtered before they reach the model: `retrieve(query, k = nil)` plus `last_decision` for audit.
    class FilteredRetriever
      def initialize(retriever, principal, policy, get_id, get_acls, recorder)
        @retriever = retriever
        @principal = principal
        @policy = Rag.compile_policy(policy)
        @get_id = get_id || ->(d, _i) { Rag.doc_member(d, 'id') }
        @get_acls = get_acls || ->(d) { Rag.acls_from_metadata(Rag.doc_member(d, 'acl'), Rag.doc_member(d, 'tags')) }
        @recorder = recorder
        @last = nil
      end

      def retrieve(query, k = nil)
        docs = @retriever.retrieve(query, k)
        res = Rag.filter(@principal, docs.is_a?(Array) ? docs : [], @policy, @get_id, @get_acls)
        @last = res['decision']
        Rag.record_retrieved(@recorder, res['documents'], @get_id)
        res['documents']
      end

      # The decision (proof trace) of the most recent retrieval, or nil if none yet.
      def last_decision = @last
    end

    # Wrap a generic retriever (anything with #retrieve(query, k)) so every result set is filtered to what `principal` may see BEFORE it
    # reaches the model (the reference's withPcaFilter). `policy` is a policy input or the result of compile_policy; get_id / get_acls override
    # how a document's id and ACL entries are read; `recorder` (a ProvenanceRecorder) records every admitted document as untrusted retrieval content.
    def with_pca_filter(retriever, principal, policy, get_id: nil, get_acls: nil, recorder: nil)
      FilteredRetriever.new(retriever, principal, policy, get_id, get_acls, recorder)
    end
  end
end
