# frozen_string_literal: true

# L4 information-flow taint (spec section 6 L4) and the `enforce.taint` gate. A port of packages/pca/src/taint.ts and the proved
# kernels behind it (formal/dafny/Taint.dfy: ComputeSafe, Gate; verified-core ext-taint.ts computeTaintVerified / taintGateVerified).
#
# The agent's own label is never read: every declared provenance ref is re-classified from facts the SERVER holds (a trusted-input
# registry it populated, or its own committed resource graph); a ref the server cannot vouch for is `agent` (the worst case).
# Pure and deterministic; malformed or absent provenance and any internal error fail CLOSED to taint 1.
module AtlasPca
  module Taint
    module_function

    LEVELS = %w[trusted first_party tool web agent].freeze
    RANK = LEVELS.each_with_index.to_h.freeze
    MAX_RANK = LEVELS.length - 1

    # the five real level names only
    def level?(kind) = kind.is_a?(String) && RANK.key?(kind)

    # the rank of a label; an unknown or non-string kind is the WORST rank (fail closed)
    def label_rank(label)
      kind = label.is_a?(Hash) ? label['kind'] : nil
      level?(kind) ? RANK[kind] : MAX_RANK
    end

    # normalised taint value of a label: trusted 0, first_party 0.25, tool 0.5, web 0.75, agent 1
    def taint_value(label) = label_rank(label) / MAX_RANK.to_f

    # least upper bound: the higher-ranked label; equal ranks keep the id only when both agree, else the generic representative
    def join_label(a, b)
      ra = label_rank(a)
      rb = label_rank(b)
      return a if ra > rb
      return b if rb > ra
      return a if a['id'] == b['id']

      { 'kind' => a['kind'] }
    end

    # the empty lineage joins to the worst case: "no verifiable trusted input" is not "trusted"
    def join_labels(labels) = labels.empty? ? { 'kind' => 'agent' } : labels.reduce { |acc, l| join_label(acc, l) }

    # the label of one declared ref: the registry's (a known kind), else first_party for a node of the resource graph, else agent
    def classify_ref(ref, registry, graph)
      return { 'kind' => 'agent' } unless ref.is_a?(String) && !ref.empty?

      vouched = registry.lookup(ref)
      return vouched if vouched.is_a?(Hash) && level?(vouched['kind'])

      begin
        return { 'kind' => 'first_party' } if !graph.nil? && graph.node(ref)
      rescue StandardError
        nil # worst case
      end
      ref.length <= 128 ? { 'kind' => 'agent', 'id' => ref } : { 'kind' => 'agent' }
    end

    # { 'taint', 'label', 'refs', 'valid', 'reason' } for a PCActn's provenance. Never raises.
    def compute_taint(provenance, registry, resource_graph = nil)
      reg_ok = registry.respond_to?(:lookup)
      prov_ok = provenance.is_a?(Hash)
      refs = []
      if reg_ok && prov_ok && provenance.key?('trusted_refs')
        raw = provenance['trusted_refs']
        return invalid('taint: trusted_refs must be an array') unless raw.is_a?(Array)
        return invalid('taint: trusted_refs must be non-empty strings') unless raw.all? { |r| r.is_a?(String) && !r.empty? }

        refs = raw
      end
      return invalid('taint: no trusted-input registry') unless reg_ok
      return invalid('taint: provenance is absent or malformed') unless prov_ok

      classified = refs.map { |r| { 'ref' => r, 'label' => classify_ref(r, registry, resource_graph) } }
      label = join_labels(classified.map { |c| c['label'] })
      { 'taint' => label_rank(label) / MAX_RANK.to_f, 'label' => label, 'refs' => classified, 'valid' => true }
    rescue StandardError, ScriptError, SecurityError, SystemStackError => e
      invalid("taint: evaluation error (fail closed): #{e.message}")
    end

    def invalid(reason) = { 'taint' => 1, 'label' => { 'kind' => 'agent' }, 'refs' => [], 'valid' => false, 'reason' => reason }

    # The enforce.taint gate (pcactn.ts M1): { 'ok' => true } or { 'ok' => false, 'reason' }. `max_taint` is the largest taint the policy
    # accepts; a negative or non-numeric bound is a misconfiguration and never passes.
    def taint_gate(provenance, registry, resource_graph, max_taint)
      t = compute_taint(provenance, registry, resource_graph)
      return { 'ok' => false, 'reason' => t['reason'] || 'provenance lineage is not server-verifiable (fail closed)' } unless t['valid']

      unless Risk.fin?(max_taint) && max_taint >= 0
        return { 'ok' => false, 'reason' => 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)' }
      end

      allowed = (0..MAX_RANK).select { |r| r / MAX_RANK.to_f <= max_taint }.max || -1
      return { 'ok' => true } if label_rank(t['label']) <= allowed

      { 'ok' => false, 'reason' => "information-flow taint #{Predicates.js_number_string(t['taint'])} exceeds policy max #{Predicates.js_number_string(max_taint)}" }
    rescue StandardError, ScriptError, SecurityError, SystemStackError => e
      { 'ok' => false, 'reason' => "taint gate error (fail closed): #{e.message}" }
    end

    # The server's trusted-input registry: digest -> label. Only the server populates it; nothing an agent sends reaches it.
    class InMemoryRegistry
      def initialize = @m = {}

      def record(digest, label)
        @m[digest] = label.to_h { |k, v| [k.to_s, v] } if digest.is_a?(String) && !digest.empty? && label.is_a?(Hash) && Taint.level?(label.transform_keys(&:to_s)['kind'])
        self
      end

      def record_trusted(digest) = record(digest, { 'kind' => 'trusted' })
      def record_first_party(digest) = record(digest, { 'kind' => 'first_party' })
      def record_tool(digest, id) = record(digest, { 'kind' => 'tool', 'id' => id })
      def record_web(digest) = record(digest, { 'kind' => 'web' })
      def lookup(digest) = (l = @m[digest]).nil? ? nil : l.dup
      def size = @m.length
    end
  end
end
