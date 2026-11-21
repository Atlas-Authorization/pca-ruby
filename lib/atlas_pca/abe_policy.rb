# frozen_string_literal: true

module AtlasPca
  # Access structures over attributes: a monotone boolean formula as a threshold tree.
  #
  #   {"attr" => a}                       leaf, the holder must own the key for attribute a
  #   {"allOf" => [...]}                  AND (n-of-n)
  #   {"anyOf" => [...]}                  OR (1-of-n)
  #   {"threshold" => k, "of" => [...]}   k-of-n
  #
  # The normalised form is {"kind" => "leaf", "attr" => a} or {"kind" => "gate", "t" => k, "of" => [...]}. Negation is not
  # supported (ABE access structures are monotone).
  module AbePolicy
    MAX_POLICY_NODES = 1024 # bounds work on untrusted input
    # Gate nesting along any root-to-leaf path: the ciphertext header is authenticated as canonical JSON (nesting capped at 32),
    # each gate costs three JSON levels and the root sits at level 2, so 10 gates is the most that can be authenticated. Enforcing it
    # here makes "encryptable" imply "decryptable".
    MAX_POLICY_DEPTH = 10

    # a refusal carrying the reason
    class Fail < StandardError; end

    module_function

    def leaf(attr) = { 'kind' => 'leaf', 'attr' => attr }
    def gate(t, of) = { 'kind' => 'gate', 't' => t, 'of' => of }
    def leaf?(n) = n['kind'] == 'leaf'

    # the value of a JSON number as JavaScript reads it (a Float), or nil when not a number
    def num(o) = o.is_a?(Numeric) ? o.to_f : nil

    # JavaScript typeof x === 'number' && Number.isInteger(x) && x > 0
    def pos_int?(o)
      d = num(o)
      !d.nil? && d.finite? && d == d.floor && d.positive?
    end

    # JavaScript String(n) for a positive integral number
    def js_int(d)
      return d.to_i.to_s if d < 1e21

      m, e = d.to_s.split('e')
      "#{m.sub(/\.0\z/, '')}e#{e}"
    end

    # { 'ok' => true, 'tree' => ... } or { 'ok' => false, 'reason' => ... }: validate and normalise an access structure; fails closed
    # with a reason on any malformed node or oversized tree.
    def normalize(policy)
      { 'ok' => true, 'tree' => walk(policy, 'policy', 0, [0]) }
    rescue Fail => e
      { 'ok' => false, 'reason' => e.message }
    end

    def walk(p, path, gates, nodes)
      nodes[0] += 1
      raise Fail, "policy too large (> #{MAX_POLICY_NODES} nodes)" if nodes[0] > MAX_POLICY_NODES
      raise Fail, "#{path}: not an object" unless p.is_a?(Hash)

      if p.key?('attr')
        a = p['attr']
        raise Fail, "#{path}: 'attr' must be a non-empty string" unless a.is_a?(String) && !a.empty?
        raise Fail, "#{path}: 'attr' is not well-formed UTF-16" unless a.valid_encoding?
        raise Fail, "#{path}: a leaf must not mix 'attr' with a gate" if %w[allOf anyOf threshold of].any? { |k| p.key?(k) }

        return leaf(a)
      end
      gate_keys = %w[allOf anyOf threshold of].select { |k| p.key?(k) && !(k == 'of' && p.key?('threshold')) }
      if gate_keys.length > 1
        raise Fail, "#{path}: ambiguous node (#{gate_keys.join(', ')}); a gate must use exactly one of allOf/anyOf/threshold"
      end
      if gate_keys.length == 1 && gates + 1 > MAX_POLICY_DEPTH
        raise Fail, "#{path}: policy nested deeper than #{MAX_POLICY_DEPTH} gates"
      end
      if p.key?('allOf')
        kids = children(p['allOf'], 'allOf', path, gates, nodes)
        return gate(kids.length, kids)
      end
      return gate(1, children(p['anyOf'], 'anyOf', path, gates, nodes)) if p.key?('anyOf')

      if p.key?('threshold')
        t = p['threshold']
        raise Fail, "#{path}: 'threshold' must be a positive integer" unless pos_int?(t)

        kids = children(p['of'], 'of', path, gates, nodes)
        d = num(t)
        raise Fail, "#{path}: threshold #{js_int(d)} exceeds the number of branches (#{kids.length})" if d > kids.length

        return gate(d.to_i, kids)
      end
      raise Fail, "#{path}: unknown policy node (expected attr/allOf/anyOf/threshold)"
    end

    def children(raw, key, path, gates, nodes)
      raise Fail, "#{path}: '#{key}' must be a non-empty array" unless raw.is_a?(Array) && !raw.empty?

      raw.each_with_index.map { |c, i| walk(c, "#{path}.#{key}[#{i}]", gates + 1, nodes) }
    end

    def of(n) = n['of']
    def t(n) = num(n['t']).to_i

    # non-cryptographic prediction: does the attribute set satisfy the tree? (Enforcement is the cryptography.)
    def satisfies?(tree, attrs)
      return attrs.include?(tree['attr']) if leaf?(tree)

      of(tree).count { |c| satisfies?(c, attrs) } >= t(tree)
    end

    # JavaScript's default sort order: UTF-16 code units
    def js_sort(strs)
      strs.sort_by { |s| s.valid_encoding? ? s.encode('UTF-16BE').unpack('n*') : s.b.bytes }
    end

    # every attribute the tree names, sorted (UTF-16 code unit order, as the reference sorts)
    def policy_attributes(tree) = js_sort(leaves(tree).uniq)

    # leaf attributes in depth-first order (one span-program row each)
    def leaves(tree) = leaf?(tree) ? [tree['attr']] : of(tree).flat_map { |c| leaves(c) }
  end
end
