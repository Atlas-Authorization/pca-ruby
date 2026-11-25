# frozen_string_literal: true

# Resource id patterns (native port of idpattern.ts of the TypeScript reference @atlasauth/pca-actions): matching and decidable containment.
require_relative 'actions'

module AtlasPca
  module ActionsIdPattern
    A = AtlasPca::Actions
    CLASS_SETS = A::ID_CLASS_CHARS.transform_values { |s| s.each_char.to_a.freeze }.freeze
    UUID_RE = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
    MAX_ID_LEN = 128

    module_function

    def in_class(s, c)
      chars = CLASS_SETS.fetch(c)
      s.each_char.all? { |ch| chars.include?(ch) }
    end

    # Does `id` (the id part of a resource, without the type) match the pattern? A non-string id never matches.
    def id_matches(p, id)
      return false unless id.is_a?(String)
      return id.length.positive? && id.length <= MAX_ID_LEN && in_class(id, 'any_safe') if p == '*'
      return id == p['exact'] if p.key?('exact')
      return false unless id.start_with?(p['prefix'])

      rest = id[p['prefix'].length..]
      return false if rest.length < p['len'][0] || rest.length > p['len'][1]
      return UUID_RE.match?(rest) if p['class'] == 'uuid'

      in_class(rest, p['class'])
    end

    def class_subset?(a, b) = (CLASS_SETS.fetch(a) - CLASS_SETS.fetch(b)).empty?

    # Is every id matched by `inner` also matched by `outer`? Sound; an exact id never contains a pattern.
    def id_pattern_contains(outer, inner)
      return true if outer == '*'
      return false if inner == '*'
      return !inner.is_a?(String) && inner.key?('exact') && inner['exact'] == outer['exact'] if outer.key?('exact')
      return id_matches(outer, inner['exact']) if inner.key?('exact')
      return false unless inner['prefix'].start_with?(outer['prefix'])

      r = inner['prefix'][outer['prefix'].length..]
      return false unless in_class(r, outer['class'])
      return inner['class'] == 'uuid' && r == '' if outer['class'] == 'uuid'
      return false unless class_subset?(inner['class'], outer['class'])

      r.length + inner['len'][0] >= outer['len'][0] && r.length + inner['len'][1] <= outer['len'][1]
    end
  end
end
