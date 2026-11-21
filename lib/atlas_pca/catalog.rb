# frozen_string_literal: true

module AtlasPca
  # The connector action catalog (the reference's `catalog` module): a small registry of data that resolves a human `permissions`
  # shorthand into what a grant is compiled from: a verb, a resource matcher, a reversibility class, a blast-radius preset and,
  # for a money-moving action, the params field that carries the amount. This is data, not enforcement: nothing here authorizes
  # anything. Specs are String-keyed Hashes with the reference's member names (connector, action, verb, reversibility,
  # blastRadius, amountField, resource, description, aliases, traits). An unknown verb resolves fail-closed (irreversible,
  # maximum blast radius), and an extension may only make an existing entry more cautious.
  #
  # A Catalog is an immutable lookup over action specs: later specs replace earlier ones by verb, in place; `all` and
  # `for_connector` keep the order of first appearance.
  class Catalog
    # Blast-radius presets by shape of action: conservative, overridable.
    BLAST = { 'read' => 0.05, 'reversibleWrite' => 0.2, 'rateLimitedWrite' => 0.5, 'irreversibleWrite' => 0.8, 'moneyMovement' => 0.9 }.freeze
    # white space as the reference's regular expressions read it, and a dot
    BAD_CONNECTOR = /[\t\n\v\f\r    -     　﻿.]/

    def initialize(actions = nil)
      @by_verb = {}
      (actions.nil? ? BUILTIN_ACTIONS : actions).each do |a|
        raise TypeError, 'buildCatalog: an action spec is null' if a.nil?

        @by_verb[a.is_a?(Hash) ? a['verb'] : nil] = a
      end
      freeze
    end

    # The spec of a verb (`connector.action`), or nil.
    def get(verb = nil) = @by_verb[verb]

    # Every action of a connector namespace.
    def for_connector(connector = nil) = @by_verb.values.select { |a| a.is_a?(Hash) && a['connector'] == connector }

    # Every action of the catalog.
    def all = @by_verb.values

    # `connector` + `action` as written by a human or a model: the exact verb, else an alias of exactly one action of that
    # connector. Absent or ambiguous: nil (never a guess).
    def resolve(connector = nil, action = nil)
      exact = @by_verb["#{Catalog.text(connector)}.#{Catalog.text(action)}"]
      return exact if exact

      hits = for_connector(connector).select do |a|
        aliases = a['aliases']
        next false if aliases.nil?
        raise TypeError, 'aliases is not a list' unless aliases.is_a?(Array) || aliases.is_a?(String)

        aliases.is_a?(Array) ? aliases.include?(action) : aliases.include?(Catalog.text(action))
      end
      hits.length == 1 ? hits[0] : nil
    end

    class << self
      # a value inside a template string of the reference
      def text(x)
        case x
        when String then x
        when nil then 'undefined'
        when Numeric then Predicates.js_number_string(x)
        else x.to_s
        end
      end

      # One action spec, shape-checked; `verb` defaults to connector + "." + action and every other member is kept. Use with
      # build_catalog / extend_catalog to add to the built-in actions. Raises ArgumentError on a bad shape.
      def define_action(spec)
        raise TypeError, 'defineAction: the spec is null' if spec.nil?

        s = spec.is_a?(Hash) ? spec : {}
        connector = s['connector']
        action = s['action']
        unless connector.is_a?(String) && action.is_a?(String) && !connector.empty? && !action.empty?
          raise ArgumentError, 'defineAction: connector and action are required'
        end
        raise ArgumentError, 'defineAction: connector must not contain whitespace or a dot' if connector.match?(BAD_CONNECTOR)
        if s.key?('amountField') && !(s['amountField'].is_a?(String) && !s['amountField'].empty?)
          raise ArgumentError, 'defineAction: amountField must be a non-empty string'
        end
        unless REVERSIBILITY_ORDER.include?(s['reversibility'])
          raise ArgumentError, "defineAction: bad reversibility '#{s.key?('reversibility') ? s['reversibility'].inspect : 'undefined'}'"
        end
        blast = s['blastRadius']
        raise ArgumentError, 'defineAction: blastRadius must be in [0,1]' unless blast.is_a?(Numeric) && blast >= 0 && blast <= 1 # false for NaN

        s.merge('verb' => s['verb'].nil? ? "#{connector}.#{action}" : s['verb'])
      end

      # A catalog over `actions` (default: the built-in actions). The specs are taken as they are (define_action checks one).
      def build_catalog(actions = nil) = new(actions)

      # What a verb is treated as when the catalog does not know it: irreversible, maximum blast radius.
      def uncatalogued_spec(verb)
        connector, _dot, rest = verb.partition('.')
        { 'connector' => connector, 'action' => rest.empty? ? verb : rest, 'verb' => verb, 'reversibility' => 'irreversible',
          'blastRadius' => 1, 'description' => "(uncatalogued) #{verb}" }
      end

      # {'spec', 'catalogued'} of a verb, failing closed: an unknown verb comes back as uncatalogued_spec with catalogued false.
      def resolve_action(catalog, verb)
        spec = catalog.get(verb)
        spec ? { 'spec' => spec, 'catalogued' => true } : { 'spec' => uncatalogued_spec(verb), 'catalogued' => false }
      end

      # A digest of the whole catalog: SHA-256 over the canonical JSON of the specs sorted by verb (in UTF-16 code unit order, as
      # the reference sorts). Pin it: a deployment that records the digest of the catalog it reviewed can refuse to start when
      # the catalog has since changed.
      def catalog_digest(catalog)
        specs = catalog.all.sort_by { |a| a.is_a?(Hash) && a['verb'].is_a?(String) ? Predicates.units(a['verb']) : [] }
        AtlasPca.hash_canonical(whole_numbers(specs))
      end

      # a whole Float is the Integer the reference's one number type prints (blastRadius 1.0 is 1)
      def whole_numbers(v)
        case v
        when Float then v.finite? && v == v.floor && v.abs <= MAX_SAFE ? v.to_i : v
        when Array then v.map { |x| whole_numbers(x) }
        when Hash then v.transform_values { |x| whole_numbers(x) }
        else v
        end
      end

      # Raises ArgumentError unless `catalog` hashes to `expected`.
      def assert_catalog_pinned(catalog, expected)
        raise ArgumentError, 'catalog does not match the pinned digest' unless expected.is_a?(String) && catalog_digest(catalog) == expected

        nil
      end

      # `base` with more actions. Unlike build_catalog(base.all + extra), an extra action may not replace an existing verb with
      # a less cautious one (a lower reversibility class or a lower blast radius): ArgumentError.
      def extend_catalog(base, extra)
        sev = ->(c) { REVERSIBILITY_ORDER.index(c) || -1 }
        num = ->(x) { x.is_a?(Numeric) && !(x.is_a?(Float) && x.nan?) }
        extra.each do |e|
          old = base.get(e['verb'])
          next unless old
          if sev.call(e['reversibility']) < sev.call(old['reversibility']) ||
             (num.call(e['blastRadius']) && num.call(old['blastRadius']) && e['blastRadius'] < old['blastRadius'])
            raise ArgumentError, "extendCatalog: '#{e['verb']}' would be less cautious than the existing entry"
          end
        end
        build_catalog(base.all + extra)
      end
    end

    # The default catalog over the built-in actions.
    DEFAULT_CATALOG = build_catalog
  end
end
