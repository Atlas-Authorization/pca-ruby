# frozen_string_literal: true
# r10 targeted kills for predicates.rb (survivors of run 39866841074 that no differential oracle reaches because JSON text
# cannot spell the input): str_eq? on a non-canonical WTF-8 pair, the String() nesting limit, resolve() on a non-root first segment,
# and the type guards of verb_matches / resource_matches / predicate_matches on values that are not strings / objects.
module MutationKill
  module PredR10
    module_function
    def p_ = AtlasPca::Predicates
    def skip? = DiffUtil.skip?('predicates.rb', 'safe_regex.rb')

    def check
      # a surrogate PAIR spelled as two 3-byte forms (CESU-8) is invalid UTF-8 but the same UTF-16 units as the astral character:
      # the byte path must not be taken for it (plain_utf8? also requires valid_encoding?)
      cesu = "\xED\xA0\xBD\xED\xB8\x80".dup.force_encoding('UTF-8')
      return 'str_eq? CESU vs astral' unless p_.str_eq?(cesu, "\u{1F600}") && p_.str_eq?("\u{1F600}", cesu)
      return 'str_eq? astral vs other' if p_.str_eq?(cesu, "\u{1F601}")
      return 'str_eq? ascii-tagged' unless p_.str_eq?('abc'.dup.force_encoding('US-ASCII'), 'abc') && !p_.str_eq?('abc'.dup.force_encoding('US-ASCII'), 'abd')
      return 'str_eq? binary-tagged' if p_.str_eq?('abc'.b, 'abd')
      # JS String(): nesting up to depth 64 is read, 65 levels deep is refused
      deep = ->(n) { n.times.reduce(['x']) { |a, _| [a] } }
      begin
        p_.js_string(deep.call(64))
      rescue StandardError => e
        return "js_string nesting 64 refused: #{e.class}"
      end
      begin
        p_.js_string(deep.call(66))
        return 'js_string nesting 66 accepted'
      rescue AtlasPca::Predicates::NotCanonical
        nil
      end
      # resolve(): the first segment must be a root even when the context holds such a member
      ctx = { 'action' => { 'verb' => 'v' }, 'subject' => { 'id' => 's' }, 'env' => { 'k' => 1 }, 'foo' => { 'bar' => 1 }, 'x' => 5 }
      return 'resolve non-root' unless p_.resolve(ctx, 'foo.bar') == [false, nil] && p_.resolve(ctx, 'x') == [false, nil]
      return 'resolve root' unless p_.resolve(ctx, 'env.k') == [true, 1] && p_.resolve(ctx, 'subject.id') == [true, 's']
      # guards on values that are not strings / arrays
      [nil, 5, 1.5, true, {}, :sym].each do |v|
        return "verb_matches(#{v.inspect})" unless p_.verb_matches(v, 'v') == false
        return "resource_matches(#{v.inspect})" unless p_.resource_matches(v, 'r') == false
      end
      return 'resource_matches UNDEF' unless p_.resource_matches(p_::UNDEF, 'r') == true
      return 'verb_matches mixed array' unless p_.verb_matches([5, nil, 'v'], 'v') == true && p_.verb_matches([5, nil], 'v') == false
      [nil, 5, 'x', [], [{ 'verb' => 'v' }]].each do |v|
        got = begin
          AtlasPca.predicate_matches(v, { 'action' => { 'verb' => 'v', 'resource' => 'r' } })
        rescue StandardError => e
          "raised #{e.class}"
        end
        return "predicate_matches(#{v.inspect}) = #{got}" unless got == false
      end
      nil
    end
  end

  t('predicates r10 targeted') do
    next true if PredR10.skip?

    bad = PredR10.check
    warn bad if bad && !ENV['MUT_FILE']
    bad.nil?
  end
end
