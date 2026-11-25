# frozen_string_literal: true

# Replays defsToYaml (the default stringifier of the reference's YAML package) against its corpora: byte-identical text, including
# anchors and aliases for containers shared between members.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_yaml_emit'
require 'minitest/autorun'

class TestRefActionsYamlEmit < Minitest::Test
  Y = AtlasPca::ActionsYamlEmit

  def same_text = ->(got, out, _c) { AtlasPca::Js.json(got) == AtlasPca::Js.json(out) }

  def test_plain_corpus
    Ref.run(self, Ref.load('core-yaml-java')['defsToYaml'], ->(ns, defs, rules = nil) { Y.defs_to_yaml(ns, defs, rules) }, compare: same_text)
  end

  # Replace {"$ref": id} in place so every reference is the ONE container built for that id.
  def fill(node, built)
    pairs = node.is_a?(Hash) ? node.keys : (0...node.length)
    pairs.each do |k|
      v = node[k]
      if v.is_a?(Hash) && v.keys == ['$ref'] then node[k] = built[v['$ref']]
      elsif v.is_a?(Hash) || v.is_a?(Array) then fill(v, built)
      end
    end
  end

  def anchors(ns, defs, rules, shared)
    built = shared.to_h { |k, v| [k, v.is_a?(Array) ? [] : {}] }
    shared.each { |k, v| v.is_a?(Array) ? built[k].concat(v) : built[k].update(v) }
    built.each_value { |v| fill(v, built) }
    holder = [defs, rules]
    fill(holder, built)
    Y.defs_to_yaml(ns, holder[0], holder[1])
  end

  def test_anchor_corpus
    Ref.run(self, Ref.load('core-yaml-anchors-java')['defsToYaml'], method(:anchors), compare: same_text)
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'defsToYaml' => 823 }, Ref.load('core-yaml-java').transform_values(&:length))
    assert_equal({ 'defsToYaml' => 32 }, Ref.load('core-yaml-anchors-java').transform_values(&:length))
  end

end
