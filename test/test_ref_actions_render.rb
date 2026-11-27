# frozen_string_literal: true

# Replays the reference oracle of the approval-render wrappers, facade specs and provenance facts
# (test-data/ref-actions-render-facade.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_render'
require 'minitest/autorun'

class TestRefActionsRender < Minitest::Test
  R = AtlasPca::ActionsRender
  BY_FN = Ref.load('actions-render-facade')

  def self.opt(c) = ->(_d) { c }

  def self.prov_actions(ds, c, probes)
    f = R.provenance_actions(ds, nil, opt(c))
    probes.map { |v| f.call({ 'verb' => v }) }
  end

  MAP = {
    'renderApproval' => ->(d, p, c) { R.render_approval_with(d, p, opt(c)) },
    'renderDigestForAction' => ->(d, p, pc, c) { R.render_digest_for_action(d, p, pc, opt(c)) },
    'approverRenderCheck' => ->(d, p, r, c) { R.approver_render_check(d, p, r, opt(c)) },
    'singleTapAllowed' => R.method(:single_tap_allowed),
    'renderersFromDefs' => ->(ds, v, p, c) { R.renderers_from_defs(ds, opt(c)).call(v, '', p) },
    'specOfDef' => ->(d, r, c) { R.spec_of_def(d, nil, opt(c), r) },
    'facadeSpecs' => ->(ds, r, c) { R.facade_specs(ds, nil, opt(c), r) },
    'provenanceInfoOf' => ->(d, c) { R.provenance_info_of(d, nil, opt(c)) },
    'provenanceActions' => ->(ds, c, probes) { prov_actions(ds, c, probes) }
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 864, BY_FN.values.sum(&:length), 'actions-render-facade'
  end

end
