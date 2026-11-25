# frozen_string_literal: true

# Replays the reference oracle of the review flow (attestation verdicts, status, queue, view, confirm) and pack transparency
# (test-data/ref-actions-review-py.json.gz).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/actions_review'
require_relative '../lib/atlas_pca/actions_transparency'
require 'minitest/autorun'

class TestRefActionsReview < Minitest::Test
  A = AtlasPca::Actions
  RV = AtlasPca::ActionsReview
  TR = AtlasPca::ActionsTransparency
  BY_FN = Ref.load('actions-review-py')
  CORE = A::CORE_REGISTRY

  def self.reg(rd) = rd.nil? ? CORE : A.extend_registry(CORE, rd)

  def self.confirm(d, oo)
    o = { 'registry' => reg(oo['regDefs']), 'reviewer' => { 'kid' => oo['kid'], 'secret' => oo['seed'] }, 'final_traits' => oo['finalTraits'], 'ts' => oo['ts'] }
    o['pins'] = oo['pins'] if oo['pins']
    o['dismissed'] = oo['dismissed'] if oo['dismissed'] && !oo['dismissed'].empty?
    RV.confirm_def(d, o)
  end

  def self.append(packs, seed_reg, seed_log)
    svc = AtlasPca::ScittLog::TransparencyService.new('EdDSA', seed_log, { 'issuer' => 'ts' })
    packs.map { |p| TR.append_pack_to_log(p, svc, { 'alg' => 'EdDSA', 'key' => seed_reg, 'issuer' => 'registry' }) }
  end

  MAP = {
    'verifyAttestation' => ->(d, p, rd) { RV.verify_attestation_verdict(d, reg(rd), p) },
    'reviewStatus' => ->(d, p, rd) { RV.review_status(d, reg(rd), p) },
    'revertStale' => ->(d, p, rd) { RV.revert_stale(d, reg(rd), p) },
    'reviewPriority' => ->(d) { RV.review_priority(d, CORE) },
    'reviewQueueOrder' => ->(ds) { RV.review_queue_order(ds, CORE).map { |d| d['verb'] } },
    'prepareReview' => ->(d, *prev) { RV.prepare_review(d, CORE, prev[0]) },
    'confirmDef' => ->(d, oo) { confirm(d, oo) },
    'packStatementPayload' => TR.method(:pack_statement_payload),
    'appendPackToLog' => ->(packs, a, b) { append(packs, a, b) },
    'verifyPackLogEntry' => ->(p, e, kr, kl, r) { TR.verify_pack_log_entry(p, e, { 'registry' => kr, 'log' => kl }, r) }
  }.freeze

  def test_every_function_is_covered = assert_equal [], BY_FN.keys - MAP.keys

  MAP.each do |fn, call|
    define_method("test_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 229, BY_FN.values.sum(&:length), 'actions-review'
  end

end
