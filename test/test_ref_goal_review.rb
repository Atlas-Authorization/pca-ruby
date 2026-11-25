# frozen_string_literal: true

# Replays the TS-reference oracle of goal review (test-data/ref-goal-review.json.gz): the policy card, semantic diff, signed goal
# approval and its loader, over an injected stub kernel (the reference generator's).
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/goal_review'
require 'minitest/autorun'

class TestRefGoalReview < Minitest::Test
  R = AtlasPca::GoalReview
  BY_FN = Ref.load('goal-review')

  # compile: no grants -> {ok: false}; policy digest of the stub policy; analyze: five grants are too many; decide: some grant has the
  # verb; newly allowed: the grants of next the previous goal lacks
  def self.stub(mode)
    compile = lambda do |g, _ont|
      raise 'boom' if mode == 'throwcompile'

      g['grants'].empty? ? { 'ok' => false, 'reasons' => ['empty'] } : { 'ok' => true, 'policy' => { 'gids' => g['grants'].map { |x| x['gid'] }, 'n' => g['grants'].length } }
    end
    digest = lambda do |p|
      raise 'boom' if mode == 'throwdigest'

      AtlasPca.hash_canonical({ 'd' => 'stub-policy', 'p' => p })
    end
    decide = ->(g, _ont, act, _hist) { g['grants'].any? { |x| x['verb'] == act['verb'] } ? 'allow' : 'deny' }
    newly = lambda do |prev, nxt, _ont = nil, _limit = nil|
      { 'witnesses' => nxt['grants'].reject { |x| prev['grants'].any? { |y| y['gid'] == x['gid'] } }
                                    .map { |x| { 'verb' => x['verb'], 'res' => 'r', 'params' => {}, 't' => 0, 'sess' => 's', 'prin' => 'p', 'org' => 'o', 'agent' => 'a', 'depth' => 0 } },
        'complete' => true }
    end
    R::ReviewKernel.new(compile, digest, ->(p) { p['n'] >= 5 ? ['too many'] : [] }, mode == 'nodecide' ? nil : decide, mode == 'nonewly' ? nil : newly)
  end

  def self.split(opts)
    o = (opts || {}).dup
    [o, o.delete('kmode') || 'full']
  end

  DIFF = lambda do |prev, nxt, opts|
    o, km = TestRefGoalReview.split(opts)
    R.diff_goals(prev, nxt, TestRefGoalReview.stub(km), o)
  end

  APPROVE = lambda do |sub, seed, opts|
    o, km = TestRefGoalReview.split(opts)
    o['kernel'] = TestRefGoalReview.stub(km)
    R.approve_goal(sub, AtlasPca::KeyPair.from_seed_b64u(seed), o)
  end

  LOAD = lambda do |sub, approval, opts|
    o, km = TestRefGoalReview.split(opts)
    o['kernel'] = TestRefGoalReview.stub(km)
    R.load_approved_goal(sub, approval, o)
  end

  FNS = {
    'effectiveLimits' => R.method(:effective_limits), 'renderPolicyCard' => R.method(:render_policy_card), 'cardDigest' => R.method(:card_digest),
    'cardToText' => R.method(:card_to_text), 'diffGoals' => DIFF, 'diffToText' => R.method(:diff_to_text), 'approveGoalSeed' => APPROVE, 'loadApprovedGoal' => LOAD
  }.freeze

  def test_every_function_is_covered
    assert_equal FNS.keys.sort, BY_FN.keys.sort
  end

  FNS.each do |fn, call|
    define_method("test_matches_reference_#{fn}") { Ref.run(self, BY_FN[fn], call) }
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 450, BY_FN.values.sum(&:length), 'goal-review'
  end

end
