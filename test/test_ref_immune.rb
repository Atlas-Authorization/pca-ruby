# frozen_string_literal: true

# Replays the TS-reference oracle of the immune system's adaptation, signed tightening proposals and durable store
# (test-data/ref-immune-java.json.gz). Guardian keys are the seeds sha256("atlas-pca-conformance/immune/<label>").
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefImmune < Minitest::Test
  I = AtlasPca::Immune
  BY_FN = Ref.load('immune-java')

  def self.sd(label) = Digest::SHA256.digest("atlas-pca-conformance/immune/#{label}").b

  # the pinned guardian "@g" is the public key of the seed labelled g
  def self.pin(opts)
    return opts unless opts.is_a?(Hash) && opts['guardian'] == '@g'

    opts.merge('guardian' => AtlasPca.b64e(OpenSSL::PKey.new_raw_private_key('ED25519', sd('g')).raw_public_key))
  end

  def run_fn(fn, **kw, &call) = Ref.run(self, BY_FN[fn], call, **kw)

  def test_adapt = run_fn('adapt') { |base, a| I.adapt(base, a) }
  def test_no_widen = run_fn('noWidenViolation') { |b, a| I.no_widen_violation(b, a) }
  def test_policy_digest = run_fn('policyDigest') { |p| I.policy_digest(p) }
  def test_state_digest = run_fn('immuneStateDigest') { |s| I.immune_state_digest(s) }

  def test_issue
    run_fn('issueTighteningProposal') { |b, s, e, n, label| I.issue_tightening_proposal(b, s, e, n, self.class.sd(label)) }
  end

  def test_apply = run_fn('applyTightening') { |b, p, o| I.apply_tightening(b, p, self.class.pin(o)) }

  # A stored JSON null reads as absent in MemoryAtomicKv (update(nil) means "leave unchanged"), so the one scenario that seeds null cannot be replayed.
  def test_store
    skip_null = ->(c) { c['args'][1].any? { |op| op[0] == 'seed' && op[1].nil? } }
    run_fn('store', skip: skip_null) do |subject, ops|
      kv = AtlasPca::MemoryAtomicKv.new
      st = I.create_immune_store(kv, subject)
      ops.map do |op|
        case op[0]
        when 'seed' then kv.set("immune/state/#{subject}", op[1]) && nil
        when 'get' then st.get
        when 'observe' then st.observe(op[1])
        when 'lastEpoch' then st.last_epoch
        when 'apply' then st.apply(op[1], op[2], self.class.pin(op[3]))
        else raise "op #{op[0]}"
        end
      rescue StandardError
        { '$err' => 'Error' }
      end
    end
  end

  def test_observe_assess
    s = I.initial_state
    assert_equal 'calm', I.assess(s)['level']
    3.times { s = I.observe(s, { 'r' => 1, 'at' => 0, 'denied' => true }) }
    a = I.assess(s)
    assert_equal 'high', a['level']
    assert_equal 1, a['score']
    t = I.observe(I.observe(I.initial_state, { 'r' => 0.5, 'at' => 100 }), { 'r' => 0.5, 'at' => Float::NAN })
    assert_equal 100, t['lastAt']
    bad = I.initial_state.merge('ewma' => 2)
    assert_equal 'high', I.assess(bad)['level']
  end

  # the corpus is pinned: its fn set and every fn's case count (a fn the replay skips, or a changed corpus, fails here)
  def test_the_corpus_is_pinned_in_full
    assert_equal({ 'adapt' => 348, 'noWidenViolation' => 21, 'policyDigest' => 2, 'immuneStateDigest' => 10, 'issueTighteningProposal' => 102, 'applyTightening' => 54, 'store' => 22 }, BY_FN.transform_values(&:length))
  end

end
