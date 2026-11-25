# frozen_string_literal: true

# authorize wires the verifier's labelled hooks into the assurance report: a carried zk proof or threshold is no longer
# blanket-`unsupported` there (the check itself still fails closed); a bond stays `unsupported` (as the reference).
require_relative '../lib/atlas_pca'
require 'minitest/autorun'

class TestAssuranceHooks < Minitest::Test
  A = AtlasPca

  def test_bare_report_marks_carried_proofs_unsupported
    r = A.assurance_report({ 'zk_compliance' => {} }, { 'zk_compliance' => 'fail' }, nil)
    assert_equal 'unsupported', r['zk_compliance']['outcome']
  end

  def test_hooked_report_keeps_the_check_status_and_the_hook_label
    zk = Object.new
    A.set_assurance_label(zk, 'groth16')
    r = A.assurance_report({ 'zk_compliance' => {} }, { 'zk_compliance' => 'pass', 'attestation' => 'fail' }, nil, hooks: { 'zk' => zk })
    assert_equal %w[pass groth16], [r['zk_compliance']['outcome'], r['zk_compliance']['level']]
    assert_equal 'fail', r['attestation']['outcome']
  end

  def test_bond_stays_unsupported_with_hooks
    r = A.assurance_report({ 'bond_ref' => 'x' }, { 'leaf_signature' => 'pass' }, nil, hooks: {})
    assert_equal 'unsupported', r['bond']['outcome']
  end

  def test_authorize_hooks_are_a_hash
    assert_equal({ 'threshold' => :h }, A.assurance_hooks_of(nil, :h))
    assert_equal({ 'zk' => 1 }, A.assurance_hooks_of({ zk: 1 }, nil))
  end
end
