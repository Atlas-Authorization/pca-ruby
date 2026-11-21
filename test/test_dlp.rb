# frozen_string_literal: true

require_relative '../lib/atlas_pca/control_evals'
require_relative '../lib/atlas_pca/dlp'
require 'minitest/autorun'

class TestDlp < Minitest::Test
  D = AtlasPca::Dlp
  P = AtlasPca::ControlEvals.example_dlp_policy

  def ev(verb, res, taint, pol = P) = D.evaluate_dlp(pol, { 'verb' => verb, 'resource' => res, 'taint' => taint })

  def test_example_policy
    assert_equal 'allow', ev('gmail.send', 'external:a@b', 0)['outcome']
    assert_equal 'step_up', ev('gmail.send', 'external:a@b', 2)['outcome']
    assert_equal "taint 2 > 0 for 'external-send' — needs human review", ev('gmail.send', 'external:a@b', 2)['reason']
    assert_equal 'deny', ev('gmail.send', 'external:a@b', 5)['outcome']
    assert_equal "taint 5 exceeds hard ceiling 3 for 'external-send'", ev('gmail.send', 'external:a@b', 5)['reason']
    assert_equal 'allow', ev('gmail.draft', 'draft:x', 9)['outcome']
    assert_equal 'deny', ev('files.read', 'secret:k', 1)['outcome']
    assert_equal 'deny', ev('gmail.send', 'external:a@b', Float::NAN)['outcome']
  end

  def test_malformed
    assert_equal 'malformed DLP policy', D.evaluate_dlp(nil, { 'verb' => 'v', 'resource' => 'r', 'taint' => 0 })['reason']
    bad = { 'classes' => [{ 'name' => 'c', 'resource' => '*', 'maxTaintForAuto' => '0' }] }
    assert_equal 'malformed DLP policy: ceilings must be numbers', ev('v', 'r', 0, bad)['reason']
  end

  def test_specific_then_strictest
    two = { 'classes' => [{ 'name' => 'any', 'resource' => '*', 'maxTaintForAuto' => 9 },
                          { 'name' => 'db', 'resource' => 'db:*', 'maxTaintForAuto' => 1 },
                          { 'name' => 'db-strict', 'resource' => 'db:*', 'maxTaintForAuto' => 0 }] }
    assert_equal 'db-strict', ev('v', 'db:x', 1, two)['class']
  end

  def test_default_policy
    assert_equal({ 'classes' => [] }, D.default_dlp_policy)
    p = D.default_dlp_policy({ 'piiResource' => 'pii:*', 'secretsResource' => 'sec:*' })
    assert_equal %w[pii secrets], p['classes'].map { |c| c['name'] }
  end
end
