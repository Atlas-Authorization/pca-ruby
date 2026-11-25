# frozen_string_literal: true

# The replay clock is the corpus header's clockMs; a header without it has no clock; cases named in clockCases run under it.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefClock < Minitest::Test
  def test_header_clock_is_read
    assert_equal 1_700_000_000_000, Ref.clock_of_header({ 'about' => 'a', 'count' => 3, 'clockMs' => 1_700_000_000_000, 'cases' => [] })
  end

  def test_a_header_without_a_clock_has_none
    assert_nil Ref.clock_of_header({ 'about' => 'a', 'count' => 3, 'cases' => [] })
    assert_raises(ArgumentError) { Ref.clock_ms('no-such-corpus') }
  end

  def test_clock_cases_run_under_the_header_clock
    h = { 'clockMs' => 1_700_000_000_000, 'clockCases' => ['b'], 'cases' => [{ 'name' => 'a' }, { 'name' => 'b' }] }
    Ref.tag_clock_cases(h)
    assert_nil h['cases'][0]['clockMs']
    assert_equal 1_700_000_000_000, h['cases'][1]['clockMs']
    Ref.with_clock(1_700_000_000_000) do
      assert_equal 1_700_000_000_000, (Time.now.to_f * 1000).round
      assert_equal 1_700_000_000_000, Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)
    end
    assert_operator Time.now.to_i, :>, 1_750_000_000
  end
end
