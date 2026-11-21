# frozen_string_literal: true

# The replay clock is the corpus header's clockMs; a header without it (an older corpus) gives the fallback.
require_relative 'support/ref_oracle'
require 'minitest/autorun'

class TestRefClock < Minitest::Test
  def test_header_clock_is_read
    assert_equal 1_700_000_000_000, Ref.clock_of_header({ 'about' => 'a', 'count' => 3, 'clockMs' => 1_700_000_000_000, 'cases' => [] })
  end

  def test_missing_header_clock_falls_back
    assert_equal Ref::FALLBACK_CLOCK_MS, Ref.clock_of_header({ 'about' => 'a', 'count' => 3, 'cases' => [] })
    assert_equal Ref::FALLBACK_CLOCK_MS, Ref.clock_ms('no-such-corpus')
  end
end
