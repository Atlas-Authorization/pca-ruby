# frozen_string_literal: true

# Replays the TS-reference oracle of the realtime revocation registry (test-data/ref-revoke.json.gz): scripted registry
# scenarios (revoke / subtree / unrevoke / kill-switch / chain check / verify gate / CAEP ingest, over a healthy or a failing
# store), isActiveAt and the CAEP event types; plus store conformance for the memory and file stores.
require_relative 'support/ref_oracle'
require 'minitest/autorun'
require 'tmpdir'

class TestRefRevoke < Minitest::Test
  R = AtlasPca::Revoke
  BY_FN = Ref.load('revoke')
  CLOCK = Ref.clock_ms('revoke')

  class Boom < R::InMemoryRevocationStore
    def initialize(fail)
      super()
      @fail = fail
    end

    def get(kind, value)
      raise 'boom' if @fail == 'failGet'

      super
    end

    def all
      raise 'boom' if @fail == 'failAll'

      super
    end
  end

  # an entry whose revokedAt is within two minutes of the wall clock or of the corpus generator's frozen clock is printed "<now>" (the reference does the same)
  def self.norm(v)
    case v
    when Array then v.map { |x| norm(x) }
    when Hash
      v.to_h do |k, x|
        now = k == 'revokedAt' && AtlasPca::Js.num?(x) && ((x - (Time.now.to_f * 1000)).abs < 120_000 || (x - CLOCK).abs < 120_000)
        [k, now ? '<now>' : norm(x)]
      end
    else v
    end
  end

  def self.step(reg, s)
    o = s['opts'] || {}
    case s['op']
    when 'revoke' then reg.revoke(s['input'])
    when 'revokeSubtree' then reg.revoke_subtree(s['target'], s['opts'])
    when 'unrevoke' then reg.unrevoke(s['key'])
    when 'list' then reg.list
    when 'lookup' then reg.lookup(s['kind'], s['value'])
    when 'prefixes' then reg.prefixes
    when 'clear' then reg.clear && nil
    when 'killAgent' then reg.kill_agent(s['holder'], o['reason'], o['revokedAt'])
    when 'killSubtree' then reg.kill_subtree(s['root'], o['reason'], o['revokedAt'])
    when 'check' then R.check_revocation(s['p'], reg, o['now'])
    when 'verify' then R.verify_with_revocation(s['p'], s['core'], reg, o['now'])
    when 'ingest' then R.ingest_caep_event(s['event'], reg)
    else raise 'bad op'
    end
  end

  SCENARIO = lambda do |spec|
    store = %w[failGet failAll].include?(spec['store']) ? Boom.new(spec['store']) : R::InMemoryRevocationStore.new
    reg = R::RevocationRegistry.new(store)
    spec['ops'].map do |s|
      norm(R.copy(step(reg, s)))
    rescue StandardError # only the refusal is compared, not its message
      { '$err' => true }
    end
  end

  # the reference stores a kind-less entry that no lookup can match; this port refuses it
  SKIP = ->(c) { c['name'].start_with?('scenario/revoke/34#') ? 'kind-less entry' : nil }

  def test_scenarios = Ref.run(self, BY_FN['scenario'], SCENARIO, skip: SKIP)
  def test_is_active_at = Ref.run(self, BY_FN['isActiveAt'], ->(e, now) { R.active_at?(e, now) })
  def test_event_types = Ref.run(self, BY_FN['caepEventTypes'], -> { R::CAEP_EVENT_TYPES })

  def test_every_function_is_covered
    assert_equal %w[caepEventTypes isActiveAt scenario], BY_FN.keys.sort
  end

  def test_in_memory_store_conforms
    assert_empty R.run_revocation_store_conformance(-> { R::InMemoryRevocationStore.new })
  end

  def test_file_store_conforms_and_survives_reopen
    Dir.mktmpdir do |d|
      n = [0]
      make = lambda do
        n[0] += 1
        R::FileRevocationStore.new(File.join(d, "r#{n[0]}.json"))
      end
      assert_empty R.run_revocation_store_conformance(make, ->(prev) { R::FileRevocationStore.new(prev.path) })
    end
  end

  def test_file_store_refuses_a_corrupt_file
    Dir.mktmpdir do |d|
      p = File.join(d, 'r.json')
      ['{not json', '{"entries":"x"}', '{"v":1,"entries":[{"kind":"cap"}]}', '{"entries":[],"x":NaN}'].each do |body|
        File.write(p, body)
        assert_raises(ArgumentError) { R::FileRevocationStore.new(p) }
      end
    end
  end

  # the corpus total is pinned (a replay that silently drops cases, or a changed corpus, fails here)
  def test_the_corpus_total_is_pinned
    assert_equal 1921, BY_FN.values.sum(&:length), 'revoke'
  end

end
