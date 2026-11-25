# frozen_string_literal: true

# Durable state: persistence, tamper / truncation / rollback evidence, the HMAC key, compaction, quarantine, the lock protocol and
# operator recovery with its fence.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'tmpdir'

class TestDurableState < Minitest::Test
  A = AtlasPca
  E = AtlasPca::DurableStateError

  def with_dir
    Dir.mktmpdir('pca-durable') { |d| yield d }
  end

  def code_of(&blk) = assert_raises(E, &blk).code

  def test_set_get_update_keys_and_reopen
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      assert_nil s.get('a')
      s.set('a', { 'n' => 1 })
      assert_equal({ 'n' => 1 }, s.get('a'))
      assert_equal 5, s.update('c') { |prev| prev.nil? ? 5 : prev + 1 }
      assert_equal 6, s.update('c') { |prev| prev + 1 }
      assert_equal 6, s.update('c') { |_| nil } # nil keeps the value
      assert_equal %w[a c], s.keys
      assert_equal 3, s.position['seq'] # the no-op update wrote nothing
      again = A.open_durable_state(dir: d)
      assert_equal [{ 'n' => 1 }, 6, 3], [again.get('a'), again.get('c'), again.verify['seq']]
      refute again.recovered
      assert_equal 0o700, File.stat(d).mode & 0o777 unless Gem.win_platform? # NTFS has no POSIX mode bits
    end
  end

  def test_unchanged_value_does_not_commit
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      s.set('k', 1)
      s.update('k') { |_| 1 }
      assert_equal 1, s.position['seq']
    end
  end

  def test_key_and_value_validation
    with_dir do |d|
      s = A.open_durable_state(dir: d, max_value_bytes: 8)
      ['', "a\nb", 'x' * 257, nil].each { |k| assert_equal 'invalid', code_of { s.set(k, 1) } }
      assert_equal 'too-large', code_of { s.set('k', 'x' * 20) }
      assert_equal 'invalid', code_of { A.open_durable_state(dir: '') }
      assert_equal 'invalid', code_of { A.open_durable_state(dir: d, hmac_key: 'short') }
    end
  end

  def test_an_edited_record_is_corrupt
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      s.set('a', 1)
      s.set('b', 2)
      j = File.join(d, 'state.journal')
      File.write(j, File.read(j).sub('"a\\n1"', '"a\\n9"'))
      assert_equal 'corrupt', code_of { s.get('a') }
      assert_equal 'corrupt', code_of { A.open_durable_state(dir: d) }
    end
  end

  def test_truncation_and_a_deleted_journal_are_rollbacks
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      3.times { |i| s.set("k#{i}", i) }
      j = File.join(d, 'state.journal')
      lines = File.read(j).lines
      File.write(j, lines.first(1).join)
      assert_equal 'rollback', code_of { s.get('k0') }
      File.delete(j)
      assert_equal 'rollback', code_of { A.open_durable_state(dir: d) }
    end
  end

  def test_a_torn_journal_is_corrupt
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      s.set('a', 1)
      j = File.join(d, 'state.journal')
      File.write(j, File.read(j).chomp)
      assert_equal 'corrupt', code_of { s.get('a') }
    end
  end

  def test_hmac_key_tags_records_and_a_wrong_or_missing_key_is_refused
    with_dir do |d|
      key = 'k' * 32
      s = A.open_durable_state(dir: d, hmac_key: key)
      s.set('a', 1)
      assert_match(/"mac"/, File.read(File.join(d, 'state.journal')))
      assert_equal 1, A.open_durable_state(dir: d, hmac_key: key).get('a')
      assert_equal 'key-mismatch', code_of { A.open_durable_state(dir: d, hmac_key: 'z' * 32) }
      assert_equal 'key-mismatch', code_of { A.open_durable_state(dir: d) }
    end
  end

  def test_compaction_keeps_the_state_and_the_chain
    with_dir do |d|
      s = A.open_durable_state(dir: d, compact_every: 4)
      10.times { |i| s.set("k#{i % 3}", i) }
      assert_operator File.read(File.join(d, 'state.journal')).lines.length, :<=, 4
      again = A.open_durable_state(dir: d, compact_every: 4)
      assert_equal [9, 7, 8], [again.get('k0'), again.get('k1'), again.get('k2')]
      assert_equal 10, again.verify['seq']
    end
  end

  def test_recover_from_corruption_quarantines_and_starts_empty
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      s.set('a', 1)
      File.write(File.join(d, 'state.journal'), "garbage\n")
      r = A.open_durable_state(dir: d, recover_from_corruption: true)
      assert r.recovered
      assert_nil r.get('a')
      assert(Dir.children(d).any? { |f| f.start_with?('state.journal.quarantine-') })
      r.set('b', 2)
      assert_equal 2, A.open_durable_state(dir: d).get('b')
    end
  end

  def test_lock_generations_are_released_and_a_live_holder_blocks_until_timeout
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      s.set('a', 1)
      top = Dir.children(d).filter_map { |f| f[/\Astate\.lock\.(\d+)\z/, 1]&.to_i }.max
      assert_equal 'free', JSON.parse(File.read(File.join(d, "state.lock.#{top}")))['st']
      # a live holder (this process, judged alive) is never superseded
      body = { 'st' => 'held', 'pid' => Process.pid, 'host' => Socket.gethostname, 'nonce' => 'n1' }
      File.write(File.join(d, "state.lock.#{top + 1}"), JSON.generate(body))
      e = assert_raises(E) { A.open_durable_state(dir: d, lock_timeout_ms: 60) }
      assert_equal 'lock-timeout', e.code
      assert_match(/pid=#{Process.pid}/, e.message)
    end
  end

  def test_a_dead_holder_is_taken_over
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      s.set('a', 1)
      top = Dir.children(d).filter_map { |f| f[/\Astate\.lock\.(\d+)\z/, 1]&.to_i }.max
      pid = spawn(RbConfig.ruby, '-e', '') # no fork on Windows
      Process.wait(pid)
      File.write(File.join(d, "state.lock.#{top + 1}"), JSON.generate({ 'st' => 'held', 'pid' => pid, 'host' => Socket.gethostname, 'nonce' => 'dead' }))
      assert_equal 1, A.open_durable_state(dir: d, lock_timeout_ms: 2000).get('a')
    end
  end

  def test_recovery_requires_force_and_the_exact_holder
    with_dir do |d|
      A.open_durable_state(dir: d).set('a', 1)
      assert_equal 'invalid', code_of { A.recover_durable_state(dir: d, expected_holder: 'unreadable') }
      assert_equal 'invalid', code_of { A.recover_durable_state(dir: d, force: true, expected_holder: { 'host' => 'h' }) }
      assert_equal({ 'released' => false, 'reason' => 'not-held', 'lock_file' => File.join(d, "state.lock.#{Dir.children(d).filter_map { |f| f[/\Astate\.lock\.(\d+)\z/, 1]&.to_i }.max}") },
                   A.recover_durable_state(dir: d, force: true, expected_holder: 'unreadable'))
    end
  end

  def test_recovery_releases_a_holder_in_another_namespace_and_fences_it
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      s.set('a', 1)
      top = Dir.children(d).filter_map { |f| f[/\Astate\.lock\.(\d+)\z/, 1]&.to_i }.max
      holder = { 'st' => 'held', 'pid' => 424_242, 'host' => 'other-host', 'nonce' => 'abc123' }
      File.write(File.join(d, "state.lock.#{top + 1}"), JSON.generate(holder))
      assert_equal 'lock-timeout', code_of { A.open_durable_state(dir: d, lock_timeout_ms: 60) }
      assert_equal 'invalid', code_of { A.recover_durable_state(dir: d, force: true, expected_holder: holder.merge('nonce' => 'wrong')) }
      r = A.recover_durable_state(dir: d, force: true, expected_holder: { 'host' => 'other-host', 'pid' => 424_242, 'nonce' => 'abc123' })
      assert_equal [true, 'released'], [r['released'], r['reason']]
      assert(Dir.children(d).any? { |f| f.match?(/\Astate\.fence\.\d+-[0-9a-f]+\z/) })
      s2 = A.open_durable_state(dir: d, lock_timeout_ms: 2000)
      s2.set('b', 2)
      assert_equal [1, 2], [s2.get('a'), s2.get('b')]
    end
  end

  def test_a_late_record_from_a_fenced_generation_is_refused
    with_dir do |d|
      s = A.open_durable_state(dir: d)
      s.set('a', 1)
      tail = A::DurableState.journal_tail(d)
      # a fence says: records after the tail must come from generation >= 50
      fence = { 'gen' => 50, 'seq' => tail['seq'], 'h' => tail['h'], 'from' => 49 }
      File.write(File.join(d, 'state.fence.50-aa'), "#{AtlasPca::Js.json({ 'v' => 1, 'fence' => fence })}\n")
      assert_equal 1, A.open_durable_state(dir: d).get('a') # at the cut: still fine
      # the writer's generation is below 50, so what it commits after the cut is refused on the next load
      s.set('b', 2) rescue nil
      assert_equal 'corrupt', code_of { A.open_durable_state(dir: d) }
    end
  end

  def test_memory_kv_has_the_same_interface
    kv = A.create_memory_durable_kv
    kv.set('a', 1)
    assert_equal 2, kv.update('a') { |p| p + 1 }
    assert_equal ['a'], kv.keys
  end
end
