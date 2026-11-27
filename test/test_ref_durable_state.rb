# frozen_string_literal: true

# Differential oracle: the durable state store (AtlasPca.open_durable_state / recover_durable_state) against the traces generated from the
# TypeScript reference (test-data/ref-durable-state.json.gz): commit and compaction bytes, tamper / rollback / generation-fence loading, the
# lock protocol and operator recovery. A scenario is an initial directory plus steps (open + ops, recover, write, dir); the whole trace (results,
# error codes and messages, the final directory) must match.
require_relative 'support/ref_oracle'
require 'minitest/autorun'
require 'tmpdir'
require 'socket'
require 'fileutils'

class TestRefDurableState < Minitest::Test
  A = AtlasPca
  CASES = Ref.load('durable-state', seeds: false).values.flatten
  DEAD = 999_999_999
  # the reference spells option names in camelCase inside messages
  NAMES = [
    ['recover_durable_state(dir:, force: true, legacy_lock: true, expected_holder:)', 'recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder })'],
    ['recover_durable_state(dir:, force: true, expected_holder:)', 'recoverDurableState({ dir, force: true, expectedHolder })'],
    ["expected_holder must be {'host','pid','nonce'} as", 'expectedHolder must be { host, pid, nonce } as'],
    %w[recover_durable_state recoverDurableState], %w[recover_from_corruption recoverFromCorruption],
    %w[expected_holder expectedHolder], %w[legacy_lock legacyLock], %w[hmac_key hmacKey]
  ].freeze

  def self.scenario(sc)
    d = Dir.mktmpdir('pca-ds-replay-')
    host = Socket.gethostname
    pid = Process.pid
    subst = ->(s) { s.gsub('$HOST', host).gsub('$PID', pid.to_s).gsub('$DEAD', DEAD.to_s) }
    norm = lambda do |s|
      s = s.gsub(d, '$DIR').gsub(host, '$HOST').gsub("pid=#{pid}", 'pid=$PID').gsub("pid #{pid}", 'pid $PID')
      NAMES.each { |a, b| s = s.gsub(a, b) }
      s
    end
    norm_name = lambda do |f|
      f = f.sub(/\A(state\.fence\.\d+)-[0-9a-f]+/, '\1-*').sub(/\.quarantine-.*\z/, '.quarantine-*')
      f = f.sub(/\Astate\.lock\.legacy-recovered-.*\z/, 'state.lock.legacy-recovered-*')
      f.sub(/\Astate\.lock\.tmp-.*\z/, 'state.lock.tmp-*')
    end
    err = ->(e) { { 'err' => { 'code' => e.code, 'msg' => norm.call(e.message) } } }
    read = lambda do |f|
      p = File.join(d, f)
      File.exist?(p) ? File.binread(p).force_encoding('UTF-8') : nil
    end
    put = lambda do |f, text|
      p = File.join(d, f)
      if text.nil?
        FileUtils.rm_f(p)
      else
        File.binwrite(p, subst.call(text))
      end
    end
    snapshot = lambda do
      names = Dir.children(d).sort
      fences = []
      try_fence = lambda do |f, pick|
        pick.call(JSON.parse(read.call(f))).each { |x| fences << x.reject { |k, _| k == 't' } }
      rescue StandardError
        fences << { 'unreadable' => norm_name.call(f) }
      end
      try_fence.call('state.fence', ->(x) { x['fences'] }) if names.include?('state.fence')
      names.grep(/\Astate\.fence\.\d+-[0-9a-f]+\z/).sort_by { |x| [x.split('.')[2].split('-')[0].to_i, x] }.each do |f|
        try_fence.call(f, ->(x) { [x['fence']] })
      end
      gens = names.grep(/\Astate\.lock\.\d+\z/).map { |f| f[11..].to_i }
      top = nil
      unless gens.empty?
        g = gens.max
        top = begin
          b = JSON.parse(read.call("state.lock.#{g}"))
          raise TypeError, 'not an object' unless b.is_a?(Hash) || b.is_a?(Array)

          t = { 'g' => g }
          if b.is_a?(Hash) # a JS array is an object with no fields
            t['st'] = b['st'] if b.key?('st')
            %w[recovering recoveredFrom].each { |k| t[k] = b[k] if b.key?(k) }
          end
          t
        rescue StandardError
          { 'g' => g, 'st' => 'unreadable' }
        end
      end
      keep = names.reject { |f| f.start_with?('state.lock.tmp-') || f.start_with?('state.probe-') || f.include?('.tmp-') }
      { 't' => 'dir', 'files' => keep.map { |f| norm_name.call(f) }, 'journal' => read.call('state.journal'), 'head' => read.call('state.head'),
        'fences' => fences, 'top' => top }
    end
    so = lambda do |v|
      case v
      when '$HOST' then host
      when '$PID' then pid
      when Array then v.map { |x| so.call(x) }
      when Hash then v.transform_values { |x| so.call(x) }
      else v
      end
    end

    out = []
    (sc['files'] || {}).each { |f, t| put.call(f, t) }
    sc['steps'].each do |st|
      case st['t']
      when 'write'
        put.call(st['file'], st['text'])
        out << nil
      when 'dir' then out << snapshot.call
      when 'recover'
        o = so.call(st['opts'] || {})
        kw = { dir: d, force: true }
        kw[:force] = o['force'] if o.key?('force')
        kw[:expected_holder] = o['expectedHolder'] if o.key?('expectedHolder')
        kw[:legacy_lock] = o['legacyLock'] if o.key?('legacyLock')
        begin
          r = A.recover_durable_state(**kw)
          ok = { 'released' => r['released'], 'reason' => r['reason'] }
          ok['lockFile'] = norm.call(r['lock_file']) if r.key?('lock_file')
          out << { 'ok' => ok }
        rescue A::DurableStateError => e
          out << err.call(e)
        end
      when 'open'
        op = st['opts'] || {}
        clock = 1000
        kw = { dir: op.key?('dir') ? op['dir'] : d, now: -> { (clock += 1) - 1 } }
        kw[:hmac_key] = Digest::SHA256.digest(op['hmacKey']) if op.key?('hmacKey')
        kw[:hmac_key] = "\0".b * op['hmacKeyBytes'] if op.key?('hmacKeyBytes')
        { 'recoverFromCorruption' => :recover_from_corruption, 'lockTimeoutMs' => :lock_timeout_ms, 'compactEvery' => :compact_every,
          'maxValueBytes' => :max_value_bytes }.each { |a, b| kw[b] = op[a] if op.key?(a) }
        begin
          h = A.open_durable_state(**kw)
        rescue A::DurableStateError => e
          out << err.call(e)
          next
        end
        res = []
        saved = {}
        undef_v = { '$undef' => true }
        absent = ->(k) { !h.send(:load)[:state].key?(k) }
        (st['ops'] || []).each do |x|
          v = case x['op']
              when 'set' then h.set(x['key'], x['value']) && nil
              when 'get' then (r = h.get(x['key'])).nil? && absent.call(x['key']) ? undef_v : r
              when 'keys' then h.keys
              when 'verify' then h.verify
              when 'position' then h.position
              when 'update'
                arg = x['arg']
                blk = {
                  'append' => ->(p) { (p || []) + [arg] },
                  'max' => ->(p) { p.nil? || arg > p ? arg : nil },
                  'noop' => ->(_p) {},
                  'same' => ->(p) { p },
                  'set' => ->(_p) { arg }
                }.fetch(x['kind'])
                (r = h.update(x['key'], &blk)).nil? && absent.call(x['key']) ? undef_v : r
              when 'fs' then put.call(x['file'], x['text']) && nil
              when 'save' then (saved[x['name']] = [read.call('state.journal'), read.call('state.head')]) && nil
              when 'restore'
                j, hd = saved[x['name']]
                put.call('state.journal', j)
                put.call('state.head', hd)
                nil
              else raise "unknown op #{x['op']}"
              end
          res << { 'ok' => v }
        rescue A::DurableStateError => e
          res << err.call(e)
        end
        out << { 'ok' => { 'recovered' => h.recovered, 'ops' => res } }
      else raise "unknown step #{st['t']}"
      end
    end
    out << snapshot.call
    out
  ensure
    FileUtils.rm_rf(d) if d
  end

  def test_corpus_is_the_full_oracle
    assert_operator CASES.length, :>, 200
  end

  def test_scenarios_match_the_reference
    bad = []
    CASES.each do |c|
      got = Ref.canon(self.class.scenario(c['args'][0]))
      want = Ref.canon(c['out'])
      next if got == want

      i = (0...[got.length, want.length].min).find { |k| got[k] != want[k] } || [got.length, want.length].min
      bad << "#{c['name']} differs at #{i}\n    native: ...#{got[[i - 80, 0].max, 240]}\n    ref:    ...#{want[[i - 80, 0].max, 240]}"
    end
    assert_empty bad.first(6), "#{bad.length} of #{CASES.length} scenarios differ from the TS reference: #{bad.map { |b| b[/\A\S+/] }.join(' ')}"
  end
end
