# frozen_string_literal: true

require 'json'
require 'openssl'
require 'securerandom'
require 'socket'
require 'digest'
require 'fileutils'

module AtlasPca
  # Crash-safe, tamper-evident, multi-process-safe persistent key/value state (the reference's `durable-state`; a faithful port, the
  # on-disk format is the same). WHY: rollback protection for signed manifests and key sets is only as good as the persistence of "the
  # highest thing I ever accepted".
  #
  # LAYOUT (a directory you own, mode 0700): `state.journal` (hash-chained records, one JSON object per line), `state.head` (seq + hash of
  # the last record, written AFTER the journal), `state.lock.<g>` (the lock: immutable numbered generation files created atomically with
  # link(2)), `state.fence*` (operator-recovery fences).
  #
  # GUARANTEES: every mutation is write-temp, fsync, rename, fsync(directory): a crash leaves the old or the new journal, never a torn one,
  # and the head trails by at most one record (repaired by the next writer). No lost updates across processes: every mutation runs under the
  # exclusive generation lock; a lock is taken over only from a PROVABLY dead holder on this host and PID namespace, never by age; the
  # generation is re-checked right before every rename. A holder that is only PAUSED across `recover_durable_state` is fenced: every record
  # and head carries the writer's generation, and the fence recovery wrote makes load refuse a late record from a released generation.
  # Records are hash-chained (and HMAC-tagged with `hmac_key`); a corrupt, truncated or rolled-back state makes every operation raise
  # DurableStateError, never silently starting empty; the ONLY way past is `recover_from_corruption: true`, which quarantines the files
  # (kept for forensics) and starts from genesis with `recovered` true.
  #
  # NOT GUARANTEED: ONE HOST and ONE PID namespace per directory (a holder on another host or in another namespace is never judged dead:
  # waiters time out, fail closed); a LOCAL filesystem with working hard links (probed at open: `link-unsupported`); a stalled live holder
  # blocks until it dies (`lock-timeout`); the journal is rewritten whole per mutation (small state) and compacted every `compact_every` records.
  class DurableStateError < StandardError
    attr_reader :code

    def initialize(code, message)
      @code = code
      super("#{code}: #{message}")
    end
  end

  # A durable state directory handle. Build with AtlasPca.open_durable_state.
  class DurableState
    DOMAIN = "pca-durable-state/v1\n"
    GENESIS = '0' * 64
    HEX64 = /\A[0-9a-f]{64}\z/
    MAX_KEY = 256
    FENCE_FILE = 'state.fence'
    FENCE_ENTRY = /\Astate\.fence\.(\d+)-([0-9a-f]+)\z/
    RECOVER_CRASH_ENV = 'PCA_DURABLE_TEST_RECOVER_CRASH_AT'
    BOOT_ID = SecureRandom.hex(12)

    attr_reader :recovered

    # ---- shared file helpers ----------------------------------------------------------------------------------------------------
    class << self
      def sha(s) = Digest::SHA256.hexdigest(s.b)

      def js_json(v) = Js.json(v)

      def safe_int?(x) = x.is_a?(Integer) && x.abs <= 9_007_199_254_740_991
      def gen?(x) = safe_int?(x) && x >= 1

      def fsync_dir(dir)
        return if Gem.win_platform? # shortcut: Windows cannot open a directory to sync it; NTFS journals the rename, upgrade if a platform call for it is ever needed

        File.open(dir, File::RDONLY) { |d| d.fsync }
      end

      def atomic_write(path, data, before_rename = nil)
        tmp = "#{path}.tmp-#{Process.pid}-#{SecureRandom.hex(6)}"
        File.open(tmp, File::WRONLY | File::CREAT | File::EXCL | File::BINARY, 0o600) do |f|
          f.write(data)
          f.fsync
        end
        if before_rename
          begin
            before_rename.call
          rescue StandardError
            begin
              File.unlink(tmp)
            rescue StandardError
              nil # best effort: the orphan temp is harmless
            end
            raise
          end
        end
        File.rename(tmp, path)
        fsync_dir(File.dirname(path))
      end

      def pid_alive?(pid)
        Process.kill(0, pid)
        true
      rescue Errno::EPERM
        true
      rescue StandardError
        false
      end

      # Process start time (field 22 of /proc/<pid>/stat), nil off Linux or when gone.
      def proc_start_of(pid)
        st = File.read("/proc/#{pid}/stat")
        st[(st.rindex(')') + 2)..].split(' ')[19]
      rescue StandardError
        nil
      end

      def my_ns
        File.readlink('/proc/self/ns/pid')
      rescue StandardError
        nil
      end

      def hostname = Socket.gethostname

      # Test-only SIGKILL of this process at a named step of operator recovery (PCA_DURABLE_TEST=1 and the env var both set).
      def test_crash_point(point)
        Process.kill('KILL', Process.pid) if ENV['PCA_DURABLE_TEST'] == '1' && ENV[RECOVER_CRASH_ENV] == point
      end

      def fence_entry_files(dir)
        Dir.children(dir).filter_map { |n| (m = FENCE_ENTRY.match(n)) ? { name: n, gen: m[1].to_i } : nil }
      end

      def parse_fence(f, where)
        ok = f.is_a?(Hash) && gen?(f['gen']) && safe_int?(f['seq']) && f['seq'] >= 0 && f['h'].is_a?(String) && HEX64.match?(f['h'])
        raise DurableStateError.new('corrupt', "#{where} has an invalid entry") unless ok

        { 'gen' => f['gen'], 'seq' => f['seq'], 'h' => f['h'] }
      end

      def read_json(path, name)
        Js.parse(File.read(path)) # JS numbers: -0 stays -0 so a fence with seq -0 is refused as the reference does
      rescue JSON::ParserError, EncodingError, Malformed
        raise DurableStateError.new('corrupt', "#{name} is not valid JSON")
      end

      # Every fence: the list in `state.fence` (absent = none) then each `state.fence.<gen>-<rand>` by generation. Malformed = corrupt.
      def read_fences(dir)
        out = []
        p = File.join(dir, FENCE_FILE)
        if File.exist?(p)
          o = read_json(p, 'state.fence')
          raise DurableStateError.new('corrupt', 'state.fence has an invalid shape') unless o.is_a?(Hash) && o['v'] == 1 && o['fences'].is_a?(Array)

          o['fences'].each { |f| out << parse_fence(f, 'state.fence') }
        end
        fence_entry_files(dir).sort_by { |e| [e[:gen], e[:name]] }.each do |e|
          o = read_json(File.join(dir, e[:name]), e[:name])
          raise DurableStateError.new('corrupt', "#{e[:name]} has an invalid shape") unless o.is_a?(Hash) && o['v'] == 1

          f = parse_fence(o['fence'], e[:name])
          raise DurableStateError.new('corrupt', "#{e[:name]} names generation #{e[:gen]} but holds #{f['gen']}") if f['gen'] != e[:gen]

          out << f
        end
        out
      end

      # (seq, hash) of the last journal record as it is on disk right now; absent or unparsable gives (0, zeros).
      def journal_tail(dir)
        lines = File.read(File.join(dir, 'state.journal')).split("\n").reject(&:empty?)
        o = JSON.parse(lines.last || 'null')
        o.is_a?(Hash) && safe_int?(o['seq']) && o['seq'] >= 1 && o['h'].is_a?(String) && HEX64.match?(o['h']) ? { 'seq' => o['seq'], 'h' => o['h'] } : { 'seq' => 0, 'h' => GENESIS }
      rescue StandardError
        { 'seq' => 0, 'h' => GENESIS }
      end

      # The operator's CUT: every journal record after the tail seen NOW must come from a generation above `g`. Its own immutable file.
      def write_fence(dir, g, before_rename = nil)
        read_fences(dir) # an unreadable fence set fails closed here too
        fence = { 'gen' => g + 1 }.merge(journal_tail(dir)).merge('from' => g, 't' => (Time.now.to_f * 1000).to_i)
        atomic_write(File.join(dir, "#{FENCE_FILE}.#{g + 1}-#{SecureRandom.hex(6)}"), "#{js_json({ 'v' => 1, 'fence' => fence })}\n", before_rename)
      end

      # a holder record is COMPLETE only with a numeric pid, a host and a non-empty nonce
      def classify_lock_file(path)
        o = begin
          JSON.parse(File.read(path))
        rescue StandardError
          return { kind: :unreadable }
        end
        return { kind: :unreadable } unless o.is_a?(Hash) || o.is_a?(Array)
        return { kind: :incomplete, raw: {} } if o.is_a?(Array)
        return { kind: :free } if o['st'] == 'free'
        return { kind: :complete, body: o } if o['pid'].is_a?(Numeric) && o['host'].is_a?(String) && o['nonce'].is_a?(String) && o['nonce'] != ''

        { kind: :incomplete, raw: o }
      end

      # Is the recorded holder demonstrably ALIVE here? Judged by PID-namespace identity when the record names one, else by hostname.
      def holder_alive_here?(b)
        return false unless b['pid'].is_a?(Numeric)

        ns_now = my_ns
        judgeable = b['ns'].is_a?(String) ? (!ns_now.nil? && b['ns'] == ns_now) : b['host'] == hostname
        return false if !judgeable || !pid_alive?(b['pid'])

        if b['start'].is_a?(String)
          cur = proc_start_of(b['pid'])
          return false if !cur.nil? && cur != b['start'] # the pid was reused by a different process
        end
        true
      end

      def confirm_holder(c, exp, path)
        case c[:kind]
        when :unreadable
          raise DurableStateError.new('invalid', "#{path} is unreadable; pass expected_holder: 'unreadable' to release it") unless exp == 'unreadable'
        when :incomplete
          unless exp == 'unreadable'
            raise DurableStateError.new('invalid', "#{path} has an incomplete holder record (#{js_json(c[:raw])[0, 160]}); after confirming its holder is gone, pass expected_holder: 'unreadable' to release it")
          end
          raise DurableStateError.new('invalid', "the holder of #{path} (pid #{c[:raw]['pid']}) is alive in this PID namespace; refusing to release a live holder") if holder_alive_here?(c[:raw])
        when :complete
          b = c[:body]
          raise DurableStateError.new('invalid', "#{path} is readable (holder pid=#{b['pid']} host=#{b['host']}); expected_holder 'unreadable' does not match") if exp == 'unreadable'
          if b['host'] != exp['host'] || b['pid'] != exp['pid'] || b['nonce'] != exp['nonce']
            raise DurableStateError.new('invalid', "expected_holder does not match the holder recorded in #{path} (recorded pid=#{b['pid']} host=#{b['host']} nonce=#{b['nonce']}); nothing was changed")
          end
          raise DurableStateError.new('invalid', "the holder of #{path} (pid #{b['pid']}) is alive in this PID namespace; refusing to release a live holder") if holder_alive_here?(b)
        end
      end

      # Operator recovery for a lock whose holder cannot be judged dead automatically (another PID namespace, a changed hostname, an
      # unreadable or incomplete top lock file, or a legacy single-file `state.lock`). Out of band: it takes the lock itself (generation g+1),
      # cuts and FENCES the released generation, then appends a "free" generation g+2. `expected_holder` is the recorded
      # {'host','pid','nonce'} EXACTLY, or 'unreadable'. Returns {'released', 'reason', 'lock_file'?}; raises DurableStateError('invalid').
      def recover(dir:, force: false, expected_holder: nil, legacy_lock: false)
        raise DurableStateError.new('invalid', 'recover_durable_state requires force: true') unless force == true

        exp = expected_holder
        unless exp == 'unreadable' || (exp.is_a?(Hash) && exp['host'].is_a?(String) && exp['pid'].is_a?(Numeric) && exp['nonce'].is_a?(String) && exp['nonce'] != '')
          raise DurableStateError.new('invalid', "expected_holder must be {'host','pid','nonce'} as recorded in the lock file, or 'unreadable'")
        end
        g = Dir.children(dir).filter_map { |f| (m = /\Astate\.lock\.(\d+)\z/.match(f)) ? m[1].to_i : nil }.max || 0
        path = File.join(dir, "state.lock.#{g}")
        top = g.zero? ? nil : classify_lock_file(path)
        legacy_path = File.join(dir, 'state.lock')
        if legacy_lock == true
          raise DurableStateError.new('invalid', "legacy_lock: true, but the blocking lock is the generation lock #{path}; call recover_durable_state without legacy_lock") if !top.nil? && top[:kind] != :free
          return { 'released' => false, 'reason' => 'not-held' } unless File.exist?(legacy_path)

          legacy = classify_lock_file(legacy_path)
          return { 'released' => false, 'reason' => 'not-held', 'lock_file' => legacy_path } if legacy[:kind] == :free

          confirm_holder(legacy, exp, legacy_path)
          write_fence(dir, g)
          File.rename(legacy_path, File.join(dir, "state.lock.legacy-recovered-#{(Time.now.to_f * 1000).to_i}-#{SecureRandom.hex(3)}"))
          fsync_dir(dir)
          return { 'released' => true, 'reason' => 'released', 'lock_file' => legacy_path }
        end
        if top.nil? || top[:kind] == :free
          if File.exist?(legacy_path)
            lb = classify_lock_file(legacy_path)
            who = lb[:kind] == :complete ? "holder pid=#{lb[:body]['pid']} host=#{lb[:body]['host']} nonce=#{lb[:body]['nonce']}" : "#{lb[:kind]} holder record"
            raise DurableStateError.new('invalid', "the blocking lock is the legacy single-file #{legacy_path} (#{who}); after confirming that holder is gone, pass legacy_lock: true with its expected_holder (or 'unreadable')")
          end
          return top.nil? ? { 'released' => false, 'reason' => 'not-held' } : { 'released' => false, 'reason' => 'not-held', 'lock_file' => path }
        end
        confirm_holder(top, exp, path)
        # in this order (formal/tla/DurableFence.tla): TAKE generation g+1 (marked `recovering`), CUT + FENCE under it, RELEASE as g+2 free
        link_body = lambda do |gen, body, crash_point|
          tmp = File.join(dir, "state.lock.tmp-#{Process.pid}-#{SecureRandom.hex(6)}")
          File.open(tmp, File::WRONLY | File::CREAT | File::EXCL | File::BINARY, 0o600) do |f|
            f.write(js_json(body))
            f.fsync
          end
          test_crash_point(crash_point)
          begin
            File.link(tmp, File.join(dir, "state.lock.#{gen}"))
          rescue Errno::EEXIST
            raise DurableStateError.new('invalid', "#{path} was superseded while recovering; re-read the lock state and retry")
          ensure
            begin
              File.unlink(tmp)
            rescue StandardError
              nil
            end
          end
        end
        ns = my_ns
        test_crash_point('before-lock')
        start = proc_start_of(Process.pid)
        body = { 'st' => 'held', 'pid' => Process.pid, 'host' => hostname, 'nonce' => SecureRandom.hex(12), 'boot' => BOOT_ID }
        body['ns'] = ns unless ns.nil?
        body['start'] = start unless start.nil?
        body['recovering'] = g
        body['t'] = (Time.now.to_f * 1000).to_i
        link_body.call(g + 1, body, 'after-lock-temp')
        test_crash_point('after-lock')
        write_fence(dir, g, -> { test_crash_point('after-fence-temp') })
        test_crash_point('after-fence')
        link_body.call(g + 2, { 'st' => 'free', 't' => (Time.now.to_f * 1000).to_i, 'recoveredFrom' => g }, 'after-release-temp')
        test_crash_point('after-release')
        { 'released' => true, 'reason' => 'released', 'lock_file' => path }
      end
    end

    # ---- the handle -------------------------------------------------------------------------------------------------------------
    # dir:, hmac_key: (>= 32 bytes), recover_from_corruption:, lock_timeout_ms: (10_000), compact_every: (256), max_value_bytes: (1 MiB), now: -> ms
    def initialize(dir:, hmac_key: nil, recover_from_corruption: false, lock_timeout_ms: 10_000, compact_every: 256, max_value_bytes: 1_048_576, now: nil)
      raise DurableStateError.new('invalid', 'dir is required') unless dir.is_a?(String) && !dir.empty?
      raise DurableStateError.new('invalid', 'hmac_key must be at least 32 bytes') if !hmac_key.nil? && hmac_key.bytesize < 32

      @dir = dir
      @key = hmac_key
      @recover_opt = recover_from_corruption == true
      @lock_timeout = lock_timeout_ms
      @compact_every = [2, compact_every].max
      @max_value = max_value_bytes
      @now = now || -> { (Time.now.to_f * 1000).to_i }
      @journal_path = File.join(dir, 'state.journal')
      @head_path = File.join(dir, 'state.head')
      @seen = { 'seq' => 0, 'hash' => GENESIS }
      @recovered = false
      @held_nonce = nil
      @my_gen = -1
      @my_ns = self.class.my_ns
      @my_start = self.class.proc_start_of(Process.pid)
      @mutex = Mutex.new
      FileUtils.mkdir_p(dir, mode: 0o700)
      begin
        File.chmod(0o700, dir)
      rescue StandardError
        nil # not ours to chmod
      end
      probe_links
      with_lock do
        l = load_or_recover
        observe(l)
        last = l[:recs].last
        write_head(last) if last && (l[:head].nil? || l[:head]['seq'] != last['seq'])
      end
    end

    # Highest chain position this handle has observed.
    def position = @seen.dup

    # Verify the chain from disk now; raises DurableStateError on any problem.
    def verify
      with_lock do
        observe(load)
        @seen.dup
      end
    end

    def get(k)
      check_key(k)
      with_lock do
        l = load
        observe(l)
        v = l[:state][k]
        v.nil? ? nil : JSON.parse(v)
      end
    end

    def keys
      with_lock do
        l = load
        observe(l)
        l[:state].keys.sort
      end
    end

    # Unconditional write (still serialised and hash-chained). Prefer `update` for monotone state.
    def set(k, value)
      check_key(k)
      vj = encode(value)
      with_lock do
        l = load
        last = l[:recs].last
        write_head(last) if last && (l[:head].nil? || l[:head]['seq'] != last['seq'])
        commit(l, k, vj)
      end
      nil
    end

    # Atomic read-modify-write: the block gets the current value (nil when absent) and returns the next value, or nil to leave the key
    # unchanged. Runs under the cross-process lock and must be quick. Returns the value now stored.
    def update(k)
      check_key(k)
      with_lock do
        l = load
        last = l[:recs].last
        write_head(last) if last && (l[:head].nil? || l[:head]['seq'] != last['seq'])
        cur = l[:state][k]
        nxt = yield(cur.nil? ? nil : JSON.parse(cur))
        next(cur.nil? ? nil : JSON.parse(cur)) if nxt.nil?

        vj = encode(nxt)
        commit(l, k, vj) if vj != cur
        JSON.parse(vj)
      end
    end

    private

    def sha(s) = self.class.sha(s)
    def js_json(v) = self.class.js_json(v)
    def now_ms = @now.call
    def mac_of(msg) = OpenSSL::HMAC.hexdigest('SHA256', @key, msg)
    def mac_eq?(a, b) = a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)

    def rec_hash(r)
      arr = [r['seq'], r['prev'], r['op'], r['payload'], r['ts']]
      arr << r['gen'] unless r['gen'].nil?
      sha(DOMAIN + js_json(arr))
    end

    def head_msg(seq, h, gen = nil) = gen.nil? ? "head\n#{seq}\n#{h}" : "head\n#{seq}\n#{h}\n#{gen}"

    def encode(value)
      s = js_json(value)
      raise DurableStateError.new('too-large', "value exceeds maxValueBytes=#{@max_value}") if Js.len16(s) > @max_value

      s
    rescue TypeError
      raise DurableStateError.new('invalid', 'value is not JSON-serialisable')
    end

    def check_key(k)
      raise DurableStateError.new('invalid', 'key must be 1..256 chars without newlines') unless k.is_a?(String) && !k.empty? && Js.len16(k) <= MAX_KEY && !k.include?("\n")
    end

    def read_head
      return nil unless File.exist?(@head_path)

      o = begin
        Js.parse(File.read(@head_path)) # JS numbers: 3.0 is 3, -0 stays -0 (and is refused)
      rescue JSON::ParserError, EncodingError, Malformed
        raise DurableStateError.new('corrupt', 'state.head is not valid JSON')
      end
      ok = o.is_a?(Hash) && self.class.safe_int?(o['seq']) && o['seq'] >= 0 && o['h'].is_a?(String) && HEX64.match?(o['h']) && (!o.key?('gen') || self.class.gen?(o['gen']))
      raise DurableStateError.new('corrupt', 'state.head has an invalid shape') unless ok

      head = { 'seq' => o['seq'], 'h' => o['h'] }
      head['gen'] = o['gen'] if o.key?('gen')
      head['mac'] = o['mac'] if o['mac'].is_a?(String)
      if @key && (head['mac'].nil? || !mac_eq?(head['mac'], mac_of(head_msg(head['seq'], head['h'], head['gen']))))
        raise DurableStateError.new('key-mismatch', 'state.head MAC does not verify (wrong key or forged head)')
      end
      head
    end

    def parse_line(line, i)
      o = begin
        Js.parse(line)
      rescue JSON::ParserError, EncodingError, Malformed
        raise DurableStateError.new('corrupt', "journal line #{i + 1} is not valid JSON")
      end
      sf = self.class.method(:safe_int?)
      ok = o.is_a?(Hash) && sf.call(o['seq']) && o['prev'].is_a?(String) && HEX64.match?(o['prev']) && %w[set checkpoint].include?(o['op']) &&
           o['payload'].is_a?(String) && sf.call(o['ts']) && o['h'].is_a?(String) && HEX64.match?(o['h']) && (!o.key?('gen') || self.class.gen?(o['gen']))
      raise DurableStateError.new('corrupt', "journal line #{i + 1} has an invalid shape") unless ok

      rec = { 'seq' => o['seq'], 'prev' => o['prev'], 'op' => o['op'], 'payload' => o['payload'], 'ts' => o['ts'] }
      rec['gen'] = o['gen'] if o.key?('gen')
      rec['h'] = o['h']
      rec['mac'] = o['mac'] if o['mac'].is_a?(String)
      rec
    end

    def load
      head = read_head
      fences = self.class.read_fences(@dir)
      unless File.exist?(@journal_path)
        raise DurableStateError.new('rollback', "state.journal is missing but state.head records seq #{head['seq']}") if !head.nil? && head['seq'].positive?

        cut = fences.find { |f| f['seq'].positive? }
        raise DurableStateError.new('rollback', "state.journal is missing but operator recovery cut it at seq #{cut['seq']}") unless cut.nil?
        raise DurableStateError.new('rollback', 'state was deleted while open') if @seen['seq'].positive?

        return { recs: [], state: {}, head: head }
      end
      text = File.read(@journal_path)
      lines = text.empty? ? [''] : text.split("\n", -1) # JS ''.split('\n') is ['']; Ruby's is []
      raise DurableStateError.new('corrupt', 'journal does not end with a newline (torn or truncated)') unless lines.last == ''

      lines.pop
      recs = []
      state = {}
      prev_hash = GENESIS
      prev_seq = 0
      prev_gen = 0
      lines.each_with_index do |line, i|
        rec = parse_line(line, i)
        if i.zero?
          raise DurableStateError.new('corrupt', 'journal does not start at genesis') if rec['op'] == 'set' && (rec['seq'] != 1 || rec['prev'] != GENESIS)
          raise DurableStateError.new('corrupt', 'bad checkpoint seq') if rec['op'] == 'checkpoint' && rec['seq'] < 1
        else
          raise DurableStateError.new('corrupt', "journal line #{i + 1}: sequence gap") if rec['seq'] != prev_seq + 1
          raise DurableStateError.new('corrupt', "journal line #{i + 1}: hash chain broken") if rec['prev'] != prev_hash
        end
        raise DurableStateError.new('corrupt', "journal line #{i + 1}: record hash mismatch (edited)") if rec_hash(rec) != rec['h']

        if @key
          if rec['mac'].nil? || !mac_eq?(rec['mac'], mac_of(rec['h']))
            raise DurableStateError.new('key-mismatch', "journal line #{i + 1}: MAC does not verify (wrong key or forged record)")
          end
        elsif !rec['mac'].nil?
          raise DurableStateError.new('key-mismatch', 'journal is MAC-tagged but no hmac_key was supplied')
        end
        rg = rec['gen'] || 0
        if rg < prev_gen
          raise DurableStateError.new('corrupt', "journal line #{i + 1} (seq #{rec['seq']}) was written by lock generation #{rg}, older than generation #{prev_gen} of an earlier record: a stale writer's record (refused)")
        end
        fences.each do |f|
          next unless rec['seq'] > f['seq'] && rg < f['gen']

          raise DurableStateError.new('corrupt', "journal line #{i + 1} (seq #{rec['seq']}) was written by lock generation #{rg}, but operator recovery fenced generations below #{f['gen']} after seq #{f['seq']}: a holder paused across recover_durable_state resumed and replaced the journal late (refused; records committed after the recovery may be lost; recover_from_corruption quarantines the files)")
        end
        prev_gen = rg
        if rec['op'] == 'checkpoint'
          entries = begin
            JSON.parse(rec['payload'])
          rescue JSON::ParserError
            raise DurableStateError.new('corrupt', 'checkpoint payload is not JSON')
          end
          raise DurableStateError.new('corrupt', 'checkpoint payload is not an array') unless entries.is_a?(Array)

          state.clear
          entries.each do |e|
            raise DurableStateError.new('corrupt', 'checkpoint entry is malformed') unless e.is_a?(Array) && e.length == 2 && e[0].is_a?(String) && e[1].is_a?(String)

            state[e[0]] = e[1]
          end
        else
          nl = rec['payload'].index("\n")
          raise DurableStateError.new('corrupt', "journal line #{i + 1}: malformed payload") if nl.nil? || nl < 1

          state[rec['payload'][0, nl]] = rec['payload'][(nl + 1)..]
        end
        recs << rec
        prev_hash = rec['h']
        prev_seq = rec['seq']
      end
      last = recs.last
      last_seq = last ? last['seq'] : 0
      fences.each do |f|
        raise DurableStateError.new('rollback', "journal is at seq #{last_seq} but operator recovery cut it at seq #{f['seq']} (truncation, or a stale writer replaced it)") if last_seq < f['seq']

        at_cut = recs.find { |r| r['seq'] == f['seq'] }
        if f['seq'].positive? && !at_cut.nil? && at_cut['h'] != f['h']
          raise DurableStateError.new('corrupt', "journal record at seq #{f['seq']} is not the record operator recovery cut at: a stale writer replaced the journal (refused; recover_from_corruption quarantines the files)")
        end
      end
      if !head.nil?
        hg = head['gen'] || 0
        raise DurableStateError.new('rollback', "journal is at seq #{last_seq} but state.head recorded seq #{head['seq']} (truncation or older copy)") if last_seq < head['seq']
        if !last.nil? && (last['gen'] || 0) < hg && (last_seq == head['seq'] + 1 || (last_seq == head['seq'] && last['h'] != head['h']))
          raise DurableStateError.new('corrupt', "journal tail (seq #{last_seq}) was written by lock generation #{last['gen'] || 0}, older than generation #{hg} that wrote state.head: a stale writer replaced the journal (refused)")
        end
        stale_head = last_seq > head['seq'] + 1 && fences.any? { |f| hg < f['gen'] && head['seq'] <= f['seq'] && last_seq > f['seq'] } &&
                     recs.any? { |r| r['seq'] == head['seq'] && r['h'] == head['h'] }
        raise DurableStateError.new('corrupt', "journal (seq #{last_seq}) is more than one record ahead of state.head (seq #{head['seq']})") if last_seq > head['seq'] + 1 && !stale_head

        unless last.nil?
          raise DurableStateError.new('corrupt', 'journal tail does not match state.head') if last_seq == head['seq'] && last['h'] != head['h']
          raise DurableStateError.new('corrupt', 'journal tail is not chained from state.head') if last_seq == head['seq'] + 1 && last['prev'] != head['h']
        end
      elsif last_seq > 1
        raise DurableStateError.new('rollback', "state.head is missing but the journal is at seq #{last_seq}")
      end
      if !last.nil?
        raise DurableStateError.new('rollback', "state moved backwards from seq #{@seen['seq']} to #{last['seq']} while open") if last['seq'] < @seen['seq']
        raise DurableStateError.new('rollback', "state forked at seq #{last['seq']} while open") if last['seq'] == @seen['seq'] && last['h'] != @seen['hash']
      elsif @seen['seq'].positive?
        raise DurableStateError.new('rollback', 'state was emptied while open')
      end
      { recs: recs, state: state, head: head }
    end

    def quarantine
      tag = "#{now_ms}-#{SecureRandom.hex(3)}"
      assert_lock_held # a writer that lost the lock must not move a newer holder's files aside
      fence_path = File.join(@dir, FENCE_FILE)
      old_entries = self.class.fence_entry_files(@dir)
      if File.exist?(fence_path) || !old_entries.empty?
        File.link(fence_path, "#{fence_path}.quarantine-#{tag}") if File.exist?(fence_path)
        self.class.atomic_write(fence_path, "#{js_json({ 'v' => 1, 'fences' => [{ 'gen' => @my_gen, 'seq' => 0, 'h' => GENESIS, 'from' => @my_gen - 1, 't' => now_ms }] })}\n")
        old_entries.each { |e| File.rename(File.join(@dir, e[:name]), File.join(@dir, "#{e[:name]}.quarantine-#{tag}")) }
      end
      [@journal_path, @head_path].each { |p| File.rename(p, "#{p}.quarantine-#{tag}") if File.exist?(p) }
      self.class.fsync_dir(@dir)
      @seen = { 'seq' => 0, 'hash' => GENESIS }
      @recovered = true
    end

    def load_or_recover
      load
    rescue DurableStateError
      raise unless @recover_opt

      quarantine
      load
    end

    def observe(l)
      last = l[:recs].last
      @seen = { 'seq' => last['seq'], 'hash' => last['h'] } if last && last['seq'] >= @seen['seq']
    end

    # ---- the lock: immutable numbered generation files (formal/tla/DurableLockGen.tla) ---------------------------------------------
    def lock_file(g) = File.join(@dir, "state.lock.#{g}")
    def legacy_lock = File.join(@dir, 'state.lock')

    def read_body(path)
      o = JSON.parse(File.read(path))
      o = {} if o.is_a?(Array) # a JS array is an object with no fields
      return nil unless o.is_a?(Hash)

      b = { 'st' => o['st'] == 'free' ? 'free' : 'held' }
      b['pid'] = o['pid'] if o['pid'].is_a?(Numeric)
      %w[host nonce start ns boot].each { |k| b[k] = o[k] if o[k].is_a?(String) }
      b['recovering'] = o['recovering'] if self.class.safe_int?(o['recovering'])
      b
    rescue StandardError
      nil
    end

    # Highest numbered generation: [g, body] (g = 0 and no body when there is none; body nil = unreadable).
    def top_lock
      g = Dir.children(@dir).filter_map { |f| (m = /\Astate\.lock\.(\d+)\z/.match(f)) ? m[1].to_i : nil }.max || -1
      g >= 1 ? [g, read_body(lock_file(g))] : [0, nil]
    end

    def holder_dead?(b, legacy_age_ms)
      return legacy_age_ms > 1000 if b.nil? # an unreadable legacy file (torn by an old version) older than 1 s
      return false if b['host'] != self.class.hostname || !b['pid'].is_a?(Numeric) # another host: cannot judge, never break
      return false if !b['ns'].nil? && b['ns'] != @my_ns # another PID namespace: cannot judge, never break
      return true unless self.class.pid_alive?(b['pid'])

      if b['start']
        cur = self.class.proc_start_of(b['pid'])
        return true if !cur.nil? && cur != b['start'] # the pid was reused by a different process
      end
      false
    end

    # Create generation g atomically with its body. false = somebody else created it first.
    def create_gen(g, body)
      tmp = File.join(@dir, "state.lock.tmp-#{Process.pid}-#{SecureRandom.hex(6)}")
      File.open(tmp, File::WRONLY | File::CREAT | File::EXCL | File::BINARY, 0o600) do |f|
        f.write(js_json(body.merge('t' => now_real)))
        f.fsync
      end
      begin
        File.link(tmp, lock_file(g))
        true
      rescue Errno::EEXIST
        false
      rescue SystemCallError => e
        raise DurableStateError.new('invalid', "the state directory's filesystem cannot create the lock atomically (link: #{e.class.name.split('::').last})")
      ensure
        begin
          File.unlink(tmp)
        rescue StandardError
          nil
        end
      end
    end

    def gc_locks(keep_from)
      Dir.children(@dir).each do |f|
        if (m = /\Astate\.lock\.(\d+)\z/.match(f))
          File.unlink(File.join(@dir, f)) if m[1].to_i < keep_from
        elsif f.start_with?('state.lock.tmp-')
          pid = f[/\Astate\.lock\.tmp-(\d+)-/, 1].to_i
          File.unlink(File.join(@dir, f)) if pid.positive? && !self.class.pid_alive?(pid)
        end
      end
    rescue StandardError
      nil # best effort
    end

    # Fail closed at open time when this filesystem cannot give the lock its atomic hard-link semantics.
    def probe_links
      a = File.join(@dir, "state.probe-#{Process.pid}-#{SecureRandom.hex(6)}")
      b = "#{a}.lnk"
      begin
        File.open(a, File::WRONLY | File::CREAT | File::EXCL | File::BINARY, 0o600) { |f| f.write('probe') }
        File.link(a, b)
        second = begin
          File.link(a, b)
          false
        rescue Errno::EEXIST
          true
        rescue StandardError
          false
        end
        raise 'link(2) is not atomic/exclusive here' if !second || File.stat(a).nlink != 2
      rescue StandardError => e
        raise DurableStateError.new('link-unsupported', "the state directory's filesystem does not provide working hard links with exclusive-create semantics (#{e.class.name.split('::').last == 'StandardError' ? e.message : e.class.name.split('::').last}); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE")
      ensure
        [a, b].each do |f|
          File.unlink(f)
        rescue StandardError
          nil
        end
      end
    end

    def with_lock(&blk)
      @mutex.synchronize { with_lock_locked(&blk) }
    end

    def with_lock_locked
      nonce = SecureRandom.hex(12)
      must_fence = false
      deadline = now_real + @lock_timeout
      loop do
        top_g, top_body = top_lock
        legacy_blocks = false
        if File.exist?(legacy_lock)
          age = begin
            now_real - (File.mtime(legacy_lock).to_f * 1000).to_i
          rescue StandardError
            0
          end
          legacy_blocks = !holder_dead?(read_body(legacy_lock), age)
        end
        free = top_g.zero? || top_body&.fetch('st', nil) == 'free'
        if !legacy_blocks && (free || holder_dead?(top_body, 0))
          recovering = free ? nil : top_body&.fetch('recovering', nil)
          body = { 'st' => 'held', 'pid' => Process.pid, 'host' => self.class.hostname, 'nonce' => nonce, 'boot' => BOOT_ID }
          body['ns'] = @my_ns unless @my_ns.nil?
          body['start'] = @my_start unless @my_start.nil?
          body['recovering'] = recovering unless recovering.nil?
          if create_gen(top_g + 1, body)
            next if top_lock[0] != top_g + 1 # a stale creator's re-created generation is buried below the real top: not a lock

            @my_gen = top_g + 1
            must_fence = !recovering.nil?
            break
          end
          next # lost the race for that generation: look again immediately
        end
        if !(now_real <= deadline)
          desc = lambda do |b|
            if b.nil? then 'an unreadable holder record'
            elsif !b['pid'].is_a?(Numeric) || b['host'].nil? || b['nonce'].nil? || b['nonce'] == ''
              "an incomplete holder record (pid=#{b['pid'] || '?'} host=#{b['host'] || '?'} nonce=#{b['nonce'].to_s.empty? ? '?' : b['nonce']}); release it with expected_holder: 'unreadable'"
            else "holder pid=#{b['pid']} host=#{b['host']} nonce=#{b['nonce']}#{b['ns'] && b['ns'] != @my_ns ? ' (another PID namespace)' : ''}"
            end
          end
          if legacy_blocks && (free || holder_dead?(top_body, 0))
            raise DurableStateError.new('lock-timeout', "could not acquire the state lock in #{@dir} within #{@lock_timeout} ms; blocked by #{legacy_lock} (legacy single-file lock of an older version; #{desc.call(read_body(legacy_lock))}). If that holder is provably gone, an operator can release it with recover_durable_state(dir:, force: true, legacy_lock: true, expected_holder:) after confirming the holder is dead; see the durable-state docs")
          end
          raise DurableStateError.new('lock-timeout', "could not acquire the state lock in #{@dir} within #{@lock_timeout} ms; blocked by #{lock_file(top_g)} (#{desc.call(top_body)}). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recover_durable_state(dir:, force: true, expected_holder:) after confirming the holder is dead; see the durable-state docs")
        end
        sleep((5 + rand(15)) / 1000.0)
      end
      @held_nonce = nonce
      gc_locks(@my_gen - 16)
      begin
        if must_fence
          # the recovery we took over may have died before (or after) writing its fence: cut and fence now, under OUR generation, before loading
          self.class.test_crash_point('takeover-after-lock')
          self.class.write_fence(@dir, @my_gen - 1, -> { self.class.test_crash_point('takeover-after-fence-temp') })
        end
        yield
      ensure
        @held_nonce = nil
        begin
          create_gen(@my_gen + 1, { 'st' => 'free' }) # release; a live holder is never superseded, so this cannot lose a race
          gc_locks(@my_gen - 15)
        rescue StandardError
          nil # the lock stays "held" by a process about to be judged dead or alive by its pid: still safe
        end
      end
    end

    def now_real = (Time.now.to_f * 1000).to_i

    # Immediately before EVERY rename this writer makes: this handle's generation must still be the highest and must still name us.
    def assert_lock_held(outcome = 'nothing was written')
      g, body = top_lock
      return unless @held_nonce.nil? || g != @my_gen || body.nil? || body['st'] != 'held' || body['nonce'] != @held_nonce

      raise DurableStateError.new('lock-lost', "the state lock is no longer held by this writer (generation #{@my_gen}, highest #{g} #{body ? body['st'] : 'unreadable'}); #{outcome}")
    end

    def commit(l, key_, value_json)
      last = l[:recs].last
      seq = (last ? last['seq'] : 0) + 1
      prev = last ? last['h'] : GENESIS
      base = { 'seq' => seq, 'prev' => prev, 'op' => 'set', 'payload' => "#{key_}\n#{value_json}", 'ts' => now_ms, 'gen' => @my_gen }
      rec = base.merge('h' => rec_hash(base))
      rec['mac'] = mac_of(rec['h']) if @key
      all = l[:recs] + [rec]
      if all.length > @compact_every
        # compact: ONE checkpoint at the same seq the new record would have, chained from the current tail, carrying the full state
        nxt = l[:state].merge(key_ => value_json)
        cb = { 'seq' => seq, 'prev' => prev, 'op' => 'checkpoint', 'payload' => js_json(nxt.to_a.sort_by { |k, _| Predicates.units(k).pack('n*') }), 'ts' => now_ms, 'gen' => @my_gen }
        cp = cb.merge('h' => rec_hash(cb))
        cp['mac'] = mac_of(cp['h']) if @key
        all = [cp]
      end
      tail = all.last
      # journal first (atomic), head second (atomic): a crash between leaves the head one record behind (repaired by the next writer)
      self.class.atomic_write(@journal_path, "#{all.map { |r| js_json(r) }.join("\n")}\n", -> { assert_lock_held })
      write_head(tail, "the journal record (seq #{tail['seq']}) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)")
      @seen = { 'seq' => tail['seq'], 'hash' => tail['h'] }
    end

    # Head write, stamped with this writer's generation and guarded by the same lock re-check as the journal.
    def write_head(tail, outcome = 'nothing was written')
      head = { 'seq' => tail['seq'], 'h' => tail['h'], 'gen' => @my_gen }
      head['mac'] = mac_of(head_msg(head['seq'], head['h'], head['gen'])) if @key
      self.class.atomic_write(@head_path, "#{js_json(head)}\n", -> { assert_lock_held(outcome) })
    end
  end

  module_function

  # In-memory key/value store with the same semantics and no durability (tests / one process).
  def create_memory_durable_kv = MemoryDurableKv.new

  # Open (creating if needed) a durable state directory. Raises DurableStateError on corrupt / rolled-back state unless recovering.
  def open_durable_state(**opts) = DurableState.new(**opts)

  # Operator recovery for a lock whose holder cannot be judged dead automatically (see DurableState.recover).
  def recover_durable_state(**opts) = DurableState.recover(**opts)
end
