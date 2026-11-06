# frozen_string_literal: true

# A minimal atomic key/value store: the backend of KvOperationStore and the plan registry.
#
# get(key) -> value | nil and update(key) { |previous| next } -> value: the block returns the value to store, or nil to
# leave the key unchanged; the whole read-modify-write is ONE atomic step of the backend (across threads for
# MemoryAtomicKv, across threads AND processes sharing the file for SqliteAtomicKv). Values are JSON values.
module AtlasPca
  # In-process store (one Mutex). Correct for ONE process only.
  class MemoryAtomicKv
    def initialize
      @m = {}
      @lock = Mutex.new
    end

    def get(key)
      @lock.synchronize { MemoryAtomicKv.copy(@m[key]) }
    end

    def set(key, value)
      @lock.synchronize { @m[key] = MemoryAtomicKv.copy(value) }
      nil
    end

    def update(key)
      @lock.synchronize do
        nxt = yield(MemoryAtomicKv.copy(@m[key]))
        @m[key] = MemoryAtomicKv.copy(nxt) unless nxt.nil?
        MemoryAtomicKv.copy(@m[key])
      end
    end

    def self.copy(v)
      v.nil? ? nil : Marshal.load(Marshal.dump(v))
    end
  end

  # Durable store on SQLite through the sqlite3 gem (required lazily). `update` runs inside BEGIN IMMEDIATE, so two
  # writers (threads or processes) can never both read the same previous value. One connection per thread and process.
  class SqliteAtomicKv
    TABLE = 'pca_kv'

    def initialize(path, timeout: 30)
      require 'sqlite3'
      @path = path
      @timeout_ms = (timeout * 1000).to_i
      @conn_key = :"atlas_pca_kv_#{object_id}"
      @conns = [] # every connection this store opened (all threads), so close can release them all
      @conns_mutex = Mutex.new
      conn.execute("CREATE TABLE IF NOT EXISTS #{TABLE} (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)")
    end

    def get(key)
      read(conn, key)
    end

    def set(key, value)
      update(key) { |_prev| value }
      nil
    end

    def update(key)
      db = conn
      db.execute('BEGIN IMMEDIATE')
      begin
        prev = read(db, key)
        nxt = yield(prev)
        unless nxt.nil?
          db.execute("INSERT INTO #{TABLE} (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                     [key, JSON.generate(nxt)])
        end
        db.execute('COMMIT')
        nxt.nil? ? prev : nxt
      rescue Exception # rubocop:disable Lint/RescueException
        begin
          db.execute('ROLLBACK')
        rescue StandardError
          nil
        end
        raise
      end
    end

    # Close every connection this store opened, on any thread (needed before the file is removed on Windows).
    # A later use lazily reopens a fresh connection.
    def close
      handles = @conns_mutex.synchronize { @conns.shift(@conns.size) }
      Thread.current[@conn_key] = nil
      handles.each do |pid, db|
        db.close if pid == Process.pid && !db.closed?
      rescue StandardError
        nil
      end
      nil
    end

    private

    def read(db, key)
      row = db.get_first_row("SELECT value FROM #{TABLE} WHERE key = ?", [key])
      row.nil? ? nil : JSON.parse(row[0])
    end

    def conn
      cur = Thread.current[@conn_key]
      return cur[1] if cur && cur[0] == Process.pid && !cur[1].closed?

      db = SQLite3::Database.new(@path)
      # A Ruby busy handler, not busy_timeout=: the C timeout sleeps holding the GVL, so the thread that owns the write
      # lock can never run to COMMIT and sibling threads deadlock until the timeout.
      started = nil
      db.busy_handler do |count|
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        started = now if count.zero?
        sleep(0.002)
        now - started < @timeout_ms / 1000.0
      end
      Thread.current[@conn_key] = [Process.pid, db]
      @conns_mutex.synchronize { @conns << [Process.pid, db] }
      db
    end
  end
end
