# frozen_string_literal: true

require 'net/http'
require 'uri'

module AtlasPca
  # The persistence contract of the undo ledger and its reference stores (the reference's `undo` stores and `server/undo` helpers).
  # A store is an object with `durable` (true ONLY when acknowledged writes survive a restart or crash; the coordinator refuses one that
  # does not say so), `get(id)`, `create(rec)` -> {'created' => true} | {'created' => false, 'record' => stored} (atomic insert if no record
  # has this id), `replace(id, expected_ver, next)` -> bool (atomic replace iff the stored `ver` is `expected_ver`) and `list(q)` where `q` is
  # {'state', 'window_ended_by'?, 'grant_ref'?, 'bond_ref'?, 'limit'?}. Records are String-keyed Hashes; every store hands out copies.
  UNDO_STORE_PREFIX = 'pca-undo/v1/'

  module_function

  # The first `n` UTF-16 units of `s`, one fewer when the cut would split a surrogate pair (never emits a lone surrogate).
  def clip_units(s, n)
    u = Predicates.units(s)
    k = u.length > n && n.positive? && u[n - 1].between?(0xD800, 0xDBFF) && u[n].between?(0xDC00, 0xDFFF) ? n - 1 : n
    GoalJs.from_units(u.first(k))
  end

  # True for an object that implements the undo store contract.
  def undo_store?(s)
    !s.nil? && %i[get create replace list durable].all? { |m| s.respond_to?(m) } && [true, false].include?(s.durable)
  end

  def undo_record_matches?(r, q)
    r['state'] == q['state'] && (q['window_ended_by'].nil? || r['window_end'] <= q['window_ended_by']) &&
      (q['grant_ref'].nil? || r['grant_ref'] == q['grant_ref']) && (q['bond_ref'].nil? || r['bond_ref'] == q['bond_ref'])
  end

  def undo_record_decode(raw)
    return nil if raw.nil?

    ok = raw.is_a?(Hash) && raw['v'] == 1 && undo_id_ok?(raw['id']) && UNDO_STATES.include?(raw['state']) && wb_safe_int?(raw['ver']) && raw['receipts'].is_a?(Array)
    raise UndoError.new('store_corrupt', 'an undo record has the wrong shape') unless ok

    raw
  end

  def undo_copy(v) = Marshal.load(Marshal.dump(v))

  # A process-memory store: `durable` is false, so the coordinator refuses it unless the caller says, for a test, that it accepts losing every
  # open window on restart. Never use it in production.
  class MemoryUndoStore
    def initialize
      @m = {}
      @lock = Mutex.new
    end

    def durable = false

    def get(id) = @lock.synchronize { (r = @m[id]).nil? ? nil : AtlasPca.undo_copy(r) }

    def create(rec)
      raise UndoError.new('invalid', 'an undo record id is a non-empty string without control characters') unless AtlasPca.undo_id_ok?(rec.is_a?(Hash) ? rec['id'] : nil)

      @lock.synchronize do
        cur = @m[rec['id']]
        next { 'created' => false, 'record' => AtlasPca.undo_copy(cur) } if cur

        @m[rec['id']] = AtlasPca.undo_copy(rec)
        { 'created' => true }
      end
    end

    def replace(id, expected_ver, nxt)
      raise UndoError.new('invalid', 'replace: the record id cannot change') if nxt['id'] != id

      @lock.synchronize do
        next false if @m[id].nil? || @m[id]['ver'] != expected_ver

        @m[id] = AtlasPca.undo_copy(nxt)
        true
      end
    end

    def list(q)
      out = @lock.synchronize { @m.values.select { |r| AtlasPca.undo_record_matches?(r, q) }.sort_by { |r| Predicates.units(r['id']).pack('n*') } }
      out = out.first(q['limit']) unless q['limit'].nil?
      AtlasPca.undo_copy(out)
    end
  end

  # The reference store over any durable key/value store (one document per record, every write one atomic read-modify-write): an object with
  # #get(key), #update(key) { |prev| next_or_nil } and #keys (a DurableState or MemoryDurableKv). `durable` is declared by the caller because
  # a kv cannot tell: true only over a persistent kv. `list` scans every key (fine for one host's backlog; a database store indexes it).
  class KvUndoStore
    attr_reader :durable

    def initialize(kv, durable)
      raise UndoError.new('store_missing', 'KvUndoStore needs a DurableKv') unless kv.respond_to?(:get) && kv.respond_to?(:update) && kv.respond_to?(:keys)
      raise UndoError.new('invalid', 'say whether the kv is durable (true or false)') unless [true, false].include?(durable)

      @kv = kv
      @durable = durable
    end

    def get(id)
      r = AtlasPca.undo_record_decode(@kv.get(key(id)))
      r.nil? ? nil : AtlasPca.undo_copy(r)
    end

    def create(rec)
      existing = nil
      @kv.update(key(rec['id'])) do |prev|
        existing = AtlasPca.undo_record_decode(prev)
        existing ? nil : AtlasPca.undo_copy(rec)
      end
      existing ? { 'created' => false, 'record' => AtlasPca.undo_copy(existing) } : { 'created' => true }
    end

    def replace(id, expected_ver, nxt)
      raise UndoError.new('invalid', 'replace: the record id cannot change') if nxt['id'] != id

      done = false
      @kv.update(key(id)) do |prev|
        cur = AtlasPca.undo_record_decode(prev)
        done = !cur.nil? && cur['ver'] == expected_ver
        done ? AtlasPca.undo_copy(nxt) : nil
      end
      done
    end

    def list(q)
      out = []
      @kv.keys.select { |x| x.start_with?(UNDO_STORE_PREFIX) }.sort_by { |x| Predicates.units(x).pack('n*') }.each do |k|
        r = AtlasPca.undo_record_decode(@kv.get(k))
        out << AtlasPca.undo_copy(r) if r && AtlasPca.undo_record_matches?(r, q)
        break if !q['limit'].nil? && out.length >= q['limit']
      end
      out
    end

    private

    def key(id)
      raise UndoError.new('invalid', 'an undo record id is a non-empty string without control characters') unless AtlasPca.undo_id_ok?(id)

      UNDO_STORE_PREFIX + id
    end
  end

  module_function

  # The required components that `o` (a Hash with the reference's option names in snake_case) lacks (empty when complete).
  def missing_undo_components(o)
    x = o.is_a?(Hash) ? o : {}
    m = []
    m << 'store' unless undo_store?(x['store'])
    m << 'engine' unless x['engine'].respond_to?(:plan)
    m << 'signer_secret' unless x['signer_secret'].is_a?(String) && x['signer_secret'].bytesize == 32
    m << 'audience' unless x['audience'].is_a?(String) && !x['audience'].empty?
    m << 'resolve_grant' unless x['resolve_grant'].respond_to?(:call)
    m << 'compensate' unless x['compensate'].respond_to?(:call)
    ops = x['operations']
    m << 'operations' unless ops.respond_to?(:create) && ops.respond_to?(:get) && ops.respond_to?(:transition)
    m << 'notifier' unless x['notifier'].respond_to?(:notify)
    m << 'alert' unless x['alert'].respond_to?(:call)
    m
  end

  # The undo service key's public half (base64url), for verifying tokens and receipts elsewhere.
  def undo_signer_public(secret) = undo_key(secret).public

  # Report an executed effect to the ledger: a committed effect is recorded (its result names the compensation target), an effect that
  # failed, was aborted or refused aborts the window (nothing to undo; held budget released); pending / uncertain leaves it running.
  # `undo` is a coordinator (#record_effect, #abort, #get); `outcome` is {'status' =>, 'result' =>?}.
  def report_undo_effect(undo, id, outcome)
    st = outcome['status']
    return undo.record_effect(id, outcome['result']) if st == 'committed'
    return undo.abort(id, "effect_#{st}") if %w[failed aborted refused].include?(st)

    undo.get(id) || raise(UndoError.new('invalid', "no undo record #{id}"))
  end

  # An undo notifier over the approval channels (an ApprovalChannels::Dispatcher): the notice becomes a step-up shaped message whose link is
  # the one-click undo URL and whose render is the WYSIWYS render of the action. `cfg`: {'undo_url' => ->(token, id) {..}, 'inbox_url'?}.
  def undo_notifier_from_dispatcher(dispatcher, cfg)
    UndoDispatcherNotifier.new(dispatcher, cfg)
  end

  class UndoDispatcherNotifier
    def initialize(dispatcher, cfg)
      @dispatcher = dispatcher
      @cfg = cfg
    end

    # `n`: {'kind', 'record', 'token'?, 'render'?}. Returns {'delivered' => true} or {'delivered' => false, 'reason' => ...}.
    def notify(n)
      r = n['record']
      act = "#{r['action']['verb']} on #{r['action']['resource']}"
      until_s = Time.at(r['window_end'] / 1000, r['window_end'] % 1000 * 1000, :usec).utc.strftime('%Y-%m-%dT%H:%M:%S.%LZ')
      reason =
        case n['kind']
        when 'opened' then "Already done: #{act}. You can undo it until #{until_s}."
        when 'vetoed' then "Undo started for #{act}."
        when 'compensated' then "Undone: #{act}."
        when 'compensation_failed' then "UNDO FAILED for #{act}: #{r.dig('outcome', 'reason') || 'unknown'}. An operator has been alerted."
        when 'revoked' then "The agent's grant was revoked. #{act} can still be undone until #{until_s}."
        else "Final: #{act} can no longer be undone."
        end
      req = { 'id' => "undo:#{r['id']}:#{n['kind']}", 'verb' => r['action']['verb'], 'resource' => r['action']['resource'], 'tier' => 3, 'reason' => reason,
              'goalCommit' => '', 'lineage' => { 'goalCommit' => '', 'goalVerified' => false,
                                                 'chain' => [{ 'kind' => 'action', 'label' => "#{r['action']['verb']} #{r['action']['resource']}", 'detail' => "undo: #{r['compensation']['verb']}" }],
                                                 'because' => reason },
              'r' => 0, 'requestedAt' => r['opened_at'] }
      req.merge!('render' => n['render'], 'renderDigest' => r['render_digest']) if !n['render'].nil? && !r['render_digest'].nil?
      link = n['kind'] == 'opened' && !n['token'].nil? ? @cfg['undo_url'].call(n['token'], r['id']) : @cfg['inbox_url']
      out = @dispatcher.notify_all(req, link.nil? ? {} : { 'inboxUrl' => link })
      return { 'delivered' => true } if out.any? { |d| d['delivered'] }

      { 'delivered' => false, 'reason' => out.empty? ? 'no enabled channel' : out.map { |d| "#{d['kind']}: #{d['reason'] || 'not delivered'}" }.join('; ') }
    end
  end

  # The relay over a hosted undo ledger: `GET {base_url}/v1/pca/undo/vetoes` with the instance secret key. `cfg`: {'base_url', 'secret_key',
  # 'fetch'? ->(url, headers) {{'ok','status','body'}}, 'limit'?}. `pending` returns [{'id','token','at'}]; a non-2xx answer or a malformed
  # body raises (and so finalizes nothing).
  def hosted_undo_veto_relay(cfg)
    UndoVetoRelay.new(cfg)
  end

  class UndoVetoRelay
    def initialize(cfg)
      @fetch = cfg['fetch'] || method(:http_get)
      @base = cfg['base_url'].sub(%r{/+\z}, '')
      @secret = cfg['secret_key']
      @limit = cfg['limit']
    end

    def pending
      limit = [200, [1, (@limit || 200).to_i].max].min
      res = @fetch.call("#{@base}/v1/pca/undo/vetoes?limit=#{limit}", { 'authorization' => "Bearer #{@secret}", 'accept' => 'application/json' })
      raise UndoError.new('invalid', "the veto relay answered #{res['status']}") unless res['ok']

      body = AtlasPca.parse_json(res['body'].to_s, loose: true)
      raise UndoError.new('invalid', 'the veto relay answered without a data list') unless body.is_a?(Hash) && body['data'].is_a?(Array)

      body['data'].map do |row|
        v = row.is_a?(Hash) ? row['veto'] : nil
        ok = row.is_a?(Hash) && row['record_id'].is_a?(String) && v.is_a?(Hash) && v['token'].is_a?(String) && v['at'].is_a?(Numeric)
        raise UndoError.new('invalid', 'the veto relay answered a malformed entry') unless ok

        { 'id' => row['record_id'], 'token' => v['token'], 'at' => v['at'] }
      end
    end

    private

    def http_get(url, headers)
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = http.read_timeout = 10
      res = http.request(Net::HTTP::Get.new(uri.request_uri, headers))
      { 'ok' => res.code.to_i.between?(200, 299), 'status' => res.code.to_i, 'body' => res.body }
    end
  end
end
