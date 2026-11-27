# frozen_string_literal: true

require 'json'
require 'monitor'
require_relative 'js_compat'
require_relative 'private_file'

# Realtime revocation and a mid-run kill-switch, matching the TypeScript reference. The core verifier is a pull check; this
# adds the ACTIVE boundary: a pluggable RevocationRegistry keyed by capability id, agent holder key, issuer key or
# delegation-subtree prefix. `check_revocation` walks EVERY hop of a PCActn's cap_chain and fails closed;
# `verify_with_revocation` ANDs the core outcome with that gate; `ingest_caep_event` turns an OpenID Shared-Signals / CAEP
# event into registry entries. Entries are JSON-shaped String-keyed Hashes (kind, value, prefix?, reason, revokedAt in epoch
# ms, notBefore?), the shape the reference stores, so a FileRevocationStore file is interchangeable with it.
module AtlasPca
  module Revoke
    PREFIX_SEP = ','
    KINDS = %w[cap holder issuer prefix].freeze
    CAEP_EVENT_TYPES = {
      'sessionRevoked' => 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
      'grantRevoked' => 'https://atlasauth.net/caep/grant-revoked',
      'killSwitch' => 'https://atlasauth.net/caep/kill-switch'
    }.freeze

    module_function

    def now_ms = (Time.now.to_f * 1000).floor
    def finite?(v) = Js.num?(v) && (v.is_a?(Integer) || v.finite?)
    def nonempty?(v) = v.is_a?(String) && !v.empty?
    def copy(v) = Marshal.load(Marshal.dump(v))
    def serialize_prefix(prefix) = prefix.join(PREFIX_SEP)

    # True when a revocation is in effect at `now` (a future notBefore has not yet been reached). A non-finite clock or
    # schedule can never be shown to be "in the future", so it bites.
    def active_at?(entry, now)
      return true unless entry.is_a?(Hash) && entry.key?('notBefore')

      nb = entry['notBefore']
      return true unless finite?(now) && finite?(nb)

      now >= nb
    end

    def valid_entry?(e)
      return false unless e.is_a?(Hash) && KINDS.include?(e['kind'])
      return false unless nonempty?(e['value']) && e['reason'].is_a?(String) && finite?(e['revokedAt'])
      return false if e.key?('notBefore') && !finite?(e['notBefore'])

      if e['kind'] == 'prefix'
        p = e['prefix']
        return false unless p.is_a?(Array) && !p.empty? && p.all? { |x| nonempty?(x) }
        return false if p.join(PREFIX_SEP) != e['value']
      end
      true
    end

    # In-memory store (the default). One process; swap in a shared store for a fleet. add(entry), remove(kind, value) -> bool,
    # get(kind, value) -> entry | nil, all -> Array (a snapshot), clear.
    class InMemoryRevocationStore
      def initialize
        @m = {}
        @lock = Monitor.new
      end

      def add(entry) = @lock.synchronize { @m[[entry['kind'], entry['value']]] = Revoke.copy(entry) }
      def remove(kind, value) = @lock.synchronize { !@m.delete([kind, value]).nil? }
      def get(kind, value) = @lock.synchronize { Revoke.copy(@m[[kind, value]]) }
      def all = @lock.synchronize { @m.values.map { |e| Revoke.copy(e) } }

      def clear
        @lock.synchronize { @m.clear }
        nil
      end
    end

    # A durable store backed by one JSON file: every change is written to a temporary file, fsynced, then renamed over the real
    # file, so a crash leaves the old or the new contents, never a torn file. Single process. Fails closed: a file that exists
    # but cannot be read or does not hold a valid entry list makes the constructor raise ArgumentError (starting empty would
    # un-revoke everything).
    class FileRevocationStore < InMemoryRevocationStore
      attr_reader :path

      def initialize(path)
        super()
        @path = path
        return unless File.exist?(path)

        parsed = begin
          JSON.parse(File.binread(path).force_encoding('UTF-8'))
        rescue StandardError
          raise ArgumentError, 'FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty'
        end
        lst = parsed.is_a?(Hash) ? parsed['entries'] : nil
        unless lst.is_a?(Array) && lst.all? { |e| Revoke.valid_entry?(e) }
          raise ArgumentError, 'FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty'
        end

        lst.each { |e| @m[[e['kind'], e['value']]] = e }
      end

      def add(entry) = write { @m[[entry['kind'], entry['value']]] = Revoke.copy(entry) }
      def remove(kind, value) = write { !@m.delete([kind, value]).nil? }

      def clear
        write { @m.clear }
        nil
      end

      private

      def flush
        tmp = "#{@path}.tmp"
        body = JSON.generate({ 'v' => 1, 'entries' => @m.values }, allow_nan: false)
        AtlasPca::PrivateFile.open(tmp, File::WRONLY | File::CREAT | File::TRUNC) do |f|
          f.write(body)
          f.fsync
        end
        File.rename(tmp, @path)
      end

      # apply the change and flush under the lock; a failed flush puts memory back, so memory never claims more than disk
      def write
        @lock.synchronize do
          before = @m.dup
          out = yield
          begin
            flush
          rescue Exception # rubocop:disable Lint/RescueException
            @m.replace(before)
            raise
          end
          out
        end
      end
    end

    # A live, mutable registry of revocations over any store (the in-memory one by default).
    class RevocationRegistry
      attr_reader :store

      def initialize(store = nil)
        @store = store || InMemoryRevocationStore.new
      end

      # Revoke a capability id, holder key, issuer key or subtree prefix; returns the stored entry. `input` is
      # {kind, value | prefix, reason?, revokedAt?, notBefore?}; a malformed one raises TypeError.
      def revoke(input)
        raise TypeError, 'revoke: input must be an object' unless input.is_a?(Hash)

        revoked_at = input['revokedAt'].nil? ? Revoke.now_ms : input['revokedAt']
        reason = input['reason'].nil? ? '' : input['reason']
        raise TypeError, 'revoke: revokedAt must be a finite number' unless Revoke.finite?(revoked_at)
        raise TypeError, 'revoke: notBefore must be a finite number' if input.key?('notBefore') && !Revoke.finite?(input['notBefore'])
        raise TypeError, 'revoke: reason must be a string' unless reason.is_a?(String)

        kind = input['kind']
        if kind == 'prefix'
          p = input['prefix']
          raise TypeError, 'revoke: a prefix revocation requires a non-empty cap-id path' unless p.is_a?(Array) && !p.empty?
          # the path is joined with ',': an element holding one would alias a different path
          if p.any? { |x| !Revoke.nonempty?(x) || x.include?(PREFIX_SEP) }
            raise TypeError, "revoke: every prefix element must be a non-empty string without ','"
          end

          entry = { 'kind' => 'prefix', 'value' => Revoke.serialize_prefix(p), 'prefix' => p.dup, 'reason' => reason, 'revokedAt' => revoked_at }
        else
          # stricter than the reference, which would store a kind-less entry that no lookup can ever match
          raise TypeError, 'revoke: kind must be a string' unless kind.is_a?(String)
          raise TypeError, "revoke: a #{kind} revocation requires a non-empty value" unless Revoke.nonempty?(input['value'])

          entry = { 'kind' => kind, 'value' => input['value'], 'reason' => reason, 'revokedAt' => revoked_at }
        end
        entry['notBefore'] = input['notBefore'] if input.key?('notBefore')
        @store.add(entry)
        entry
      end

      # Revoke a delegation subtree: a root cap id (String) revokes every chain through it; an ordered cap-id path (Array)
      # revokes every chain whose hops begin with it. opts: reason, revokedAt, notBefore.
      def revoke_subtree(target, opts = nil)
        base = target.is_a?(Array) ? { 'kind' => 'prefix', 'prefix' => target } : { 'kind' => 'cap', 'value' => target }
        revoke(base.merge(opts || {}))
      end

      # Remove a revocation ({kind, value} or {kind: 'prefix', prefix}); true when one was removed.
      def unrevoke(key)
        raise TypeError, 'unrevoke: key must be an object' unless key.is_a?(Hash)

        kind = key['kind']
        if kind == 'prefix'
          p = key['prefix']
          # a non-string element could never have been stored; refusing keeps the revocation (fail closed)
          return false unless p.is_a?(Array) && !p.empty? && p.all? { |x| x.is_a?(String) }

          return @store.remove('prefix', Revoke.serialize_prefix(p))
        end
        return false unless kind.is_a?(String) && key['value'].is_a?(String)

        @store.remove(kind, key['value'])
      end

      def list = @store.all
      def lookup(kind, value) = @store.get(kind, value)
      def prefixes = @store.all.select { |e| e['kind'] == 'prefix' }
      def clear = @store.clear

      # KILL-SWITCH: instantly revoke an agent by its holder key (no notBefore, so it bites at once).
      def kill_agent(holder, reason = nil, revoked_at = nil)
        revoke({ 'kind' => 'holder', 'value' => holder, 'reason' => reason.nil? ? 'kill-switch: agent killed' : reason, 'revokedAt' => revoked_at })
      end

      # KILL-SWITCH: instantly revoke the delegation subtree rooted at `root_cap_id`.
      def kill_subtree(root_cap_id, reason = nil, revoked_at = nil)
        revoke({ 'kind' => 'cap', 'value' => root_cap_id, 'reason' => reason.nil? ? 'kill-switch: subtree killed' : reason, 'revokedAt' => revoked_at })
      end
    end

    # ---- the revocation check ----------------------------------------------------------------------------------------------

    def match_reason(entry)
      base = "#{entry['kind']} #{entry['value']} is revoked"
      entry['reason'].empty? ? base : "#{base}: #{entry['reason']}"
    end

    def starts_with?(ids, prefix) = !prefix.empty? && ids.length >= prefix.length && prefix.each_index.all? { |i| ids[i] == prefix[i] }

    def scan_revoked(chain, registry, now)
      ids = []
      chain.each do |hop|
        # root -> leaf; cap id, then issuer, then holder
        [['cap', hop['id']], ['issuer', hop['issuer']], ['holder', hop['holder']]].each do |kind, key|
          next unless nonempty?(key)

          entry = registry.lookup(kind, key)
          return { 'revoked' => true, 'matched' => entry, 'reason' => match_reason(entry) } if entry && active_at?(entry, now)
        end
        ids << hop['id'] if hop['id'].is_a?(String)
      end
      registry.prefixes.each do |entry|
        p = entry['prefix']
        next unless p.is_a?(Array) && !p.empty? && starts_with?(ids, p) && active_at?(entry, now)

        return { 'revoked' => true, 'matched' => entry, 'reason' => match_reason(entry) }
      end
      { 'revoked' => false }
    end

    # Is any authority in this PCActn's cap_chain revoked at `now` (epoch ms; default the clock)? Never raises and never
    # reports "not revoked" because it could not look: a missing or malformed chain, a hop whose id / issuer / holder is not a
    # non-empty String, a non-finite `now` or a store that raises all yield revoked: true with a reason starting
    # "revocation check failed closed".
    def check_revocation(p, registry, now = nil)
      closed = ->(why) { { 'revoked' => true, 'reason' => "revocation check failed closed: #{why}" } }
      now = now_ms if now.nil?
      return closed.call('clock is not a finite number') unless finite?(now)

      chain = p.is_a?(Hash) ? p['cap_chain'] : nil
      return closed.call('the action carries no capability chain') unless chain.is_a?(Array) && !chain.empty?

      chain.each do |hop|
        %w[id issuer holder].each do |k|
          return closed.call("a chain hop has no #{k}") unless nonempty?(hop.is_a?(Hash) ? hop[k] : nil)
        end
      end
      begin
        scan_revoked(chain, registry, now)
      rescue StandardError # a failing store denies; "Error" is the reference's name for a generic failure
        closed.call('the revocation store failed (Error)')
      end
    end

    # Allow ONLY if the core verified (allow == true) AND nothing in the chain is revoked.
    def verify_with_revocation(p, core, registry, now = nil)
      core_allow = core.is_a?(Hash) && core['allow'] == true
      revocation = check_revocation(p, registry, now)
      allow = core_allow && !revocation['revoked']
      return { 'allow' => allow, 'coreAllow' => core_allow, 'revocation' => revocation } if allow

      reason = if core_allow
                 revocation.fetch('reason', 'revoked')
               else
                 r = core.is_a?(Hash) ? core['reason'] : nil
                 r.nil? ? 'core verification failed' : r
               end
      { 'allow' => allow, 'coreAllow' => core_allow, 'revocation' => revocation, 'reason' => reason }
    end

    # ---- Shared-Signals / CAEP bridge --------------------------------------------------------------------------------------

    def string_field(subject, key)
      v = subject.is_a?(Hash) ? subject[key] : nil
      nonempty?(v) ? v : nil
    end

    def js_round(v)
      return v unless v.finite?

      f = v.floor
      r = v - f >= 0.5 ? f + 1 : f
      r.abs < 2**53 ? r : r.to_f
    end

    # CAEP event_timestamp is integer SECONDS; the registry records epoch ms.
    def revoked_at_from(ts) = finite?(ts) ? js_round(ts.to_f * 1000) : now_ms

    # Bridge a CAEP revocation event {type, payload} into registry entries (returned): grant-revoked revokes the cap id
    # grant_ref; kill-switch kills the `agent` holder (and grant_ref's cap when named); session-revoked kills the subject's
    # holder / agent / id key when it carries one. A missing payload raises TypeError.
    def ingest_caep_event(event, registry)
      raise TypeError, 'ingest_caep_event: event must be an object' unless event.is_a?(Hash)

      payload = event['payload']
      raise TypeError, 'ingest_caep_event: event has no payload' if payload.nil?

      ev = payload.is_a?(Hash) ? payload : {}
      dflt = ->(v, d) { v.nil? ? d : v }
      added = []
      case event['type']
      when CAEP_EVENT_TYPES['grantRevoked']
        if nonempty?(ev['grant_ref'])
          added << registry.revoke({ 'kind' => 'cap', 'value' => ev['grant_ref'], 'reason' => dflt.call(ev['reason'], 'CAEP grant-revoked'),
                                     'revokedAt' => revoked_at_from(ev['event_timestamp']) })
        end
      when CAEP_EVENT_TYPES['killSwitch']
        at = revoked_at_from(ev['event_timestamp'])
        added << registry.kill_agent(ev['agent'], dflt.call(ev['reason'], 'CAEP kill-switch'), at) if nonempty?(ev['agent'])
        if nonempty?(ev['grant_ref'])
          added << registry.revoke({ 'kind' => 'cap', 'value' => ev['grant_ref'], 'reason' => dflt.call(ev['reason'], 'CAEP kill-switch'), 'revokedAt' => at })
        end
      else
        subject = ev['subject']
        raise TypeError, 'ingest_caep_event: subject is null' if ev.key?('subject') && subject.nil?

        holder = string_field(subject, 'holder') || string_field(subject, 'agent') || string_field(subject, 'id')
        unless holder.nil?
          reason = ev['reason_admin'].nil? ? ev['reason_user'] : ev['reason_admin']
          added << registry.kill_agent(holder, dflt.call(reason, 'CAEP session-revoked'), revoked_at_from(ev['event_timestamp']))
        end
      end
      added
    end

    # ---- store conformance -------------------------------------------------------------------------------------------------

    StoreCase = Struct.new(:name, :run)

    def centry(kind, value, **extra)
      e = { 'kind' => kind, 'value' => value, 'reason' => "r-#{kind}-#{value}", 'revokedAt' => 1000 }
      e['prefix'] = value.split(',') if kind == 'prefix'
      e.merge(extra.transform_keys(&:to_s))
    end

    def sorted_entries(xs) = xs.sort_by { |e| e['kind'] + e['value'] }

    # Conformance cases for a revocation store: each `run.call` raises when the store breaks the contract. `make` returns a
    # fresh, empty store; a persistent store passes `reopen.call(previous)` (a new handle on the same location) to run the
    # durability case.
    def revocation_store_cases(make, reopen = nil)
      eq = ->(a, b) { raise "#{a.inspect} != #{b.inspect}" unless a == b }
      cases = [
        StoreCase.new('starts empty', lambda do
          eq.call(make.call.all, [])
          eq.call(make.call.get('cap', 'x'), nil)
        end),
        StoreCase.new('add then get returns the whole entry, including notBefore', lambda do
          s = make.call
          e = centry('cap', 'c1', notBefore: 5000)
          s.add(e)
          eq.call(s.get('cap', 'c1'), e)
        end),
        StoreCase.new('the same value under different kinds is kept apart', lambda do
          s = make.call
          %w[cap holder issuer].each { |k| s.add(centry(k, 'k')) }
          eq.call(s.all.length, 3)
          eq.call(s.remove('holder', 'k'), true)
          eq.call(s.get('cap', 'k')['kind'], 'cap')
          eq.call(s.get('issuer', 'k')['kind'], 'issuer')
          eq.call(s.get('holder', 'k'), nil)
        end),
        StoreCase.new('add at an existing key replaces, it does not duplicate', lambda do
          s = make.call
          s.add(centry('cap', 'c', reason: 'first'))
          s.add(centry('cap', 'c', reason: 'second'))
          eq.call(s.all.length, 1)
          eq.call(s.get('cap', 'c')['reason'], 'second')
        end),
        StoreCase.new('remove reports whether something was removed, and only once', lambda do
          s = make.call
          s.add(centry('cap', 'c'))
          eq.call(s.remove('cap', 'c'), true)
          eq.call(s.remove('cap', 'c'), false)
          eq.call(s.remove('cap', 'never-added'), false)
        end),
        StoreCase.new('prefix paths that differ stay distinct', lambda do
          s = make.call
          ['a,b', 'a', 'b,a'].each { |v| s.add(centry('prefix', v)) }
          eq.call(s.all.length, 3)
          eq.call(s.remove('prefix', 'a'), true)
          eq.call(sorted_entries(s.all).map { |e| e['value'] }, ['a,b', 'b,a'])
        end),
        StoreCase.new('all is a snapshot: changing it does not change the store', lambda do
          s = make.call
          s.add(centry('cap', 'c'))
          snap = s.all
          snap.pop
          snap << centry('cap', 'forged')
          eq.call(s.all.length, 1)
          eq.call(s.get('cap', 'forged'), nil)
        end),
        StoreCase.new('clear drops everything', lambda do
          s = make.call
          s.add(centry('cap', 'c'))
          s.add(centry('prefix', 'a,b'))
          s.clear
          eq.call(s.all, [])
          eq.call(s.get('cap', 'c'), nil)
        end),
        StoreCase.new('interleaved adds and removes from many threads lose nothing', lambda do
          s = make.call
          n = 200
          # each pair removes only its own earlier add, so the expected survivors do not depend on scheduling
          (0...(n / 2)).each_slice(13).map do |ks|
            Thread.new do
              ks.each do |k|
                s.add(centry('cap', "c#{2 * k}"))
                s.add(centry('cap', "c#{(2 * k) + 1}"))
                s.remove('cap', "c#{2 * k}")
              end
            end
          end.each(&:join)
          left = s.all.map { |e| e['value'] }
          eq.call(left.uniq.length, n / 2)
          n.times { |i| eq.call(left.include?("c#{i}"), i.odd?) }
        end)
      ]
      unless reopen.nil?
        cases << StoreCase.new('entries survive reopening the store', lambda do
          s = make.call
          a = centry('cap', 'durable', notBefore: 9000)
          b = centry('prefix', 'r,m')
          s.add(a)
          s.add(b)
          s.add(centry('holder', 'gone'))
          s.remove('holder', 'gone')
          eq.call(sorted_entries(reopen.call(s).all), sorted_entries([a, b]))
        end)
      end
      cases
    end

    # Run every case; returns the failure descriptions (an empty Array means the store conforms).
    def run_revocation_store_conformance(make, reopen = nil)
      revocation_store_cases(make, reopen).filter_map do |c|
        c.run.call
        nil
      rescue StandardError => e
        "#{c.name}: #{e.class}: #{e.message}"
      end
    end
  end
end
