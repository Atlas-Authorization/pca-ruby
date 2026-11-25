# frozen_string_literal: true

require_relative '../atlas_pca'
require_relative 'js_compat'

module AtlasPca
  # One-time-use guard for a verified PCActn and its reference in-memory store, the anti-replay primitives the token vault spends
  # an action with. Mirrors the TypeScript reference (@atlasauth/pca, replay): a store contract (consume_once(key, retain_until_ms,
  # now_ms) -> bool, advance(stream_key, counter) -> bool, both raising when they cannot decide), the injective namespaced key, and
  # the guard that composes them with the wire-level freshness rules. Run the guard only AFTER the PCActn verified.
  module ConnectReplay
    MAX_REPLAY_COMPONENT_LEN = 512
    PCACTN_MAX_LIFETIME_MS = 3_600_000
    PCACTN_MAX_SKEW_MS = 60_000
    MAX_AUD_LEN = 256
    MAX_NONCE_LEN = 128

    module_function

    def replay_key(namespace, *parts) = Js.replay_key(namespace, *parts)

    def finite?(x) = x.is_a?(Integer) || (x.is_a?(Float) && x.finite?)

    # a lone surrogate is an invalid UTF-8 string here (WTF-8)
    def lone?(s) = !s.dup.force_encoding(Encoding::UTF_8).valid_encoding?

    def u8len(s) = s.bytesize

    def safe_int?(n) = finite?(n) && n == n.floor && n.abs <= MAX_SAFE

    def safe_nonneg_int?(n)
      return false unless finite?(n)
      return false if n.is_a?(Float) && (n != n.floor || (n.zero? && (1.0 / n).negative?))

      n >= 0 && n <= MAX_SAFE
    end

    # {ok: true} or {ok: false, code, reason} as String-keyed Hashes; never raises: every failure, a store failure included, is a denial.
    def guard_pcactn_replay(store, pcactn, aud, now, clock_skew_ms = nil, require_nonce = true, counters = nil)
      p = pcactn
      deny = ->(code, reason) { { 'ok' => false, 'code' => code, 'reason' => reason } }
      skew = [finite?(clock_skew_ms) && clock_skew_ms >= 0 ? clock_skew_ms : PCACTN_MAX_SKEW_MS, PCACTN_MAX_SKEW_MS].min
      obj_ok = p.is_a?(Hash)
      chain = obj_ok ? p['cap_chain'] : nil
      leaf = chain.is_a?(Array) && !chain.empty? ? chain[-1] : nil
      leaf_ok = leaf.is_a?(Hash) && !leaf.empty? && leaf['holder'].is_a?(String) && p['grant_ref'].is_a?(String)
      comps_ok = leaf_ok && [p['grant_ref'], leaf['holder']].all? { |c| !(c.empty? || lone?(c) || u8len(c) > MAX_REPLAY_COMPONENT_LEN) }
      has_nonce = obj_ok && p.key?('nonce')
      nonce = obj_ok ? p['nonce'] : nil
      nonce_ok = has_nonce && nonce.is_a?(String) && !nonce.empty? && u8len(nonce) <= MAX_NONCE_LEN && !lone?(nonce)
      now_ok = safe_int?(now)
      aud_ok = aud.is_a?(String) && !aud.empty? && u8len(aud) <= MAX_AUD_LEN && !lone?(aud)
      aud_matches = obj_ok && p['aud'].is_a?(String) && p['aud'] == aud
      iat_ok = obj_ok && safe_nonneg_int?(p['iat'])
      exp_ok = obj_ok && safe_nonneg_int?(p['exp'])
      iat = iat_ok ? p['iat'] : 0
      exp = exp_ok ? p['exp'] : 0
      counter_ok = obj_ok && safe_nonneg_int?(p['counter'])
      sk = skew.floor
      window_ok = iat_ok && exp_ok && exp > iat && exp - iat <= PCACTN_MAX_LIFETIME_MS
      code = if !now_ok || !aud_ok || !obj_ok then 'malformed'
             elsif !aud_matches then 'audience'
             elsif !window_ok then 'malformed'
             elsif iat > now + sk then 'not_yet_valid'
             elsif now > exp then 'expired'
             elsif !leaf_ok || !comps_ok || !counter_ok then 'malformed'
             end
      unless code.nil?
        reasons = { 'audience' => 'the PCActn is for another audience', 'not_yet_valid' => 'iat is in the future beyond the clock-skew allowance',
                    'expired' => 'the PCActn has expired' }
        return deny.call(code, reasons[code]) if reasons.key?(code)
        return deny.call(code, 'verifier clock is not an integer epoch-ms') unless now_ok
        return deny.call(code, 'verifier audience is invalid') unless aud_ok
        return deny.call(code, 'not a PCActn') unless obj_ok
        return deny.call(code, 'iat / exp are not a valid bounded window') unless window_ok
        return deny.call(code, 'no leaf holder / grant') unless leaf_ok
        return deny.call(code, 'grant / holder is not a bounded string') unless comps_ok

        return deny.call(code, 'counter is not a non-negative safe integer')
      end
      return deny.call('malformed', 'exp + clock skew exceeds the safe-integer range (retention horizon not representable)') if exp + skew.ceil > MAX_SAFE

      retain_until = exp + skew
      begin
        if has_nonce
          return deny.call('malformed', 'nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes') unless nonce_ok

          consumed = store.consume_once(replay_key('pca-nonce/v1', aud, p['grant_ref'], leaf['holder'], nonce), retain_until, now)
          return deny.call('replay', 'nonce already consumed') unless Js.truthy?(consumed)
        elsif require_nonce != false
          return deny.call('malformed', 'a nonce is required')
        end
        unless counters.nil?
          advanced = counters.advance(replay_key('pca-counter/v1', aud, p['grant_ref'], leaf['holder']), p['counter'])
          return deny.call('replay', 'counter is not greater than the last accepted') unless Js.truthy?(advanced)
        end
      rescue StandardError => e # a store that cannot decide fails closed
        return deny.call('store_unavailable', "replay store failed closed: #{e.message.empty? ? 'error' : e.message}")
      end
      { 'ok' => true }
    end

    # Reference store: correct only for a single verifier process whose lifetime covers the action lifetime.
    class InMemoryReplayStore
      def initialize(max_entries = 100_000)
        @seen = {}
        @streams = {}
        @max = max_entries
      end

      def size = @seen.size

      def prune(now_ms)
        return 0 unless ConnectReplay.finite?(now_ms) # an infinite clock must not expire live replay keys

        dead = @seen.select { |_k, until_ms| until_ms < now_ms }.keys
        dead.each { |k| @seen.delete(k) }
        dead.length
      end

      def consume_once(key, retain_until_ms, now_ms)
        unless key.is_a?(String) && !key.empty? && ConnectReplay.finite?(retain_until_ms) && ConnectReplay.finite?(now_ms) && retain_until_ms >= now_ms
          raise ArgumentError, 'consumeOnce: invalid key or retention horizon'
        end

        until_ms = @seen[key]
        return false if !until_ms.nil? && until_ms >= now_ms

        if until_ms.nil? && @seen.size >= @max
          prune(now_ms)
          raise 'replay store full of live entries' if @seen.size >= @max
        end
        @seen[key] = [retain_until_ms, until_ms.nil? ? 0 : until_ms].max
        true
      end

      def advance(stream_key, counter)
        raise ArgumentError, 'advance: invalid stream or counter' unless stream_key.is_a?(String) && !stream_key.empty? && ConnectReplay.safe_nonneg_int?(counter)

        last = @streams[stream_key]
        return false if !last.nil? && !(counter > last)

        @streams[stream_key] = counter
        true
      end
    end
  end
end
