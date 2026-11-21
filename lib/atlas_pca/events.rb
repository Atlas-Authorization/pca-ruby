# frozen_string_literal: true

require 'openssl'
require_relative 'js_compat'

# Typed step-up lifecycle events and Stripe-style signed webhooks: content-addressed events (the id is the digest of every
# other field), `t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<payload>">` signatures with a tolerance window and secret rotation, and
# verify_delivery (signature + freshness + a well-formed event + a first sight of its id). A transport contract, not a
# decision. Mirrors @atlasauth/pca-events. A secret is a String: a binary (ASCII-8BIT) String is raw key bytes, any other
# String is UTF-8 text.
module AtlasPca
  module Events
    EVENT_TYPES = %w[step_up.created step_up.approved step_up.denied step_up.expired].freeze
    MIN_SECRET_BYTES = 16
    MAX_HEADER_CHARS = 2048
    EVENT_DOMAIN = 'atlas-pca/stepup-event/v1'

    module_function

    def event_id(e)
      f = { 'd' => EVENT_DOMAIN, 'type' => e['type'], 'at' => e['at'], 'grant_ref' => e['grant_ref'],
            'action' => { 'verb' => e['action']['verb'], 'resource' => e['action']['resource'] }, 'tier' => e['tier'] }
      f['actor'] = e['actor'] if e.key?('actor')
      # an absent member is `undefined` in the reference, which the canonical form refuses
      raise ArgumentError, 'canonicalize: unsupported type undefined' unless %w[type at grant_ref tier].all? { |k| e.key?(k) } &&
                                                                              %w[verb resource].all? { |k| e['action'].key?(k) }

      AtlasPca.hash_canonical(f)
    rescue AtlasPca::Malformed => e
      raise ArgumentError, e.message.start_with?('canonicalize:') ? e.message : "canonicalize: #{e.message}"
    end

    def pick(h, k, out, key = k)
      out[key] = h[k] if h.is_a?(Hash) && h.key?(k)
    end

    def wf?(x) = x.is_a?(String) && x.valid_encoding?

    # The fields every event carries, checked the same way at build and serialize time (fail closed on anything else).
    def check_event_fields(who, e, with_id)
      bad = ->(m) { raise TypeError, "#{who}: #{m}" }
      bad.call('not an object') unless e.is_a?(Hash)
      tier = e['tier']
      bad.call('unknown event type or tier') unless EVENT_TYPES.include?(e['type']) && Js.num?(tier) && [2, 3].include?(tier)
      # an absent `at` defaults to now at build time; a serialized event must carry one
      bad.call('at must be a finite number') unless (e['at'].nil? && !with_id) || (Js.num?(e['at']) && e['at'].to_f.finite?)
      bad.call('grant_ref must be a well-formed string') unless wf?(e['grant_ref'])
      a = e['action']
      bad.call('action must carry well-formed verb and resource strings') unless a.is_a?(Hash) && wf?(a['verb']) && wf?(a['resource'])
      bad.call('actor must be a well-formed string') if e.key?('actor') && !wf?(e['actor'])
      bad.call('id must be a well-formed string') if with_id && !wf?(e['id'])
    end

    # Build a step-up event: `at` defaults to now (ms); the id is derived from every other field. A non-object `data` reads as
    # empty, so the first failing check (type/tier, at, grant_ref, action, actor) is the reference's, never a property-read error.
    def build_step_up_event(type, data)
      d = data.is_a?(Hash) ? data : {}
      action = d['action']
      probe = { 'type' => type, 'tier' => d['tier'], 'at' => d['at'], 'grant_ref' => d['grant_ref'], 'action' => action }
      probe['actor'] = d['actor'] if d.key?('actor')
      check_event_fields('buildStepUpEvent', probe, false)

      base = { 'type' => type, 'at' => d['at'].nil? ? (Time.now.to_f * 1000).floor : d['at'] }
      pick(d, 'grant_ref', base)
      act = {}
      pick(action, 'verb', act)
      pick(action, 'resource', act)
      base['action'] = act
      pick(d, 'tier', base)
      base['actor'] = d['actor'] if d.key?('actor')
      base.merge('id' => event_id(base))
    end

    # JSON wire form (JSON.stringify).
    def serialize_event(e)
      check_event_fields('serializeEvent', e, true)
      Js.json(e)
    end

    # Parse + validate a JSON step-up event; raises on anything that is not a well-formed event or whose id is not its digest.
    def parse_event(s)
      raise TypeError, 'parseEvent: not a string' unless s.is_a?(String)

      o = Js.parse(s)
      raise ArgumentError, 'parseEvent: not an object' unless o.is_a?(Hash) || o.is_a?(Array)

      o = {} if o.is_a?(Array)
      raise ArgumentError, 'parseEvent: bad id' unless o['id'].is_a?(String) && !o['id'].empty?
      raise ArgumentError, 'parseEvent: bad type' unless EVENT_TYPES.include?(o['type'])
      raise ArgumentError, 'parseEvent: bad at' unless Js.num?(o['at']) && o['at'].to_f.finite?
      raise ArgumentError, 'parseEvent: bad grant_ref' unless o['grant_ref'].is_a?(String)

      a = o['action']
      raise ArgumentError, 'parseEvent: bad action' unless a.is_a?(Hash) || a.is_a?(Array)

      a = {} if a.is_a?(Array)
      raise ArgumentError, 'parseEvent: bad action fields' unless a['verb'].is_a?(String) && a['resource'].is_a?(String)

      tier = [2, 3].find { |t| Js.num?(o['tier']) && o['tier'] == t }
      raise ArgumentError, 'parseEvent: bad tier' if tier.nil?
      raise ArgumentError, 'parseEvent: bad actor' if o.key?('actor') && !o['actor'].is_a?(String)

      ev = { 'id' => o['id'], 'type' => o['type'], 'at' => o['at'], 'grant_ref' => o['grant_ref'],
             'action' => { 'verb' => a['verb'], 'resource' => a['resource'] }, 'tier' => tier }
      ev['actor'] = o['actor'] if o.key?('actor')
      raise ArgumentError, 'parseEvent: id does not match the event content' unless event_id(ev.except('id')) == ev['id']

      ev
    end

    def secret_bytes(secret)
      return nil unless secret.is_a?(String)

      b = Js.utf8(secret)
      b.bytesize >= MIN_SECRET_BYTES ? b : nil
    end

    # {t, v1: [...]} of `t=<digits>,v1=<hex>[,v1=...]`, or nil. Several v1 are allowed (rotation); two different t are not.
    def parse_signature_header(h)
      return nil unless h.is_a?(String) && Js.len16(h) <= MAX_HEADER_CHARS

      t = nil
      v1 = []
      h.split(',', -1).each do |part|
        eq = part.index('=')
        next if eq.nil?

        key = Js.trim(part[0, eq])
        val = Js.trim(part[(eq + 1)..])
        if key == 't'
          return nil unless val.match?(/\A[0-9]{1,15}\z/)

          n = val.to_i
          return nil if !t.nil? && t != n

          t = n
        elsif key == 'v1'
          v1 << val
        end
      end
      t.nil? || v1.empty? ? nil : { 't' => t, 'v1' => v1 }
    end

    def mac(key, t, payload) = OpenSSL::HMAC.digest('SHA256', key, "#{Js.string(t)}.".b + Js.utf8(payload.to_s))

    # `t=<unixSeconds>,v1=<hex>`. Options: timestamp (default now). Raises on a short secret or a bad timestamp; the error
    # never contains the secret.
    def sign_webhook(secret, payload, opts = nil)
      raise TypeError, 'signWebhook: the payload must be a string' unless payload.is_a?(String)

      key = secret_bytes(secret)
      raise RangeError, "signWebhook: the secret must be at least #{MIN_SECRET_BYTES} bytes" if key.nil?

      t = Js.get(opts || {}, 'timestamp')
      t = Time.now.to_i if t.nil?
      unless Js.safe_integer?(t) && t >= 0
        raise RangeError, 'signWebhook: timestamp must be a non-negative integer (unix seconds)'
      end

      "t=#{Js.string(t)},v1=#{mac(key, t, payload).unpack1('H*')}"
    end

    # True iff the header carries a v1 HMAC of this payload within the tolerance (default 300 s). Never raises. Options:
    # tolerance_sec, now (unix seconds).
    def verify_webhook(secret, payload, header, opts = nil)
      key = secret_bytes(secret)
      return false if key.nil?

      parsed = parse_signature_header(header)
      return false if parsed.nil?

      o = opts.is_a?(Hash) ? opts : {}

      tol = o['tolerance_sec'].nil? ? 300 : o['tolerance_sec']
      now = o['now'].nil? ? Time.now.to_i : o['now']
      return false unless Js.num?(tol) && tol.to_f.finite? && tol >= 0 && Js.num?(now) && now.to_f.finite?
      return false if (now - parsed['t']).abs > tol

      expected = mac(key, parsed['t'], payload)
      match = false
      parsed['v1'].each do |v|
        next unless v.match?(/\A(?:[0-9a-fA-F]{2})*\z/)

        match = true if OpenSSL.fixed_length_secure_compare(expected, [v].pack('H*')) rescue false
      end
      match
    rescue StandardError
      false
    end

    # Accept one delivery: signature + freshness, a well-formed event, and a first sight of its id (replay: an object with
    # consume_once(key, retain_until_ms, now_ms) -> true on first sight). {'ok' => true, 'event'} or {'ok' => false, 'reason'}.
    # Never raises; no reason carries the secret or the payload.
    def verify_delivery(secret, payload, header, opts)
      unless opts.is_a?(Hash) && opts['replay'].respond_to?(:consume_once)
        return { 'ok' => false, 'reason' => 'a replay store is required' }
      end
      return { 'ok' => false, 'reason' => 'bad signature' } unless verify_webhook(secret, payload, header, opts)

      begin
        event = parse_event(payload)
      rescue StandardError => e
        return { 'ok' => false, 'reason' => e.message }
      end
      sig = parse_signature_header(header)
      now = opts['now'].nil? ? Time.now.to_i : opts['now']
      tol = opts['tolerance_sec'].nil? ? 300 : opts['tolerance_sec']
      begin
        first = opts['replay'].consume_once(Js.replay_key('pca-stepup-event/v1', event['id']), ((sig['t'] + tol) * 1000) + 1, now * 1000)
        return { 'ok' => false, 'reason' => 'replayed delivery' } unless first == true
      rescue StandardError
        return { 'ok' => false, 'reason' => 'replay store unavailable' }
      end
      { 'ok' => true, 'event' => event }
    rescue StandardError
      { 'ok' => false, 'reason' => 'bad signature' }
    end

    # The headers of an outbound webhook POST.
    def webhook_headers(secret, payload, opts = nil)
      { 'PCA-Signature' => sign_webhook(secret, payload, opts), 'content-type' => 'application/json' }
    end
  end
end
