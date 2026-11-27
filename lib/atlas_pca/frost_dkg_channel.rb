# frozen_string_literal: true

require 'monitor'

module AtlasPca
  # The wire codec, the inbox and the party driver of the FROST DKG (the reference's `frost-dkg-channel`, with the framing rule of `frost-dkg-tls`): strict
  # JSON with exact member sets and a size cap checked before the parse; a per-peer inbox that fails a peer sticky on a duplicate, an equivocation, a malformed
  # or a wrong-session message; an in-memory network; and `run_dkg_over_channel`, one party's whole ceremony over a channel (an object answering
  # `self_id`, `peers`, `broadcast(kind, body)`, `send(to, kind, body)`, `collect(kind, from, timeout_ms)` -> {id => body} and `close`). The TLS socket is an
  # injected transport: only its length-prefixed framing and identity rule are here.
  module FrostDkgChannel
    UNDEF = IntentV2::UNDEF
    DKG_WIRE_VERSION = 1
    DKG_MAX_MESSAGE_BYTES = 256 * 1024
    DKG_MAX_PARTICIPANTS = 256
    DKG_MESSAGE_KINDS = %w[round1 share complaints rebuttals echo].freeze

    class DkgChannelError < StandardError
      attr_reader :code, :peer

      def initialize(code, peer, message)
        super("dkg channel (#{code}#{peer.nil? ? '' : ", peer #{peer}"}): #{message}")
        @code = code
        @peer = peer
      end

      # the message without the "dkg channel (...): " prefix
      def bare = message.sub(/\Adkg channel \([^)]*\): /, '')
    end

    module_function

    def err(code, peer, message) = DkgChannelError.new(code, peer, message)
    def b64u(b) = AtlasPca.b64e(b)

    # the length-prefixed text of a message: {v, sid, kind, body} (members in this order, the body's members in the order given)
    def encode_dkg_message(session_id, kind, body)
      bytes = JSON.generate({ 'v' => DKG_WIRE_VERSION, 'sid' => b64u(session_id), 'kind' => kind, 'body' => body }).b
      raise err('oversize', nil, "message of #{bytes.length} bytes exceeds the cap") if bytes.length > DKG_MAX_MESSAGE_BYTES

      bytes
    end

    def as_record(x, keys, what)
      raise err('malformed', nil, "#{what} is not an object") unless x.is_a?(Hash)
      raise err('malformed', nil, "#{what} has unexpected or missing members") if x.length != keys.length || !keys.all? { |k| x.key?(k) }

      x
    end

    def pos_int(x, what)
      raise err('malformed', nil, "#{what} is not a positive integer") unless Attestation.safe_int?(x) && x.positive?

      x
    end

    def b64_field(x, what, len = nil)
      raise err('malformed', nil, "#{what} is not canonical base64url") if !x.is_a?(String) || AtlasPca.b64d(x, len).nil?

      x
    end

    # {kind, body} of a message of this session. Raises DkgChannelError (malformed / oversize / wrong-session).
    def decode_dkg_message(bytes, session_id)
      raise err('malformed', nil, 'message is not bytes') unless bytes.is_a?(String)
      raise err('oversize', nil, "message of #{bytes.length} bytes exceeds the cap") if bytes.bytesize > DKG_MAX_MESSAGE_BYTES

      msg = begin
        txt = bytes.dup.force_encoding('UTF-8')
        raise ArgumentError, 'invalid UTF-8' unless txt.valid_encoding?

        AtlasPca.parse_json(txt, any_top: true)
      rescue StandardError
        raise err('malformed', nil, 'message is not strict JSON')
      end
      o = as_record(msg, %w[v sid kind body], 'envelope')
      raise err('malformed', nil, 'unsupported wire version') unless Attestation.js_eq(o['v'], DKG_WIRE_VERSION)
      raise err('malformed', nil, 'unknown message kind') unless o['kind'].is_a?(String) && DKG_MESSAGE_KINDS.include?(o['kind'])
      raise err('wrong-session', nil, 'message names another session') unless o['sid'] == b64u(session_id)

      { 'kind' => o['kind'], 'body' => o['body'] }
    end

    def decode_dkg_round1_package(x, t)
      o = as_record(x, %w[identifier sessionId coefficientCommitments proofOfKnowledge], 'round-1 package')
      pok = as_record(o['proofOfKnowledge'], %w[R mu], 'proof of knowledge')
      cc = o['coefficientCommitments']
      raise err('malformed', nil, "round-1 package must commit to exactly t=#{t} coefficients") if !cc.is_a?(Array) || cc.length != t

      { 'identifier' => pos_int(o['identifier'], 'identifier'), 'sessionId' => b64_field(o['sessionId'], 'sessionId'),
        'coefficientCommitments' => cc.map { |c| b64_field(c, 'coefficient commitment', 32) },
        'proofOfKnowledge' => { 'R' => b64_field(pok['R'], 'PoP R', 32), 'mu' => b64_field(pok['mu'], 'PoP mu', 32) } }
    end

    def decode_dkg_share_message(x)
      o = as_record(x, %w[from to sessionId share sig], 'share message')
      { 'from' => pos_int(o['from'], 'from'), 'to' => pos_int(o['to'], 'to'), 'sessionId' => b64_field(o['sessionId'], 'sessionId'),
        'share' => AtlasPca.b64d(b64_field(o['share'], 'share', 32)), 'sig' => b64_field(o['sig'], 'share signature', 64) }
    end

    def complaint_of(x)
      o = as_record(x, %w[accused accuser sessionId revealedShare shareSig], 'complaint')
      { 'accused' => pos_int(o['accused'], 'accused'), 'accuser' => pos_int(o['accuser'], 'accuser'), 'sessionId' => b64_field(o['sessionId'], 'sessionId'),
        'revealedShare' => b64_field(o['revealedShare'], 'revealed share', 32), 'shareSig' => b64_field(o['shareSig'], 'share signature', 64) }
    end

    def rebuttal_of(x)
      o = as_record(x, %w[accused accuser sessionId presentedShare shareSig], 'rebuttal')
      { 'accused' => pos_int(o['accused'], 'accused'), 'accuser' => pos_int(o['accuser'], 'accuser'), 'sessionId' => b64_field(o['sessionId'], 'sessionId'),
        'presentedShare' => b64_field(o['presentedShare'], 'presented share', 32), 'shareSig' => b64_field(o['shareSig'], 'share signature', 64) }
    end

    def list_of(x, key)
      o = as_record(x, [key], key)
      l = o[key]
      raise err('malformed', nil, "#{key} is not a bounded list") if !l.is_a?(Array) || l.length > DKG_MAX_PARTICIPANTS

      l.map { |v| yield v }
    end

    def decode_dkg_complaints(x) = list_of(x, 'complaints') { |v| complaint_of(v) }
    def decode_dkg_rebuttals(x) = list_of(x, 'rebuttals') { |v| rebuttal_of(v) }

    def decode_dkg_echo(x)
      o = as_record(x, %w[identifier sessionId transcriptDigest], 'echo')
      { 'identifier' => pos_int(o['identifier'], 'identifier'), 'sessionId' => b64_field(o['sessionId'], 'sessionId'),
        'transcriptDigest' => b64_field(o['transcriptDigest'], 'transcript digest', 32) }
    end

    def now_ms = Process.clock_gettime(Process::CLOCK_MONOTONIC) * 1000

    # Per-peer message store: one message per (kind, peer); a second identical one is `duplicate`, a different one `equivocation`; a failed peer stays
    # failed (sticky, across kinds). `collect` waits (up to the timeout) for a kind from a set of peers.
    class DkgInbox
      attr_reader :session_id, :peers

      def initialize(session_id, peers)
        @session_id = session_id
        @peers = peers
        @seen = {}
        @errors = {}
        @gone = {}
        @closed = false
        @mon = Monitor.new
        @cond = @mon.new_cond
      end

      def fail(peer, err)
        @mon.synchronize do
          @errors[peer] = DkgChannelError.new(err.code, peer, err.bare) unless @errors.key?(peer)
          @cond.broadcast
        end
      end

      def accept(sender, bytes)
        return unless @peers.include?(sender)

        begin
          m = FrostDkgChannel.decode_dkg_message(bytes, @session_id)
          key = "#{m['kind']}\0#{sender}"
          digest = FrostDkgChannel.b64u(bytes)
          @mon.synchronize do
            prev = @seen[key]
            raise FrostDkgChannel.err(prev[:digest] == digest ? 'duplicate' : 'equivocation', sender, "second #{m['kind']} message") if prev

            @seen[key] = { digest: digest, body: m['body'] }
            @cond.broadcast
          end
        rescue StandardError => e
          fail(sender, e.is_a?(DkgChannelError) ? e : FrostDkgChannel.err('malformed', sender, 'undecodable message'))
        end
        nil
      end

      def peer_gone(peer)
        @mon.synchronize do
          @gone[peer] = true
          @cond.broadcast
        end
      end

      def close
        @mon.synchronize do
          @closed = true
          @cond.broadcast
        end
      end

      # {id => body} for every wanted peer (ascending). Raises DkgChannelError: a failed peer's error (lowest id first), `closed`, or `timeout` naming the
      # lowest missing peer.
      def collect(kind, from, timeout_ms)
        want = from.sort
        deadline = FrostDkgChannel.now_ms + timeout_ms
        @mon.synchronize do
          loop do
            want.each { |id| raise @errors[id] if @errors.key?(id) }
            out = {}
            want.each { |id| (m = @seen["#{kind}\0#{id}"]) && out[id] = m[:body] }
            return out if out.length == want.length
            raise FrostDkgChannel.err('closed', nil, 'channel closed before all messages arrived') if @closed

            gone = want.find { |id| !out.key?(id) && @gone.key?(id) }
            raise FrostDkgChannel.err('closed', gone, "link ended before its #{kind} message arrived") unless gone.nil?

            left = deadline - FrostDkgChannel.now_ms
            unless left > 0
              missing = want.reject { |id| out.key?(id) }
              raise FrostDkgChannel.err('timeout', missing[0], "no #{kind} message from #{missing.join(',')}")
            end
            @cond.wait(left / 1000.0)
          end
        end
      end
    end

    # One in-memory channel of a network
    class MemoryChannel
      attr_reader :self_id, :peers

      def initialize(self_id, peers, route, inbox)
        @self_id = self_id
        @peers = peers
        @route = route
        @inbox = inbox
      end

      def broadcast(kind, body)
        @peers.each { |p| @route.call(@self_id, p, kind, body) }
        nil
      end

      def send_to(to, kind, body)
        raise FrostDkgChannel.err('identity', to, 'not a connected peer') unless @peers.include?(to)

        @route.call(@self_id, to, kind, body)
        nil
      end

      def collect(kind, from, timeout_ms) = @inbox.collect(kind, from, timeout_ms)

      def close
        @inbox.close
        nil
      end
    end

    # An in-memory network: {channels => {id => channel}, deliver => ->(from, to, bytes)}. `intercept` (d: {from, to, kind, bytes}) may return other bytes
    # or nil to drop a delivery.
    def create_memory_dkg_network(ids, session_id, intercept = nil)
      sorted = ids.sort
      inboxes = {}
      sorted.each { |id| inboxes[id] = DkgInbox.new(session_id, sorted.reject { |p| p == id }) }
      deliver = ->(from, to, bytes) { inboxes[to]&.accept(from, bytes) }
      channels = {}
      sorted.each do |self_id|
        peers = sorted.reject { |p| p == self_id }
        route = lambda do |from, to, kind, body|
          bytes = FrostDkgChannel.encode_dkg_message(session_id, kind, body)
          out = intercept ? intercept.call({ 'from' => from, 'to' => to, 'kind' => kind, 'bytes' => bytes }) : bytes
          deliver.call(from, to, out) unless out.nil?
        end
        channels[self_id] = MemoryChannel.new(self_id, peers, route, inboxes[self_id])
      end
      { 'channels' => channels, 'deliver' => deliver }
    end

    def bind(peer)
      yield
    rescue DkgChannelError => e
      raise DkgChannelError.new(e.code, peer, e.bare)
    end

    # One party's whole ceremony over a channel (synchronous). `opts`: 't', 'participants', 'sessionId', 'timeoutMs'? (30000), 'coefficients'?.
    # Returns {'keyPackage', 'qualified', 'complaints'}; raises DkgChannelError. Randomness (`random`): t coefficients, then the PoP nonce.
    def run_dkg_over_channel(ch, opts, random: nil)
      d = FrostDkg
      self_id = ch.self_id
      ids = opts['participants'].sort
      if ids.length > DKG_MAX_PARTICIPANTS || ids.each_with_index.any? { |i, k| !Attestation.safe_int?(i) || i <= 0 || (k.positive? && ids[k - 1] == i) }
        raise err('protocol', nil, 'participants must be distinct positive integers within the cap')
      end
      raise err('protocol', nil, 'this participant is not in the participant list') unless ids.include?(self_id)

      t = opts['t']
      raise err('protocol', nil, 'need 1 <= t <= n') if !Attestation.safe_int?(t) || t < 1 || t > ids.length

      others = ids.reject { |i| i == self_id }
      raise err('protocol', nil, 'the channel peers are not exactly the other participants') if ch.peers.length != others.length || !others.each_with_index.all? { |o, k| ch.peers[k] == o }

      sid = opts['sessionId']
      sid_b64 = b64u(sid)
      tmo = opts['timeoutMs'].nil? ? 30_000 : opts['timeoutMs']
      n = ids.length
      r1 = d.dkg_round1(self_id, t, n, sid, opts['coefficients'] ? { 'coefficients' => opts['coefficients'] } : {}, random: random)
      ch.broadcast('round1', r1['package'])
      pkgs = [r1['package']]
      ch.collect('round1', others, tmo).each do |from, body|
        p = bind(from) { decode_dkg_round1_package(body, t) }
        raise err('identity', from, "package claims identifier #{p['identifier']}") if p['identifier'] != from
        raise err('wrong-session', from, 'package names another session') if p['sessionId'] != sid_b64

        pkgs << p
      end
      by_id = pkgs.to_h { |p| [p['identifier'], p] }
      pok = pkgs.select { |p| d.dkg_verify_round1(p['identifier'], p, sid) }
      ok_peers = others.select { |o| pok.any? { |p| p['identifier'] == o } }
      d.dkg_round2(r1['state'], pok).each do |s|
        ch.send_to(s['to'], 'share', { 'from' => s['from'], 'to' => s['to'], 'sessionId' => s['sessionId'], 'share' => b64u(s['share']), 'sig' => s['sig'] })
      end
      inbox = []
      mine = []
      ch.collect('share', ok_peers, tmo).each do |from, body|
        m = bind(from) { decode_dkg_share_message(body) }
        raise err('identity', from, "share claims sender #{m['from']}") if m['from'] != from
        raise err('identity', from, "share is addressed to #{m['to']}") if m['to'] != self_id
        raise err('wrong-session', from, 'share names another session') if m['sessionId'] != sid_b64

        received = { 'from' => from, 'sessionId' => m['sessionId'], 'share' => m['share'], 'sig' => m['sig'] }
        sender = by_id[from]
        if d.dkg_verify_share(received, sender, self_id, sid)
          inbox << received
          next
        end
        c = d.dkg_file_complaint({ 'accused' => from, 'accuser' => self_id, 'receivedShare' => m['share'], 'shareSig' => m['sig'],
                                   'senderCommitments' => sender['coefficientCommitments'], 'sessionId' => sid })
        raise err('protocol', from, 'share failed verification and is not admissible blame') unless d.dkg_verify_complaint(c, pkgs)['justified']

        mine << c
      end
      ch.broadcast('complaints', { 'complaints' => mine })
      complaints = mine.dup
      ch.collect('complaints', others, tmo).each do |from, body|
        pairs = {}
        bind(from) { decode_dkg_complaints(body) }.each do |c|
          raise err('identity', from, "complaint filed as #{c['accuser']}") if c['accuser'] != from
          raise err('wrong-session', from, 'complaint names another session') if c['sessionId'] != sid_b64
          raise err('protocol', from, 'complaint names an invalid accused') if c['accused'] == from || !ids.include?(c['accused'])
          raise err('duplicate', from, 'two complaints against one accused') if pairs.key?(c['accused'].to_s)

          pairs[c['accused'].to_s] = true
          complaints << c
        end
      end
      rebuttals = complaints.select { |c| c['accused'] == self_id }.map { |c| d.dkg_rebut(self_id, c, r1['state']) }
      ch.broadcast('rebuttals', { 'rebuttals' => rebuttals })
      all_rebuttals = rebuttals.dup
      ch.collect('rebuttals', others, tmo).each do |from, body|
        bind(from) { decode_dkg_rebuttals(body) }.each do |r|
          raise err('identity', from, "rebuttal made as #{r['accused']}") if r['accused'] != from
          raise err('wrong-session', from, 'rebuttal names another session') if r['sessionId'] != sid_b64

          all_rebuttals << r
        end
      end
      qualified = d.dkg_qualified_set(ids, complaints, pkgs, all_rebuttals)
      raise err('disqualified', self_id, 'this participant was disqualified by the blame round') unless qualified.include?(self_id)
      raise err('protocol', nil, 'fewer than t participants remain qualified') if qualified.length < t

      echo = d.dkg_echo({ 'identifier' => self_id, 'round1Packages' => pkgs, 'complaints' => complaints, 'qualified' => qualified, 'sessionId' => sid })
      ch.broadcast('echo', echo)
      echoes = [echo]
      ch.collect('echo', qualified.reject { |q| q == self_id }, tmo).each do |from, body|
        e = bind(from) { decode_dkg_echo(body) }
        raise err('identity', from, "echo claims identifier #{e['identifier']}") if e['identifier'] != from

        echoes << e
      end
      agreement = d.dkg_check_echoes(qualified, echoes, sid)
      raise err('equivocation', nil, agreement['reason']) unless agreement['agreed']

      key_package = d.dkg_finalize(self_id, r1['state'], inbox, pkgs, qualified, { 'echoes' => echoes, 'complaints' => complaints })
      { 'keyPackage' => key_package, 'qualified' => qualified, 'complaints' => complaints }
    end

    # a 4-byte big-endian length prefix, then the payload
    def tls_frame_encode(payload) = [payload.bytesize].pack('N') + payload.b

    # The framing loop of the TLS node over chunks of bytes: {accepted: [payload...], error: nil | 'oversize', buffered: bytes left}. A frame longer than
    # the cap is refused before any allocation, and nothing after it is read.
    def tls_frame_decode(chunks)
      buf = ''.b
      accepted = []
      error = nil
      chunks.each do |chunk|
        break if error

        buf += chunk.b
        loop do
          break if buf.bytesize < 4

          len = buf.unpack1('N')
          if len > DKG_MAX_MESSAGE_BYTES
            error = 'oversize'
            break
          end
          break if buf.bytesize < 4 + len

          accepted << buf.byteslice(4, len)
          buf = buf.byteslice(4 + len, buf.bytesize - 4 - len)
        end
      end
      { 'accepted' => accepted, 'error' => error, 'buffered' => buf.bytesize }
    end
  end
end
