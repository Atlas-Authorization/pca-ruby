# frozen_string_literal: true

require 'openssl'
require 'socket'
require 'timeout'
require_relative '../mpc_net'
require_relative 'certs'
require_relative 'clock'

module AtlasPca
  module Mpc
    module Net
      # Authenticated, confidential, fail-closed point-to-point mesh over TLS 1.3 (research prototype).
      #
      #  - MUTUAL TLS with PINNED self-signed certificates. A peer is identified by the SHA-256 of its certificate, never by anything
      #    it claims; the claimed id in the hello frame must agree with the pin. The TLS chain check is replaced by the pin (the
      #    handshake still proves possession of the certificate's key).
      #  - Strict framing and per-link sequence numbers. A malformed frame, a duplicate or replayed frame, a skipped frame, a frame
      #    for the wrong round or session, or an oversize length prefix aborts the whole run with an ATTRIBUTABLE NetAbort.
      #  - Timeouts on every receive (no hangs); a silent peer is blamed after recv_timeout_ms.
      #  - ABORT PROPAGATION: the first failure poisons the mesh, wakes every pending receive, best-effort sends an abort frame to
      #    every peer, then closes the sockets. Once failed, nothing further is sent as protocol data (fail closed).
      NodeAddr = Struct.new(:id, :host, :port, :cert_pem, keyword_init: true)
      # what a (test-only) tamper hook sees for each outgoing frame: the recipient, the frame, and its honest encoding
      TamperEvent = Struct.new(:to, :frame, :raw)
      LinkStats = Struct.new(:peer, :app_bytes_out, :app_bytes_in, :frames_out, :frames_in, :tls_bytes_written, :tls_bytes_read)

      # most non-fatal observations kept in Mesh#events; further ones are only counted
      MAX_MESH_EVENTS = 64

      class Mesh
        W = NetWire
        InboxItem = Struct.new(:f, :size, :abort)

        # the per-peer state of one link
        class Link
          attr_accessor :socket, :inbox_bytes, :paused, :send_seq, :recv_seq, :closed, :hello_seen, :bytes_in, :bytes_out, :frames_in,
                        :frames_out
          attr_reader :id, :splitter, :inbox, :wmu

          def initialize(id)
            @id = id
            @socket = nil
            @splitter = W::FrameSplitter.new
            @inbox = []
            @inbox_bytes = 0
            @paused = false
            @send_seq = 0
            @recv_seq = 0
            @closed = false
            @hello_seen = false
            @bytes_in = @bytes_out = @frames_in = @frames_out = 0
            @wmu = Mutex.new
          end
        end

        attr_reader :self_id, :events

        def initialize(self_id:, nodes:, key_pem:, cert_pem:, session_id:, link_to: nil, listen_host: nil, connect_timeout_ms: 30_000,
                       recv_timeout_ms: 20_000, tamper: nil, unsafe_test_hooks: false, max_inbox_frames: 1024,
                       max_inbox_bytes: 32 * 1024 * 1024, clock: nil)
          raise ArgumentError, 'mesh: the tamper test hook requires unsafe_test_hooks: true (test-only)' if tamper && unsafe_test_hooks != true

          @self_id = self_id
          @nodes = nodes
          @key_pem = key_pem
          @cert_pem = cert_pem
          @session_id = session_id
          @listen_host = listen_host
          @connect_timeout_ms = connect_timeout_ms
          @recv_timeout_ms = recv_timeout_ms
          [@recv_timeout_ms, @connect_timeout_ms].each do |ms|
            raise RangeError, 'mesh: timeouts must be finite numbers >= 0' unless ms.is_a?(Numeric) && ms.to_f.finite? && ms >= 0
          end
          @tamper = tamper
          @max_inbox_frames = max_inbox_frames
          @max_inbox_bytes = max_inbox_bytes
          @clock = clock || WALL_CLOCK
          @mu = Mutex.new
          @cv = ConditionVariable.new
          @evmu = Mutex.new
          @events = []
          @events_dropped = 0
          @failure = nil
          @finished = false
          @defer_aborts = false
          @server = nil
          @pinned = {}
          @links = {}
          want = link_to || nodes.map(&:id).reject { |i| i == self_id }
          nodes.each { |n| @pinned[Certs.fingerprint_of(n.cert_pem)] = n.id if n.id != self_id }
          want.each do |id|
            raise ArgumentError, "mesh: unknown link target #{id}" unless nodes.any? { |n| n.id == id }

            @links[id] = Link.new(id)
          end
          @sign_key = OpenSSL::PKey.read(key_pem)
        end

        attr_reader :session_id

        def events_dropped = @evmu.synchronize { @events_dropped }
        def peers = @links.keys.sort
        def failed = @mu.synchronize { @failure }

        # ------------------------------------------------------------------ connect

        # listens, dials every lower-numbered link target, and waits until all links are authenticated
        def connect
          me = @nodes.find { |n| n.id == @self_id } or raise ArgumentError, 'mesh: self not in nodes'
          @server = TCPServer.new(@listen_host || '0.0.0.0', me.port)
          Thread.new { accept_loop }.tap { |t| t.report_on_exception = false }
          deadline = @clock.now + @connect_timeout_ms
          peers.each do |id|
            next unless id < @self_id

            Thread.new { dial(id, deadline) }.tap { |t| t.report_on_exception = false }
          end
          loop do
            err = nil
            @mu.synchronize do
              raise @failure if @failure

              missing = peers.reject { |i| @links[i].hello_seen }
              return nil if missing.empty?

              if !(@clock.now <= deadline) # a NaN clock or deadline is past, never "not yet"
                err = NetWire::NetAbort.new('timeout', missing[0], @self_id, "connect: no authenticated link from #{missing.join(',')}")
              else
                @cv.wait(@mu, 0.02)
              end
            end
            if err
              self.fail(err)
              raise err
            end
          end
        end

        def server_ctx
          ctx = base_ctx
          ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
          ctx
        end

        def client_ctx
          ctx = base_ctx
          ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
          ctx
        end

        # TLS 1.3 only, our identity, and NO chain trust: the callback accepts any chain because trust is the SHA-256 pin, checked
        # on every connection right after the handshake (the handshake itself still proves the peer holds its certificate's key)
        def base_ctx
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.min_version = OpenSSL::SSL::TLS1_3_VERSION
          ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION
          ctx.key = OpenSSL::PKey.read(@key_pem)
          ctx.cert = OpenSSL::X509::Certificate.new(@cert_pem)
          ctx.verify_callback = ->(_ok, _store) { true }
          ctx.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_OFF
          ctx.options |= OpenSSL::SSL::OP_NO_TICKET
          ctx
        end
        private :server_ctx, :client_ctx, :base_ctx

        # the node id a TLS peer is pinned to, or nil (no certificate, not pinned, or outside its validity period)
        def pinned_id(ssl)
          cert = ssl.peer_cert
          return nil if cert.nil?

          now = Time.now
          return nil if now < cert.not_before || now > cert.not_after

          @pinned[Certs.fingerprint_of(cert)]
        end
        private :pinned_id

        def accept_loop
          ctx = server_ctx
          loop do
            tcp = @server.accept
            Thread.new { incoming(tcp, ctx) }.tap { |t| t.report_on_exception = false }
          end
        rescue IOError, SystemCallError
          nil
        end
        private :accept_loop

        def incoming(tcp, ctx)
          ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
          ssl.sync_close = true
          begin
            Timeout.timeout(15) { ssl.accept }
          rescue StandardError => e
            note("tlsClientError: #{e.message[0, 120]}")
            tcp.close rescue nil # rubocop:disable Style/RescueModifier
            return
          end
          id = pinned_id(ssl)
          if id.nil? || !@links.key?(id) || id < @self_id
            note("rejected incoming connection (pin=#{ssl.peer_cert ? Certs.fingerprint_of(ssl.peer_cert) : 'none'})")
            ssl.close rescue nil # rubocop:disable Style/RescueModifier
            return
          end
          note("duplicate connection from node #{id}") unless attach(id, ssl)
        end
        private :incoming

        def dial(id, deadline)
          node = @nodes.find { |n| n.id == id }
          until failed || @clock.now >= deadline
            return if dial_once(node, id)

            sleep 0.15
          end
        end
        private :dial

        # true when the attempt is over (linked, or failed for good); false to retry
        def dial_once(node, id)
          tcp = nil
          ssl = nil
          begin
            tcp = Socket.tcp(node.host, node.port, connect_timeout: 5)
            ssl = OpenSSL::SSL::SSLSocket.new(tcp, client_ctx)
            ssl.sync_close = true
            Timeout.timeout(15) { ssl.connect }
          rescue StandardError
            (ssl || tcp)&.close rescue nil # rubocop:disable Style/RescueModifier
            return false
          end
          if pinned_id(ssl) != id
            ssl.close rescue nil # rubocop:disable Style/RescueModifier
            self.fail(NetWire::NetAbort.new('identity', id, @self_id, "dial: peer certificate is not the pinned identity of node #{id}"))
            return true
          end
          attach(id, ssl)
          true
        end
        private :dial_once

        # true when ssl became the link's socket; false (and closed) when the link already had one
        def attach(id, ssl)
          l = @links[id]
          ok = @mu.synchronize do
            if l.socket
              false
            else
              l.socket = ssl
              true
            end
          end
          unless ok
            ssl.close rescue nil # rubocop:disable Style/RescueModifier
            return false
          end
          begin
            ssl.to_io.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
          rescue StandardError
            nil
          end
          Thread.new { read_loop(l, ssl) }.tap { |t| t.report_on_exception = false }
          # hello: first frame on every link (seq 0); carries our id so the peer can cross-check the pin
          send_frame(l, 'hello', 'hello', { 'id' => @self_id })
          true
        end
        private :attach

        # ------------------------------------------------------------------ receive path

        def read_loop(l, ssl)
          loop do
            @mu.synchronize { @cv.wait(@mu, 0.5) while l.paused && !l.closed && !@failure }
            on_data(l, ssl.readpartial(65_536))
          end
        rescue EOFError
          on_closed(l, 'peer ended')
        rescue IOError, SystemCallError, OpenSSL::SSL::SSLError => e
          on_closed(l, "socket error: #{e.message[0, 80]}")
        ensure
          on_closed(l, 'socket closed')
        end
        private :read_loop

        def on_data(l, chunk)
          err = nil
          skip = nil
          @mu.synchronize do
            return nil if @failure

            err, skip = process_chunk(l, chunk)
            @cv.broadcast if err.nil?
          end
          self.fail(err, skip) if err
        end
        private :on_data

        # under @mu: returns [NetAbort, skip_peer] when the chunk poisons the mesh, else nil
        def process_chunk(l, chunk)
          l.bytes_in += chunk.bytesize
          begin
            bodies = l.splitter.push(chunk)
          rescue StandardError
            return [W::NetAbort.new('oversize', l.id, @self_id, 'length prefix above MAX_FRAME_BYTES'), nil]
          end
          bodies.each do |b|
            f = W.parse_frame(b)
            if f.nil?
              pv = W.version_mismatch(b)
              unless pv.nil?
                return [W::NetAbort.new('version', l.id, @self_id,
                                        "peer #{l.id} speaks wire version #{pv}, this node speaks #{W::WIRE_VERSION}; upgrade both peers"), nil]
              end
              return [W::NetAbort.new('malformed', l.id, @self_id, 'undecodable or ill-shaped frame'), nil]
            end
            return [W::NetAbort.new('wrong-session', l.id, @self_id, 'frame from another session'), nil] if f['sid'] != @session_id

            if f['ty'] == 'abort'
              claim = abort_claim(l, f)
              if @defer_aborts
                # order-preserving: the claim takes effect when it is READ, after every frame this peer sent before it
                l.inbox << InboxItem.new(f, b.bytesize, claim)
                next
              end
              return [claim, l.id]
            end
            if f['seq'] != l.recv_seq
              kind = f['seq'] < l.recv_seq ? 'duplicate' : 'out-of-order'
              return [W::NetAbort.new(kind, l.id, @self_id, "expected seq #{l.recv_seq}, got #{f['seq']} (round #{f['rd']})"), nil]
            end
            l.recv_seq += 1
            l.frames_in += 1
            if f['ty'] == 'hello'
              d = f['d']
              id = d.is_a?(Hash) ? d['id'] : nil
              if l.hello_seen || !id.is_a?(Integer) || id != l.id
                return [W::NetAbort.new('identity', l.id, @self_id, "hello claims id #{sanitize(id.inspect, 40)} on the link pinned to #{l.id}"), nil]
              end

              l.hello_seen = true
            else
              return [W::NetAbort.new('malformed', l.id, @self_id, 'data before hello'), nil] unless l.hello_seen

              l.inbox << InboxItem.new(f, b.bytesize, nil)
              l.inbox_bytes += b.bytesize
              if l.inbox.length > @max_inbox_frames || l.inbox_bytes > @max_inbox_bytes
                return [W::NetAbort.new('flood', l.id, @self_id, "peer #{l.id} queued more than the inbox cap allows"), nil]
              end

              l.paused = true if !l.paused && (l.inbox.length > @max_inbox_frames / 2 || l.inbox_bytes > @max_inbox_bytes / 2)
            end
          end
          nil
        end
        private :process_chunk

        # An abort frame is only a CLAIM by the peer that sent it: we blame that peer (the authenticated sender), never the party it
        # names, otherwise any peer could frame an honest one.
        def abort_claim(l, f)
          d = f['d'].is_a?(Hash) ? f['d'] : {}
          relayed = d['relayed'] == true # a relayed abort is second-hand: it names no one
          claimed_kind = d['kind'].is_a?(String) && W::ABORT_KINDS.include?(d['kind']) ? d['kind'] : nil
          max_id = @nodes.map(&:id).max
          b = d['blamed']
          claimed_blame = b.is_a?(Integer) && b >= 0 && b <= max_id ? b : nil
          detail = d['detail'].is_a?(String) ? sanitize(d['detail'], 120) : ''
          W::NetAbort.new(
            'peer-abort', relayed ? nil : l.id, @self_id,
            "peer #{l.id} #{relayed ? 'relayed' : 'reported'} an abort (#{claimed_kind || 'unspecified'}, accuses #{claimed_blame.nil? ? 'no one' : claimed_blame}, unverified) #{detail}",
            claimed_kind, claimed_blame,
            relayed ? 'relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence' : nil
          )
        end
        private :abort_claim

        def on_closed(l, why)
          @mu.synchronize do
            return nil if l.closed

            l.closed = true
            note("link #{l.id} closed before hello: #{why}") if !@finished && !@failure && !l.hello_seen
            @cv.broadcast
          end
        end
        private :on_closed

        # ------------------------------------------------------------------ send path

        def send_frame(l, ty, rd, d)
          l.wmu.synchronize do
            frame = W::Frame.new(W::WIRE_VERSION, ty, @session_id, l.send_seq, rd, d)
            l.send_seq += 1
            raw = W.encode_frame(frame)
            outs = @tamper && ty != 'hello' ? @tamper.call(TamperEvent.new(l.id, frame, raw)) : [raw]
            outs.each do |b|
              next unless l.socket

              begin
                l.socket.write(b)
                l.bytes_out += b.bytesize
              rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
                nil # a dead link shows up as a disconnect on the next receive
              end
            end
            l.frames_out += 1
          end
        end
        private :send_frame

        # sends a protocol message to one peer; raises the mesh failure if already aborted (fail closed)
        def send_to(to, round, payload)
          f = failed
          raise f if f

          l = @links[to] or raise ArgumentError, "mesh: no link to #{to}"
          send_frame(l, 'msg', round, payload)
        end

        def broadcast(round, payload, to = peers) = to.each { |p| send_to(p, round, payload) }

        # ECDSA-P256/SHA-256 signature over data with this node's TLS identity key (transferable: verifiable against the pinned cert)
        def sign(data) = @sign_key.sign(OpenSSL::Digest.new('SHA256'), data.b)

        # verifies sig over data against the PINNED certificate of node peer; false on any failure (never raises)
        def verify(peer, data, sig)
          n = @nodes.find { |x| x.id == peer }
          return false if n.nil? || peer == @self_id

          OpenSSL::X509::Certificate.new(n.cert_pem).public_key.verify(OpenSSL::Digest.new('SHA256'), sig.b, data.b)
        rescue StandardError
          false
        end

        # receives the next message from from, which must belong to round. Times out; never hangs.
        def recv(from, round, timeout_ms = nil)
          timeout_ms ||= @recv_timeout_ms
          raise RangeError, 'mesh: recv timeout must be a finite number >= 0' unless timeout_ms.is_a?(Numeric) && timeout_ms.to_f.finite? && timeout_ms >= 0

          l = @links[from] or raise ArgumentError, "mesh: no link to #{from}"
          deadline = @clock.now + timeout_ms
          loop do
            err = nil
            @mu.synchronize do
              raise @failure if @failure

              it = l.inbox.shift
              if it&.abort
                err = it.abort
              elsif it
                l.inbox_bytes -= it.size
                if l.paused && l.inbox.length <= @max_inbox_frames / 2 && l.inbox_bytes <= @max_inbox_bytes / 2
                  l.paused = false
                  @cv.broadcast
                end
                return it.f['d'] if it.f['rd'] == round

                err = W::NetAbort.new('wrong-round', from, @self_id, "expected round '#{round}', got '#{it.f['rd']}'")
              elsif l.closed
                err = W::NetAbort.new('disconnect', from, @self_id, "link to #{from} closed while awaiting '#{round}'")
              else
                left = deadline - @clock.now
                if !(left > 0) # a NaN clock or deadline is past, never "not yet"
                  err = W::NetAbort.new(
                    'timeout', from, @self_id,
                    "no '#{round}' message from #{from} within #{timeout_ms}ms (deadline #{timeout_ms}ms; a silent peer is blamed on this local observation only)",
                    nil, nil, nil, nil, timeout_ms
                  )
                else
                  timer = @clock.set_timer(left) { @mu.synchronize { @cv.broadcast } }
                  @cv.wait(@mu, [left / 1000.0, 1.0].min)
                  @clock.clear_timer(timer)
                end
              end
            end
            next if err.nil?

            self.fail(err, err.kind == 'peer-abort' ? from : nil)
            raise err
          end
        end

        # While on, a peer's abort frame does not poison the mesh on arrival: it is queued behind that peer's earlier frames and only
        # takes effect when a receive from that peer reaches it (the blame round: a fast party's abort, in particular a cheater's own
        # claim, cannot pre-empt an honest party still collecting the blame data it needs). An abort already queued still takes
        # effect at the next receive from that peer.
        def set_defer_aborts(on) = @mu.synchronize { @defer_aborts = on }

        # receives round from every peer in from concurrently; a failure on any link raises (the mesh failure when one is recorded)
        def collect(round, from = peers, timeout_ms = nil)
          return { from[0] => recv(from[0], round, timeout_ms) } if from.length == 1

          results = {}
          errors = []
          lock = Mutex.new
          from.map do |p|
            Thread.new do
              v = recv(p, round, timeout_ms)
              lock.synchronize { results[p] = v }
            rescue StandardError => e
              lock.synchronize { errors << e }
            end.tap { |t| t.report_on_exception = false }
          end.each(&:join)
          raise(failed || errors.first) unless errors.empty?

          from.to_h { |p| [p, results[p]] }
        end

        # ------------------------------------------------------------------ failure / shutdown

        # Poison the mesh: record the first failure, tell EVERY peer except skip_peer (the one that just told us: forwarding the
        # original accusation, so an innocent bystander is never blamed for merely closing), close all.
        def fail(err, skip_peer = nil)
          targets = nil
          @mu.synchronize do
            return nil if @failure

            @failure = err
            targets = @links.values.select { |l| l.id != skip_peer && l.socket && !l.closed }
          end
          targets.each do |l|
            # a forwarded peer-abort stays a claim: we pass on what was claimed, receivers re-attribute to us
            relay = err.kind == 'peer-abort'
            d = { 'kind' => relay ? (err.claimed_kind || 'peer-abort') : err.kind, 'blamed' => relay ? err.claimed_blame : err.blamed,
                  'detail' => sanitize(err.message, 200) }
            d['relayed'] = true if relay
            send_abort(l, d)
          end
          @mu.synchronize { @cv.broadcast }
          Thread.new { sleep 0.05; close_all }.tap { |t| t.report_on_exception = false }
          nil
        end

        def send_abort(l, d)
          l.wmu.synchronize do
            frame = W::Frame.new(W::WIRE_VERSION, 'abort', @session_id, l.send_seq, 'abort', d)
            l.send_seq += 1
            l.socket.write(W.encode_frame(frame))
          end
        rescue StandardError
          nil # best effort
        end
        private :send_abort

        # normal completion: closes after a short flush; peers still reading see EOF only after our data
        def finish
          @finished = true
          sleep 0.1
          close_all
        end

        def close_all
          socks = @mu.synchronize { @links.values.filter_map(&:socket) }
          socks.each { |s| s.to_io.shutdown(Socket::SHUT_WR) rescue nil } # rubocop:disable Style/RescueModifier
          Thread.new do
            sleep 0.1
            socks.each { |s| s.close rescue nil } # rubocop:disable Style/RescueModifier
            @server&.close rescue nil # rubocop:disable Style/RescueModifier
          end.tap { |t| t.report_on_exception = false }
        end
        private :close_all

        # TLS-level byte counters are not exposed by the TLS binding: the tls_* fields repeat the application byte counts
        def stats
          peers.map do |p|
            l = @links[p]
            LinkStats.new(p, l.bytes_out, l.bytes_in, l.frames_out, l.frames_in, l.bytes_out, l.bytes_in)
          end
        end

        def note(msg)
          @evmu.synchronize do
            if @events.length < MAX_MESH_EVENTS
              @events << msg
            else
              @events_dropped += 1
            end
          end
        end
        private :note

        # printable-ASCII, length-capped copy of untrusted text (no control characters, no log forging)
        def sanitize(x, max) = x.to_s.gsub(/[^\x20-\x7e]/, '?')[0, max]
        private :sanitize
      end
    end
  end
end
