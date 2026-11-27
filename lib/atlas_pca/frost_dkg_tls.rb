# frozen_string_literal: true

require 'monitor'
require 'openssl'
require 'socket'
require 'timeout'

module AtlasPca
  # A mutual-TLS channel for the FROST distributed key generation over Ruby's OpenSSL (the reference's `frost-dkg-tls`; the Go port is the sibling).
  #
  # One TLS 1.3 connection per pair of participants, mutually authenticated by pinned certificate: each side trusts exactly the other participants'
  # certificates, and the peer's SHA-256 certificate fingerprint maps to its participant id, so the sender identity the DKG driver sees comes from the
  # handshake and never from message content. The higher-numbered party dials the lower-numbered one. A peer without a pinned certificate, a plaintext
  # client, a TLS 1.2 client, a second connection for an already linked identity and a connection from a party that should have been dialled are all
  # refused before any DKG byte is read. Frames are a 4-byte big-endian length then the message; the length is checked against DKG_MAX_MESSAGE_BYTES
  # before any allocation. The node's channel answers the interface of `FrostDkgChannel.run_dkg_over_channel`.
  #
  # This is a reference: certificate issuance, rotation and revocation are the deployer's. No cryptography is written here: the handshake, the
  # certificates and the record layer are OpenSSL's.
  module FrostDkgTls
    CH = FrostDkgChannel
    HANDSHAKE_TIMEOUT_S = 10
    REDIAL_S = 0.05

    module_function

    def fingerprint(cert) = OpenSSL::Digest::SHA256.hexdigest(cert.to_der)

    # The node's own key and certificate are PEM texts; `peer_certs` is [{'id' => Integer, 'certPem' => String}] (certificates only, of every OTHER
    # participant). Returns a Node (listening already; `port` is the bound port, 0 = ephemeral on `listen_host`, default 127.0.0.1).
    def start_node(self_id:, session_id:, key_pem:, cert_pem:, peer_certs:, listen_port: 0, listen_host: '127.0.0.1')
      Node.new(self_id, session_id, key_pem, cert_pem, peer_certs, listen_port, listen_host)
    end

    # One participant's TLS endpoint.
    class Node
      attr_reader :port

      def initialize(self_id, session_id, key_pem, cert_pem, peer_certs, listen_port, listen_host)
        @self_id = self_id
        @session_id = session_id
        @key = OpenSSL::PKey.read(key_pem)
        @cert = OpenSSL::X509::Certificate.new(cert_pem)
        @peer_certs = peer_certs.to_h { |p| [p['id'], OpenSSL::X509::Certificate.new(p['certPem'])] }
        @pinned = @peer_certs.to_h { |id, c| [FrostDkgTls.fingerprint(c), id] }
        if @pinned.size != peer_certs.length || @peer_certs.size != peer_certs.length || @peer_certs.key?(self_id)
          raise ArgumentError, 'startTlsDkgNode: peer certificates must be distinct and none may be this node'
        end

        @peers = @peer_certs.keys.sort
        @inbox = CH::DkgInbox.new(session_id, @peers)
        @mon = Monitor.new
        @linked = @mon.new_cond
        @links = {}
        @sockets = []
        @threads = []
        @closed = false

        @server = TCPServer.new(listen_host, listen_port)
        @port = @server.addr[1]
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.cert = @cert
        ctx.key = @key
        ctx.cert_store = store_of(@peer_certs.values)
        ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
        ctx.min_version = OpenSSL::SSL::TLS1_3_VERSION
        @server_ctx = ctx
        @acceptor = Thread.new { accept_loop }
      end

      # Dial the lower-numbered peers, wait for the higher-numbered ones, and return the channel once every link is authenticated.
      # `addresses`: [{'id', 'host', 'port'}]. Raises DkgChannelError('timeout') when a link is still missing after the deadline (the node is closed).
      def connect(addresses, connect_timeout_ms = 15_000)
        stop = false
        addresses.each do |a|
          raise CH.err('identity', a['id'], 'address for a participant that is not a pinned peer') unless @peers.include?(a['id'])

          track(Thread.new { dial(a['id'], a['host'], a['port'], -> { stop }) }) if a['id'] < @self_id
        end
        deadline = CH.now_ms + connect_timeout_ms
        missing = @mon.synchronize do
          # the only timer is the overall deadline; completion is signalled by the link event itself
          until @links.size >= @peers.length
            left = deadline - CH.now_ms
            unless left > 0
              m = @peers.reject { |p| @links.key?(p) }
              close_locked
              break m
            end
            @linked.wait(left / 1000.0)
          end
        end
        stop = true
        raise CH.err('timeout', missing[0], "no authenticated link to #{missing.join(',')}") if missing.is_a?(Array)

        Channel.new(self, @self_id, @peers, @inbox, @session_id)
      end

      # the participant ids with an authenticated link right now
      def linked_ids = @mon.synchronize { @links.keys.sort }

      def close
        @mon.synchronize { close_locked }
        @threads.dup.each { |t| t.join(2) unless t == Thread.current }
        nil
      end

      # one framed write to a linked peer
      def write(to, kind, body)
        sock, lock = @mon.synchronize { @links[to] }
        raise CH.err('closed', to, 'no authenticated link') if sock.nil?

        frame = CH.tls_frame_encode(CH.encode_dkg_message(@session_id, kind, body))
        lock.synchronize { sock.write(frame) }
        nil
      rescue CH::DkgChannelError
        raise
      rescue StandardError
        raise CH.err('closed', to, 'write failed')
      end

      private

      def store_of(certs)
        s = OpenSSL::X509::Store.new
        certs.each { |c| s.add_cert(c) }
        s
      end

      def track(thread)
        @mon.synchronize { @threads << thread }
        thread.report_on_exception = false
        thread
      end

      def close_locked
        return if @closed

        @closed = true
        @inbox.close
        @sockets.each { |s| quiet { s.close } }
        quiet { @server.close }
        @linked.broadcast
      end

      def quiet
        yield
      rescue StandardError
        nil
      end

      def accept_loop
        until @closed
          tcp = begin
            @server.accept
          rescue StandardError
            break
          end
          track(Thread.new(tcp) { |conn| serve(conn) }) # the block gets its own copy: `tcp` is reassigned by the next accept
        end
      end

      # a server-side connection: the handshake demands a certificate this node pinned; only a higher-numbered, not yet linked peer is kept
      def serve(tcp)
        ssl = OpenSSL::SSL::SSLSocket.new(tcp, @server_ctx)
        ssl.sync_close = true
        register(ssl)
        Timeout.timeout(HANDSHAKE_TIMEOUT_S) { ssl.accept }
        id = @pinned[FrostDkgTls.fingerprint(ssl.peer_cert)] if ssl.peer_cert
        return quiet { ssl.close } if id.nil? || id < @self_id || link?(id)

        attach(id, ssl)
      rescue StandardError => e
        quiet { tcp.close }
      end

      def register(sock)
        @mon.synchronize do
          raise IOError, 'closed' if @closed

          @sockets << sock
        end
      end

      def link?(id) = @mon.synchronize { @links.key?(id) }

      def dial(id, host, port, stopped)
        cert = @peer_certs.fetch(id)
        until stopped.call || @closed
          return if try_dial(id, host, port, cert)

          sleep(REDIAL_S)
        end
      end

      def try_dial(id, host, port, cert)
        tcp = TCPSocket.new(host, port)
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.cert = @cert
        ctx.key = @key
        ctx.cert_store = store_of([cert])
        ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
        ctx.verify_hostname = false # pinned by certificate, not by host name
        ctx.min_version = OpenSSL::SSL::TLS1_3_VERSION
        ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
        ssl.sync_close = true
        register(ssl)
        Timeout.timeout(HANDSHAKE_TIMEOUT_S) { ssl.connect }
        if ssl.peer_cert.nil? || @pinned[FrostDkgTls.fingerprint(ssl.peer_cert)] != id
          quiet { ssl.close }
          return false
        end
        attach(id, ssl)
        true
      rescue StandardError => e
        quiet { tcp&.close }
        false
      end

      # a linked, authenticated peer: its frames feed the inbox; the end of the link marks the peer gone
      def attach(id, sock)
        @mon.synchronize do
          return quiet { sock.close } if @closed || @links.key?(id)

          @links[id] = [sock, Mutex.new]
          @linked.broadcast
        end
        track(Thread.new { read_loop(id, sock) })
      end

      def read_loop(id, sock)
        buf = ''.b
        loop do
          chunk = sock.readpartial(16_384)
          buf << chunk.b
          loop do
            break if buf.bytesize < 4

            len = buf.unpack1('N')
            if len > CH::DKG_MAX_MESSAGE_BYTES
              @inbox.fail(id, CH.err('oversize', id, "frame of #{len} bytes exceeds the cap"))
              quiet { sock.close }
              return
            end
            break if buf.bytesize < 4 + len

            @inbox.accept(id, buf.byteslice(4, len))
            buf = buf.byteslice(4 + len, buf.bytesize - 4 - len)
          end
        end
      rescue StandardError
        nil
      ensure
        @mon.synchronize { @links.delete(id) if @links[id] && @links[id][0].equal?(sock) }
        @inbox.peer_gone(id)
      end
    end

    # The channel of a connected node (the interface of run_dkg_over_channel).
    class Channel
      attr_reader :self_id, :peers

      def initialize(node, self_id, peers, inbox, session_id)
        @node = node
        @self_id = self_id
        @peers = peers
        @inbox = inbox
        @session_id = session_id
      end

      def broadcast(kind, body)
        @peers.each { |p| @node.write(p, kind, body) }
        nil
      end

      def send_to(to, kind, body)
        raise CH.err('identity', to, 'not a connected peer') unless @peers.include?(to)

        @node.write(to, kind, body)
      end

      def collect(kind, from, timeout_ms) = @inbox.collect(kind, from, timeout_ms)

      def close = @node.close
    end
  end
end
