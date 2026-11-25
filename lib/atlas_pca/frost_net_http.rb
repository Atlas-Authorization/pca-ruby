# frozen_string_literal: true

require 'json'
require 'net/http'
require 'socket'
require 'uri'

module AtlasPca
  # The HTTP carriage of the networked FROST signer (the reference's `startSignerHttpServer`, `httpSignerTransport` and the single-signer runner): a
  # `GuardianSignerService` behind JSON over loopback HTTP, and the coordinator-side transport that talks to it. Routes: POST /round1 and POST /round2
  # (anything else is 404, a non-POST is 405); JSON in, JSON out, every byte base64url; a handler error is a refusal response, never a stack or a share.
  # The server holds exactly ONE share (the service it was given) and answers one request at a time (the service is not re-entrant).
  # Bodies are read by Content-Length only (a chunked body is refused) and capped at 1 MiB.
  module FrostNetHttp
    MAX_BODY_BYTES = 1 << 20
    MAX_HEADER_BYTES = 16 * 1024
    READY_PREFIX = 'FROST_SIGNER_READY '
    IO_TIMEOUT_S = 10

    module_function

    # A running server: url, port, close.
    class SignerHttpServer
      attr_reader :url, :port

      def initialize(service, host, port)
        @service = service
        @lock = Mutex.new
        @closed = false
        @sockets = []
        @mon = Mutex.new
        @server = TCPServer.new(host, port)
        @port = @server.addr[1]
        @url = "http://#{host}:#{@port}"
        @acceptor = Thread.new { accept_loop }
        @acceptor.report_on_exception = false
      end

      def close
        @mon.synchronize do
          return nil if @closed

          @closed = true
          @sockets.each { |s| quiet { s.close } }
          quiet { @server.close }
        end
        @acceptor.join(2)
        nil
      end

      private

      def quiet
        yield
      rescue StandardError
        nil
      end

      def accept_loop
        until @closed
          conn = begin
            @server.accept
          rescue StandardError
            break
          end
          @mon.synchronize { @sockets << conn }
          Thread.new(conn) { |c| serve(c) }.report_on_exception = false # the block gets its own copy: `conn` is reassigned by the next accept
        end
      end

      def serve(conn)
        conn.timeout = IO_TIMEOUT_S
        status, body = respond(conn)
        write_response(conn, status, body)
        linger(conn)
      rescue StandardError
        nil
      ensure
        quiet { conn.close }
        @mon.synchronize { @sockets.delete(conn) }
      end

      # Let the peer finish what it is still sending (bounded, never parsed): closing a socket with unread data resets the connection on some
      # platforms, and the peer then never sees the refusal that was just written.
      def linger(conn)
        conn.close_write
        left = 2 * MAX_BODY_BYTES
        left -= conn.readpartial(65_536).bytesize while left.positive?
      rescue StandardError # EOF (the peer is done), a timeout or a reset all end the wait
        nil
      end

      def refusal(reason) = { 'ok' => false, 'identifier' => @service.identifier, 'refused' => true, 'reason' => reason }

      def respond(conn)
        method, path, headers = read_head(conn)
        return [405, { 'ok' => false, 'reason' => 'method not allowed' }] unless method == 'POST'
        return [404, { 'ok' => false, 'reason' => 'not found' }] unless %w[/round1 /round2].include?(path)

        raw = read_body(conn, headers)
        req = raw.empty? ? {} : JSON.parse(raw)
        [200, @lock.synchronize { path == '/round1' ? @service.round1(req) : @service.round2(req) }]
      rescue StandardError => e
        [400, refusal(e.is_a?(JSON::ParserError) ? 'request body is not JSON' : e.message)]
      end

      # [method, path, headers (lower-case names)]; the head is capped
      def read_head(conn)
        line = conn.gets("\r\n", MAX_HEADER_BYTES)
        raise ArgumentError, 'bad request line' if line.nil?

        method, path, = line.split(' ', 3)
        headers = {}
        total = line.bytesize
        loop do
          h = conn.gets("\r\n", MAX_HEADER_BYTES)
          raise ArgumentError, 'bad request head' if h.nil?

          total += h.bytesize
          raise ArgumentError, 'request head too large' if total > MAX_HEADER_BYTES

          break if h == "\r\n"

          k, v = h.split(':', 2)
          headers[k.strip.downcase] = v.to_s.strip unless v.nil?
        end
        [method, path, headers]
      end

      def read_body(conn, headers)
        raise ArgumentError, 'chunked request bodies are not accepted' if headers.key?('transfer-encoding')

        len = headers['content-length']
        return '' if len.nil?
        raise ArgumentError, 'bad content-length' unless len.match?(/\A\d+\z/)
        raise ArgumentError, 'request body too large' if len.to_i > MAX_BODY_BYTES

        body = conn.read(len.to_i)
        raise ArgumentError, 'request body is shorter than its content-length' if body.nil? || body.bytesize != len.to_i

        body.force_encoding(Encoding::UTF_8)
      end

      def write_response(conn, status, body)
        json = JSON.generate(body)
        reason = { 200 => 'OK', 400 => 'Bad Request', 404 => 'Not Found', 405 => 'Method Not Allowed' }.fetch(status, 'Error')
        conn.write("HTTP/1.1 #{status} #{reason}\r\ncontent-type: application/json\r\ncontent-length: #{json.bytesize}\r\nconnection: close\r\n\r\n#{json}")
      end
    end

    # Start an HTTP server for one signer service. Binds 127.0.0.1 and, by default, an ephemeral port (pass `port` to pin one).
    def start_signer_http_server(service, port: nil, host: '127.0.0.1') = SignerHttpServer.new(service, host, port || 0)

    # The coordinator-side transport to a signer at `base_url` (an object answering `identifier`, `round1(req)` and `round2(req)`): POST the request as
    # JSON, read the JSON answer. A transport failure raises (the coordinator reports the signer as refused).
    class HttpSignerTransport
      attr_reader :identifier

      def initialize(base_url, identifier, timeout_ms)
        @uri = URI.parse(base_url)
        @identifier = identifier
        @timeout = timeout_ms / 1000.0
      end

      def round1(req) = post('/round1', req)
      def round2(req) = post('/round2', req)

      private

      def post(path, body)
        http = Net::HTTP.new(@uri.host, @uri.port)
        http.open_timeout = http.read_timeout = http.write_timeout = @timeout
        res = http.post(path, JSON.generate(body), { 'content-type' => 'application/json' })
        JSON.parse(res.body.to_s)
      end
    end

    def http_signer_transport(base_url, identifier, timeout_ms: 10_000) = HttpSignerTransport.new(base_url, identifier, timeout_ms)

    # ---- the single-signer runner: one service, one share, one process ----

    def require_bytes(b64, len, field)
      out = AtlasPca.b64d(b64, len)
      raise ArgumentError, "frost-net-runner: field '#{field}' is not #{len}-byte canonical base64url" if out.nil?

      out
    end

    # The service of a runner config {identifier, share, groupPublicKey, threshold, policyAuthorityPublicKey, port?, host?}: bytes are base64url.
    def build_service(cfg)
      FrostNet::GuardianSignerService.new(identifier: cfg['identifier'], share: require_bytes(cfg['share'], 32, 'share'),
                                          group_public_key: require_bytes(cfg['groupPublicKey'], 32, 'groupPublicKey'), threshold: cfg['threshold'],
                                          policy_authority_public_key: require_bytes(cfg['policyAuthorityPublicKey'], 32, 'policyAuthorityPublicKey'))
    end

    # Start the signer of `cfg` over HTTP; the returned server's `ready_line` is the one machine-parseable line a parent reads.
    def run_signer(cfg)
      service = build_service(cfg)
      start_signer_http_server(service, port: cfg['port'], host: cfg['host'] || '127.0.0.1')
    end

    def ready_line(identifier, server) = "#{READY_PREFIX}#{JSON.generate({ 'identifier' => identifier, 'url' => server.url, 'port' => server.port })}"
  end
end
