# frozen_string_literal: true

# The HTTP carriage of the networked FROST signer over loopback: the routes and refusals of the server (against a stub service, no FROST backend
# needed), and a 2-of-3 signing session through the HTTP transports of three single-share signers, checked against the group key.
require_relative '../lib/atlas_pca'
require 'minitest/autorun'
require 'json'
require 'net/http'

class TestFrostNetHttp < Minitest::Test
  A = AtlasPca
  H = AtlasPca::FrostNetHttp

  # a stub with the two entry points of a signer service
  class Stub
    attr_reader :identifier, :calls

    def initialize = (@identifier = 7; @calls = [])

    def round1(req) = (@calls << [:round1, req]; { 'ok' => true, 'identifier' => 7, 'echo' => req })
    def round2(req) = (@calls << [:round2, req]; raise 'boom' if req['explode']; { 'ok' => true, 'identifier' => 7 })
  end

  def setup
    @stub = Stub.new
    @server = H.start_signer_http_server(@stub)
  end

  def teardown = @server.close

  def request(method, path, body = nil, headers = {})
    http = Net::HTTP.new('127.0.0.1', @server.port)
    http.read_timeout = 10
    req = Net::HTTPGenericRequest.new(method, !body.nil?, true, path, headers)
    req.body = body
    res = http.request(req)
    [res.code.to_i, JSON.parse(res.body)]
  end

  def test_it_binds_loopback_on_an_ephemeral_port
    assert_match(%r{\Ahttp://127\.0\.0\.1:\d+\z}, @server.url)
    assert_operator @server.port, :>, 0
  end

  def test_a_post_to_each_round_reaches_the_service
    assert_equal [200, { 'ok' => true, 'identifier' => 7, 'echo' => { 'a' => 1 } }], request('POST', '/round1', '{"a":1}')
    assert_equal [200, { 'ok' => true, 'identifier' => 7 }], request('POST', '/round2', '{"b":2}')
    assert_equal [[:round1, { 'a' => 1 }], [:round2, { 'b' => 2 }]], @stub.calls
  end

  def test_an_empty_body_is_an_empty_request
    code, = request('POST', '/round1')
    assert_equal 200, code
    assert_equal [[:round1, {}]], @stub.calls
  end

  def test_other_methods_and_paths_are_refused
    assert_equal [405, { 'ok' => false, 'reason' => 'method not allowed' }], request('GET', '/round1')
    assert_equal [404, { 'ok' => false, 'reason' => 'not found' }], request('POST', '/round3', '{}')
    assert_equal [404, { 'ok' => false, 'reason' => 'not found' }], request('POST', '/round1?x=1', '{}')
    assert_empty @stub.calls
  end

  def test_a_handler_error_is_a_refusal_never_a_stack
    code, body = request('POST', '/round2', '{"explode":true}')
    assert_equal 400, code
    assert_equal({ 'ok' => false, 'identifier' => 7, 'refused' => true, 'reason' => 'boom' }, body)
  end

  def test_a_body_that_is_not_json_is_refused
    code, body = request('POST', '/round1', '{nope')
    assert_equal 400, code
    assert_equal 'request body is not JSON', body['reason']
    assert_empty @stub.calls
  end

  def test_an_oversize_body_is_refused_before_it_is_read
    code, body = request('POST', '/round1', 'x' * (H::MAX_BODY_BYTES + 1))
    assert_equal 400, code
    assert_equal 'request body too large', body['reason']
    assert_empty @stub.calls
  end

  def test_a_chunked_body_is_refused
    sock = TCPSocket.new('127.0.0.1', @server.port)
    sock.write("POST /round1 HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
    head, _, rest = sock.read.partition("\r\n\r\n")
    assert_match(/\AHTTP\/1\.1 400 /, head)
    assert_equal 'chunked request bodies are not accepted', JSON.parse(rest)['reason']
    assert_empty @stub.calls
  end

  def test_the_transport_posts_json_and_reads_the_answer
    t = H.http_signer_transport(@server.url, 7)
    assert_equal 7, t.identifier
    assert_equal({ 'ok' => true, 'identifier' => 7, 'echo' => { 'x' => 'y' } }, t.round1({ 'x' => 'y' }))
    assert_equal({ 'ok' => true, 'identifier' => 7 }, t.round2({}))
  end

  def test_a_closed_server_fails_the_transport
    t = H.http_signer_transport(@server.url, 7, timeout_ms: 2000)
    @server.close
    assert_raises(StandardError) { t.round1({}) }
  end

  def test_the_runner_reads_base64url_bytes_and_prints_one_ready_line
    err = assert_raises(ArgumentError) { H.build_service({ 'identifier' => 1, 'share' => 'AA', 'groupPublicKey' => 'AA', 'threshold' => 2, 'policyAuthorityPublicKey' => 'AA' }) }
    assert_match(/field 'share' is not 32-byte canonical base64url/, err.message)
    line = H.ready_line(3, @server)
    assert line.start_with?(H::READY_PREFIX)
    assert_equal({ 'identifier' => 3, 'url' => @server.url, 'port' => @server.port }, JSON.parse(line.delete_prefix(H::READY_PREFIX)))
  end

  # a 2-of-3 signing session, every signer in its own server holding one share, driven over HTTP
  def test_a_two_of_three_session_over_http_signs_under_the_group_key
    begin
      A::Frost.trusted_dealer_keygen(2, 3)
    rescue LoadError => e
      flunk e.message if %w[true 1].include?(ENV['CI'])
      skip e.message
    end
    dealt = A::Frost.trusted_dealer_keygen(2, 3)
    gpk = dealt['groupPublicKey']
    authority = A::KeyPair.new(Digest::SHA256.digest('http-runner-authority'))
    servers = dealt['participantShares'].map do |s|
      cfg = { 'identifier' => s['identifier'], 'share' => A.b64e(s['share']), 'groupPublicKey' => A.b64e(gpk), 'threshold' => 2,
              'policyAuthorityPublicKey' => authority.public }
      [s['identifier'], H.run_signer(cfg)]
    end
    transports = servers.map { |id, srv| H.http_signer_transport(srv.url, id) }
    message = 'rotate the recovery keys'.b
    allow = A::FrostNet.issue_allow_token(authority, { 'message' => message, 'groupPublicKey' => gpk })
    # the enrollment (verification share and proof of possession) is out of band: the dealer's side reads it from its own copy of each service
    services = dealt['participantShares'].map { |s| H.build_service({ 'identifier' => s['identifier'], 'share' => A.b64e(s['share']), 'groupPublicKey' => A.b64e(gpk), 'threshold' => 2, 'policyAuthorityPublicKey' => authority.public }) }
    coordinator = A::FrostNet::NetworkCoordinator.new(group_public_key: gpk, threshold: 2, signers: transports, enroll: services.map(&:enrollment))
    out = coordinator.sign(message, allow)
    assert A.verify_b64u(A.b64e(gpk), message, A.b64e(out['signature'])), 'the aggregate is a standard Ed25519 signature under the group key'
    assert_equal 2, out['signers'].length
    # a token for another action is refused by every signer
    bad = A::FrostNet.issue_allow_token(authority, { 'message' => 'something else'.b, 'groupPublicKey' => gpk })
    assert_raises(A::FrostNet::CoordinatorError) { coordinator.sign(message, bad) }
  ensure
    servers&.each { |_, srv| srv.close }
  end
end
