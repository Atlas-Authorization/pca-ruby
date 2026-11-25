# frozen_string_literal: true

# The egress proxy server: loopback-only (127.0.0.1, ephemeral ports), no external network. The policy logic itself is replayed
# against the shared corpus in test_ref_sandbox; this covers the I/O layer.
require_relative 'support/ref_oracle'
require_relative '../lib/atlas_pca/sandbox_egress'
require 'minitest/autorun'
require 'socket'

class TestSandboxEgress < Minitest::Test
  S = AtlasPca::Sandbox
  OP = { 'verb' => 'http.get', 'resource' => 'api', 'params' => { 'x' => 1 } }.freeze

  def result
    { 'allow' => true, 'operation' => { 'verb' => OP['verb'], 'resource' => OP['resource'], 'params_digest' => AtlasPca.hash_canonical(OP['params']), 'id' => 'op1' } }
  end

  def policy(port, **t)
    p = S::EgressPolicy.new
    tmpl = { 'method' => 'GET', 'scheme' => 'http', 'host' => '127.0.0.1', 'port' => port, 'path' => '/ok' }.merge(t.transform_keys(&:to_s))
    p.admit(result, OP, ->(_op) { tmpl }, { 'uses' => 1 })
    p
  end

  # a one-shot upstream answering every connection with a fixed 200 and recording each request head
  def upstream(seen)
    srv = TCPServer.new('127.0.0.1', 0)
    Thread.new do
      loop do
        c = srv.accept
        head = +''
        head << c.readpartial(4096) until head.include?("\r\n\r\n")
        seen << head
        c.write("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-up: 1\r\nconnection: close\r\n\r\nhi")
        c.close
      end
    rescue IOError, SystemCallError
      nil
    end
    [srv, srv.addr[1]]
  end

  def send_raw(port, raw)
    s = TCPSocket.new('127.0.0.1', port)
    s.write(raw)
    data = s.read
    s.close
    data
  end

  def test_proxy_flow
    seen = []
    up, uport = upstream(seen)
    log = S::ReceiptLog.new
    proxy = AtlasPca::Sandbox::EgressProxy.new(policy(uport), log, allow_private: true).start
    url = "http://127.0.0.1:#{uport}/ok"
    req = "GET #{url} HTTP/1.1\r\nhost: x\r\nx-keep: 1\r\nproxy-authorization: secret\r\n\r\n"
    ok = send_raw(proxy.port, req)
    assert ok.start_with?('HTTP/1.1 200') && ok.end_with?('hi') && ok.include?('x-up: 1')
    assert seen[0].include?('x-keep: 1') && !seen[0].downcase.include?('proxy-authorization')
    # the single use is spent: the same request is refused and never reaches the upstream
    again = send_raw(proxy.port, req)
    assert again.start_with?('HTTP/1.1 403') && again.include?('spent') && seen.length == 1
    # a different path, a body the template does not allow, chunked framing, an origin-form request, a doubled length: all refused
    ["GET http://127.0.0.1:#{uport}/other HTTP/1.1\r\n\r\n", "POST #{url} HTTP/1.1\r\ncontent-length: 1\r\n\r\nx",
     "GET #{url} HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n", "GET /ok HTTP/1.1\r\n\r\n",
     "GET #{url} HTTP/1.1\r\ncontent-length: 1\r\ncontent-length: 2\r\n\r\nxx"].each do |raw|
      got = send_raw(proxy.port, raw)
      assert got.start_with?('HTTP/1.1 403') || got.start_with?('HTTP/1.1 400'), got
    end
    assert_equal 1, seen.length
    assert_equal %w[ok refused], log.entries.first(2).map { |e| e['outcome'] }
    assert S.verify_receipt_chain(log.entries)['ok']
  ensure
    proxy&.close
    up&.close
  end

  def test_proxy_private_guard
    seen = []
    up, uport = upstream(seen)
    log = S::ReceiptLog.new
    proxy = AtlasPca::Sandbox::EgressProxy.new(policy(uport), log).start # allow_private defaults to false: a loopback upstream is refused
    got = send_raw(proxy.port, "GET http://127.0.0.1:#{uport}/ok HTTP/1.1\r\n\r\n")
    assert got.start_with?('HTTP/1.1 502') && seen.empty?
    assert_equal 'upstream:EACCES', log.entries.last['reason']
  ensure
    proxy&.close
    up&.close
  end

  def test_proxy_connect
    up = TCPServer.new('127.0.0.1', 0)
    Thread.new do
      c = up.accept
      c.write(c.readpartial(4))
      c.close
    rescue IOError, SystemCallError
      nil
    end
    uport = up.addr[1]
    p = S::EgressPolicy.new
    p.admit(result, OP, ->(_op) { { 'method' => 'GET', 'scheme' => 'https', 'host' => '127.0.0.1', 'port' => uport, 'path' => '/', 'tunnel' => true } })
    proxy = AtlasPca::Sandbox::EgressProxy.new(p, S::ReceiptLog.new, allow_private: true).start
    s = TCPSocket.new('127.0.0.1', proxy.port)
    s.write("CONNECT 127.0.0.1:#{uport} HTTP/1.1\r\n\r\n")
    assert s.readpartial(4096).start_with?('HTTP/1.1 200')
    s.write('ping')
    assert_equal 'ping', s.read(4)
    s.close
    # not admitted any more (one use): refused
    assert send_raw(proxy.port, "CONNECT 127.0.0.1:#{uport} HTTP/1.1\r\n\r\n").start_with?('HTTP/1.1 403')
  ensure
    proxy&.close
    up&.close
  end
end
