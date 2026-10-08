#!/usr/bin/env ruby
# frozen_string_literal: true

# Plain runner for the Rack middleware (mirrors conformance.rb's style; no test framework dep):
#   ruby -Ilib -Itest test/test_middleware.rb   (exit 1 on any failure)
#
# It reuses the conformance-vector loader to get a GENUINELY-signed, valid PCActn, then drives
# AtlasPca::RackMiddleware#call directly with hand-built Rack envs.
require_relative '../lib/atlas_pca/rack_middleware'
require 'stringio'

DIR = File.expand_path('../conformance', __dir__)
# loose: the vectors file carries deliberately-bad values as already-parsed objects (see conformance.rb).
DOC = AtlasPca.parse_json(File.read(File.join(DIR, 'vectors.json'), encoding: 'UTF-8'), loose: true)

$fails = 0
$count = 0

def check(cond, msg)
  $count += 1
  return if cond

  $fails += 1
  warn "FAIL: #{msg}"
end

# Pull the first valid, non-PQ (ed25519) vector that carries an object PCActn.
VECTOR = DOC['vectors'].find do |v|
  v['expect']['allow'] == true &&
    (v['requires'].nil? || v['requires'].empty? || v['requires'] == 'ed25519') &&
    v.key?('pcactn')
end
abort 'no valid ed25519 object vector found' if VECTOR.nil?

PCACTN   = VECTOR['pcactn']
GRANT    = VECTOR['grant']
AUDIENCE = VECTOR['context']['aud']
NOW      = VECTOR['context']['now']
GRANT_REF = PCACTN['grant_ref']

# resolve_grant that only knows the one real grant.
RESOLVER = lambda do |grant_ref|
  grant_ref == GRANT_REF ? GRANT : nil
end

# The app under the middleware: records that it ran and what landed in env['pca'].
def terminal_app
  seen = {}
  app = lambda do |env|
    seen[:ran] = true
    seen[:pca] = env['pca']
    [200, { 'content-type' => 'text/plain' }, ['ok']]
  end
  [app, seen]
end

def header_env(b64u, extra = {})
  { 'HTTP_PCA_ACTION' => b64u, 'rack.input' => StringIO.new('') }.merge(extra)
end

def body_json(status, headers, body)
  AtlasPca.parse_json(body.join, any_top: true)
end

# base64url(canonical JSON) of a parsed PCActn — exactly what a client would put on the wire.
B64_PCACTN = AtlasPca.b64e(AtlasPca.canon_bytes(PCACTN))

# ---------------------------------------------------------------------------
# 1. valid header -> app runs + env['pca'] populated
# ---------------------------------------------------------------------------
app, seen = terminal_app
mw = AtlasPca::RackMiddleware.new(app, audience: AUDIENCE, resolve_grant: RESOLVER, now: NOW)
status, _headers, body = mw.call(header_env(B64_PCACTN))
check(status == 200, "valid header: status=#{status} want 200 (body=#{body.join})")
check(seen[:ran] == true, 'valid header: downstream app did not run')
check(!seen[:pca].nil?, 'valid header: env[\'pca\'] not set')
check(seen[:pca] && seen[:pca]['verdict'].allow == true, 'valid header: verdict not allow')
check(seen[:pca] && seen[:pca]['pcactn'].equal?(PCACTN) || (seen[:pca] && seen[:pca]['pcactn'] == PCACTN),
      'valid header: pcactn not threaded through env')

# ---------------------------------------------------------------------------
# 1b. valid JSON body { "pcactn": ... } -> app runs; body rewound for downstream
# ---------------------------------------------------------------------------
app, seen = terminal_app
mw = AtlasPca::RackMiddleware.new(app, audience: AUDIENCE, resolve_grant: RESOLVER, now: NOW)
envelope = "{\"pcactn\":#{AtlasPca.canonicalize(PCACTN)}}"
input = StringIO.new(envelope)
env = { 'rack.input' => input } # no header -> body path
status, _headers, _body = mw.call(env)
check(status == 200, "valid body: status=#{status} want 200")
check(seen[:ran] == true, 'valid body: downstream app did not run')
check(input.read == envelope, 'valid body: rack.input was not rewound for downstream')

# ---------------------------------------------------------------------------
# 2. no header (and no body) -> 401 + WWW-Authenticate
# ---------------------------------------------------------------------------
app, seen = terminal_app
mw = AtlasPca::RackMiddleware.new(app, audience: AUDIENCE, resolve_grant: RESOLVER, now: NOW)
status, headers, body = mw.call('rack.input' => StringIO.new(''))
check(status == 401, "no header: status=#{status} want 401")
check(seen[:ran].nil?, 'no header: downstream app should NOT have run')
check(headers['WWW-Authenticate'].to_s.start_with?('PCA realm="pca"'),
      "no header: WWW-Authenticate missing/wrong: #{headers['WWW-Authenticate'].inspect}")
check(body_json(status, headers, body)['error'] == 'invalid_pcactn', 'no header: error code not invalid_pcactn')

# ---------------------------------------------------------------------------
# 2b. undecodable header -> 401
# ---------------------------------------------------------------------------
app, = terminal_app
mw = AtlasPca::RackMiddleware.new(app, audience: AUDIENCE, resolve_grant: RESOLVER, now: NOW)
status, headers, = mw.call(header_env('!!!not base64!!!'))
check(status == 401, "undecodable header: status=#{status} want 401")
check(headers['WWW-Authenticate'].to_s.start_with?('PCA realm="pca"'), 'undecodable header: no challenge')

# ---------------------------------------------------------------------------
# 3. unknown grant -> 401
# ---------------------------------------------------------------------------
app, seen = terminal_app
none = ->(_ref) { nil }
mw = AtlasPca::RackMiddleware.new(app, audience: AUDIENCE, resolve_grant: none, now: NOW)
status, headers, body = mw.call(header_env(B64_PCACTN))
check(status == 401, "unknown grant: status=#{status} want 401")
check(seen[:ran].nil?, 'unknown grant: downstream app should NOT have run')
check(body_json(status, headers, body)['error_description'].to_s.include?('unknown grant'),
      'unknown grant: description does not mention unknown grant')

# ---------------------------------------------------------------------------
# 4. wrong audience -> 403 (verifier produces a denying verdict)
# ---------------------------------------------------------------------------
app, seen = terminal_app
mw = AtlasPca::RackMiddleware.new(app, audience: 'rs-someone-else', resolve_grant: RESOLVER, now: NOW)
status, headers, body = mw.call(header_env(B64_PCACTN))
check(status == 403, "wrong audience: status=#{status} want 403")
check(seen[:ran].nil?, 'wrong audience: downstream app should NOT have run')
parsed = body_json(status, headers, body)
check(parsed['error'] == 'access_denied', 'wrong audience: error code not access_denied')
check(parsed['failed_checks'].is_a?(Array) && parsed['failed_checks'].include?('audience'),
      "wrong audience: failed_checks should list audience, got #{parsed['failed_checks'].inspect}")
check(headers['WWW-Authenticate'].to_s.start_with?('PCA realm="pca"'), 'wrong audience: no challenge')

puts "#{$count} assertions, #{$fails} failures (vector: #{VECTOR['name']})"
exit($fails.zero? ? 0 : 1)
