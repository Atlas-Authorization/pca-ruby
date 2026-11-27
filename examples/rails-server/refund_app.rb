# frozen_string_literal: true

require 'json'
require 'atlas_pca/rack_middleware'

# A tiny resource server: POST /refunds is gated by AtlasPca.protect. The caller must present a proof (header PCA-Action)
# that was signed for exactly the operation this route executes. The route maps the request to that operation itself;
# nothing in the proof is trusted to say what runs.
module RefundApp
  module_function

  # The operation this route executes, from the request (method, path, JSON body), never from the proof.
  def operation(env)
    return nil unless env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] == '/refunds'

    body = JSON.parse(env['rack.input'].read.to_s)
    env['rack.input'].rewind
    { verb: 'payments.send', resource: "payments/#{body['account']}", params: { amount: body['amount'], currency: body['currency'] } }
  rescue JSON::ParserError
    nil
  end

  def handler(env)
    return [404, { 'content-type' => 'application/json' }, ['{"error":"not_found"}']] unless env['PATH_INFO'] == '/refunds'

    op = env['pca']['operation']
    [200, { 'content-type' => 'application/json' }, [JSON.generate(refunded: true, verb: op.verb, resource: op.resource)]]
  end

  # `grants` come from your own store (never from the request). Returns [rack_app, protected]; call
  # protected.revoke(grant_id) to refuse every further action under a grant.
  def build(grants:, audience:, **opts)
    prot = AtlasPca.protect(audience: audience, grants: grants, operation: method(:operation), **opts)
    app = AtlasPca::RackMiddleware.new(method(:handler), **prot.options)
    [app, prot]
  end
end
