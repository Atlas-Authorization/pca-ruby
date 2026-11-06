# frozen_string_literal: true

require_relative '../atlas_pca'

# AtlasPca.protect: the secure defaults for a resource server, in one call (mirrors the TypeScript protect()).
#
#   p = AtlasPca.protect(audience: 'ins_acme', grants: [grant],
#                        operation: ->(env) { { verb: 'stripe.refund', resource: "charge:#{...}", params: {...} } })
#   use AtlasPca::RackMiddleware, **p.options      # Rails: config.middleware.use AtlasPca::RackMiddleware, **p.options
#   p.revoke(grant['id'])                          # later: every action under that grant is refused
#
# It fills in what every server otherwise wires by hand, and nothing else: the grant lookup (your list or callable, never the
# request), a MemoryStateStore for replay, a revocation source, `plan: 'single-step'` (the grant alone limits what runs).
# Not ported: the TypeScript server-side catalog risk (this authorize has no risk option; the risk policy is not ported).
# Any option you pass wins over the default. Options the authorize pipeline knows (state_store, plan, context, require, ...)
# go to `authorize:`; everything else (now, header, intent_policy, executor, ...) goes to the middleware as given.
module AtlasPca
  # `options` is for RackMiddleware.new(app, **options); `revoke(grant_id)` refuses every further action under that grant.
  class Protected
    attr_reader :options

    def initialize(options, revoked)
      @options = options
      @revoked = revoked
    end

    def revoke(grant_id)
      @revoked[grant_id] = true
      nil
    end
  end

  # grants: an Array of grants (looked up by their 'id'), or a callable grant_ref -> grant | nil.
  # is_revoked: optional extra ->(pcactn, grant) revocation source, consulted in addition to revoke().
  def self.protect(audience:, grants:, operation:, is_revoked: nil, **rest)
    resolve_grant = protect_resolver(grants)
    raise ArgumentError, 'operation: must respond to #call' unless operation.respond_to?(:call)
    raise ArgumentError, 'is_revoked: must respond to #call' unless is_revoked.nil? || is_revoked.respond_to?(:call)

    revoked = {}
    authorize = rest.delete(:authorize) || {}
    raise ArgumentError, 'authorize: must be a Hash (use protect\'s own keywords for the rest)' unless authorize.is_a?(Hash)

    RackMiddleware::AUTHORIZE_KEYS.each { |k| authorize = authorize.merge(k => rest.delete(k)) if rest.key?(k) }
    authorize = { state_store: MemoryStateStore.new, plan: 'single-step' }.merge(authorize.to_h { |k, v| [k.to_sym, v] })
    authorize[:operation] = operation
    is_revoked ||= authorize[:is_revoked]
    authorize[:is_revoked] = lambda do |pcactn, grant|
      id = grant.is_a?(Hash) ? grant['id'] : nil
      return true if id.nil? || revoked.key?(id)

      is_revoked.nil? ? false : is_revoked.call(pcactn, grant)
    end
    Protected.new({ audience: audience, resolve_grant: resolve_grant, authorize: authorize }.merge(rest), revoked)
  end

  def self.protect_resolver(grants)
    return grants if grants.respond_to?(:call)
    raise ArgumentError, 'grants: must be an Array of grants or a callable grant_ref -> grant' unless grants.is_a?(Array)

    by_id = {}
    grants.each do |g|
      raise ArgumentError, 'grants: every grant must be a Hash with a String "id"' unless g.is_a?(Hash) && g['id'].is_a?(String)

      by_id[g['id']] = g
    end
    ->(ref) { by_id[ref] }
  end
end
