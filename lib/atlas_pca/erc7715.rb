# frozen_string_literal: true

require_relative 'js_compat'

# ERC-7715 (wallet_requestExecutionPermissions) for PCA grants: map a grant's money envelope to a permission request, filter
# the wallet's supported permissions, the revoke params, and verify what the wallet actually granted (a wallet may narrow,
# never widen). Pure mapping, no chain access. Mirrors @atlasauth/pca-erc7715 including the reference's JS value coercions
# (String(x) / BigInt(x)). The request / response are the ERC's own camelCase JSON; options are snake_case.
module AtlasPca
  module Erc7715
    HEX_ADDR = /\A0x[0-9a-fA-F]{40}\z/
    HEX_QTY = /\A0x(0|[1-9a-fA-F][0-9a-fA-F]*)\z/
    DEC = /\A(0|[1-9][0-9]*)\z/
    CONTEXT = /\A0x[0-9a-fA-F]+\z/

    module_function

    def test?(re, x) = re.match?(Js.string(x)) # RegExp#test coerces its argument with String(x)
    def hex(n) = "0x#{n.to_s(16)}"

    # Options: chain_id (Integer), session_account, token_address (nil: native token), base_units_per_minor (decimal
    # String: the exact token base units per ONE minor unit), from, is_adjustment_allowed. Raises on a bad envelope / option.
    def grant_to_permission_request(g, o)
      cap = Js.get(g, 'capMinor')
      exp = Js.get(g, 'expiresAtSec')
      unless Js.safe_integer?(cap) && cap.positive? && Js.safe_integer?(exp) && exp.positive?
        raise RangeError, 'grantToPermissionRequest: bad envelope'
      end
      if !test?(HEX_ADDR, o['session_account']) || (o.key?('from') && !test?(HEX_ADDR, o['from'])) ||
         (o.key?('token_address') && !test?(HEX_ADDR, o['token_address']))
        raise RangeError, 'grantToPermissionRequest: bad address'
      end
      bupm = o['base_units_per_minor']
      if !test?(DEC, bupm) || bupm == '0'
        raise RangeError, 'grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string'
      end

      chain = o['chain_id']
      raise TypeError, 'grantToPermissionRequest: chain_id must be an Integer' unless chain.is_a?(Integer)
      raise RangeError, 'grantToPermissionRequest: bad chain' if chain <= 0

      allowance = hex(Js.bigint(cap) * Js.bigint(bupm))
      adj = o['is_adjustment_allowed'].nil? ? true : o['is_adjustment_allowed']
      req = { 'chainId' => hex(chain) }
      req['from'] = o['from'] if o.key?('from')
      req['to'] = o['session_account']
      req['permission'] = if o.key?('token_address')
                            { 'type' => 'erc20-token-allowance', 'isAdjustmentAllowed' => adj,
                              'data' => { 'tokenAddress' => o['token_address'], 'allowance' => allowance } }
                          else
                            { 'type' => 'native-token-allowance', 'isAdjustmentAllowed' => adj, 'data' => { 'allowance' => allowance } }
                          end
      req['rules'] = [{ 'type' => 'expiry', 'data' => { 'timestamp' => exp } }]
      req
    end

    # wallet_getSupportedExecutionPermissions result filtered to what the request could use. Total (false on anything odd).
    def supports_request(supported, req)
      type = Js.get(Js.get(req, 'permission'), 'type')
      raise TypeError, 'supported is null' if supported.nil?

      s = supported.is_a?(Hash) ? supported[Js.string(type)] : nil
      return false if s.nil?

      ids = Js.get(s, 'chainIds')
      return false unless ids.is_a?(Array) && ids.map { |c| Js.lower(c) }.include?(Js.lower(Js.get(req, 'chainId')))

      rt = Js.get(s, 'ruleTypes')
      rt = Js.get(s, 'rulesTypes') if rt.nil? # the draft spells both
      rules = Js.get(req, 'rules')
      rules = [] if rules.nil?
      raise TypeError, 'rules.every is not a function' unless rules.is_a?(Array)

      rules.all? { |r| rt.is_a?(Array) && rt.include?(Js.get(r, 'type')) }
    rescue StandardError
      false
    end

    def revoke_params(context) = { 'permissionContext' => context }

    # nil when the granted permission is within the request and the grant, else the reason. Options: allowed_managers
    # (delegation managers trusted for this chain, case-insensitive), context_owner (callable(context) -> grant digest or nil).
    def verify_granted_permission(g, sent, got, o)
      r = got
      return 'response_malformed' unless r.is_a?(Hash) && (r['permission'].is_a?(Hash) || r['permission'].is_a?(Array))

      perm = r['permission']
      ctx = r['context']
      return 'context_malformed' unless ctx.is_a?(String) && ctx.match?(CONTEXT)

      owner = o['context_owner']&.call(ctx)
      return 'context_bound_to_other_grant' if !owner.nil? && owner != Js.get(g, 'grantDigest')

      mgr = r['delegationManager']
      allowed = o['allowed_managers']
      raise TypeError, 'allowed_managers must be an array' unless !(mgr.is_a?(String) && mgr.match?(HEX_ADDR)) || allowed.is_a?(Array)
      unless mgr.is_a?(String) && mgr.match?(HEX_ADDR) && allowed.map { |a| Js.lower(a) }.include?(mgr.downcase)
        return 'delegation_manager_not_allowed'
      end
      return 'chain_mismatch' if Js.lower(Js.string(r['chainId'])) != Js.lower(Js.get(sent, 'chainId'))
      return 'recipient_mismatch' if Js.lower(Js.string(r['to'])) != Js.lower(Js.get(sent, 'to'))
      return 'from_mismatch' if sent.key?('from') && Js.lower(Js.string(r['from'])) != Js.lower(sent['from'])

      pt = Js.get(perm, 'type')
      spt = Js.get(Js.get(sent, 'permission'), 'type')
      return 'permission_type_mismatch' if pt != spt || !%w[native-token-allowance erc20-token-allowance].include?(pt)

      d = Js.get(perm, 'data')
      sd = Js.get(Js.get(sent, 'permission'), 'data')
      tok = Js.get(d, 'tokenAddress')
      stok = Js.get(sd, 'tokenAddress')
      return 'token_mismatch' if Js.string(tok.nil? ? '' : tok).downcase != Js.string(stok.nil? ? '' : stok).downcase

      amt = Js.get(d, 'allowance')
      return 'amount_malformed' unless amt.is_a?(String) && amt.match?(HEX_QTY)
      return 'amount_widened' if Js.bigint(amt) > Js.bigint(Js.get(sd, 'allowance'))

      ra = perm.is_a?(Hash) ? perm['isAdjustmentAllowed'] : nil
      return 'adjustment_widened' if ra != Js.get(sent['permission'], 'isAdjustmentAllowed') && ra == true
      return 'expiry_missing' unless r['rules'].is_a?(Array)

      expiry = nil
      r['rules'].each do |rule|
        return 'unknown_rule_type' unless (rule.is_a?(Hash) ? rule['type'] : nil) == 'expiry'
        return 'duplicate_expiry' unless expiry.nil?

        expiry = Js.get(rule['data'], 'timestamp')
        return 'expiry_malformed' if !Js.safe_integer?(expiry) || Js.neg_zero?(expiry)
      end
      return 'expiry_missing' if expiry.nil?

      ge = Js.get(g, 'expiresAtSec')
      return 'expiry_extended' unless Js.num?(ge) && Js.safe_integer?(ge) && expiry <= ge # a grant expiry that is not a finite integer bounds nothing

      nil
    rescue StandardError
      'response_malformed'
    end

    def grant_digest_of(grant) = AtlasPca.hash_canonical(grant)
  end
end
