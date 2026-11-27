# frozen_string_literal: true

# The `pca_grant` OAuth authorization-details type (RFC 9396): validation and the resource-server presentation check. The type
# is a pointer to a PCA grant, not authority: a verified per-action PCActn is still required. Every function is total.
# Results: validate -> nil (accepted) or a code; parse -> [details, nil] or [nil, code]; check -> [index, nil] or [nil, code].
# Hashes use String keys.
module AtlasPca
  PCA_GRANT_TYPE = 'pca_grant'
  PCA_GRANT_DOMAIN = 'atlas-pca/pca-grant-chain/v1'
  PCA_GRANT_MEMBERS = %w[type chain_digest chain_len chain_ref bundle_revision locations].freeze
  PCA_GRANT_REFUSED = %w[actions datatypes identifier privileges].freeze

  module_function

  # https://, printable ASCII without '#' or '\', at most 2048 characters, non-empty authority (to the first '/' or '?') without '@'.
  def pca_grant_https_url?(u)
    return false unless u.is_a?(String) && u.bytesize <= 2048 && u.start_with?('https://')
    return false if u.bytes.any? { |c| c < 0x21 || c > 0x7e || c == 0x23 || c == 0x5c }

    rest = u[8..]
    cut = rest.index(%r{[/?]})
    authority = cut ? rest[0, cut] : rest
    !authority.empty? && !authority.include?('@')
  end

  def pca_grant_chain_digest(ids)
    hash_canonical({ 'd' => PCA_GRANT_DOMAIN, 'ids' => ids })
  end

  # nil when accepted, else the refusal code.
  def validate_pca_grant_detail(x)
    return 'bad_entry' unless x.is_a?(Hash)
    return 'bad_type' unless x['type'] == PCA_GRANT_TYPE

    x.each_key do |k|
      return 'refused_member' if PCA_GRANT_REFUSED.include?(k)
      return 'unknown_member' unless PCA_GRANT_MEMBERS.include?(k)
    end
    d = x['chain_digest']
    return 'bad_chain_digest' unless d.is_a?(String) && !b64d(d, 32).nil?

    n = x['chain_len']
    return 'bad_chain_len' unless n.is_a?(Integer) && n >= 1 && n <= 16
    return 'bad_chain_ref' if x.key?('chain_ref') && !pca_grant_https_url?(x['chain_ref'])
    return 'bad_bundle_revision' if x.key?('bundle_revision') && !k3_int?(x['bundle_revision'])

    if x.key?('locations')
      l = x['locations']
      return 'bad_locations' unless l.is_a?(Array) && !l.empty? && l.length <= 8 && l.all? { |u| pca_grant_https_url?(u) }
    end
    nil
  end

  def parse_pca_grant_details(arr)
    return [nil, 'not_an_array'] unless arr.is_a?(Array)
    return [nil, 'too_many_details'] if arr.length > 16

    out = []
    arr.each do |e|
      return [nil, 'bad_entry'] unless e.is_a?(Hash) && e['type'].is_a?(String)
      next unless e['type'] == PCA_GRANT_TYPE

      code = validate_pca_grant_detail(e)
      return [nil, code] if code

      out << e
    end
    [out, nil]
  end

  # Allow only with a verified per-action proof (exactly true) and a detail naming a prefix of the presented chain (and this resource).
  def check_pca_grant_presentation(details, resource, chain_ids, proof_verified)
    return [nil, 'no_detail'] if details.empty?
    return [nil, 'proof_required'] unless proof_verified == true

    reason = 'chain_mismatch'
    details.each_with_index do |d, i|
      n = d['chain_len']
      next if chain_ids.length < n || pca_grant_chain_digest(chain_ids[0, n]) != d['chain_digest']

      loc = d['locations']
      if loc && !loc.include?(resource)
        reason = 'wrong_location'
        next
      end
      return [i, nil]
    end
    [nil, reason]
  end
end
