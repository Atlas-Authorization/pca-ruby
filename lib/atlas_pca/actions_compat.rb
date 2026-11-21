# frozen_string_literal: true

# Migration shims between the old, disagreeing action vocabularies and the one ActionDef vocabulary (native port of compat.ts of
# the TypeScript reference @atlasauth/pca-actions). Every conversion is total and fails closed.
require_relative 'actions'
require_relative 'siem'

module AtlasPca
  module ActionsCompat
    A = AtlasPca::Actions
    U16 = AtlasPca::Siem::U16

    READ_RE = /\A(?:read|get|list|view|search|fetch|head)(?:_|\z)/
    DELETE_RE = /(?:\A|_)(?:delete|remove|destroy|drop|purge)(?:_|\z)/
    SEND_RE = /(?:\A|_)(?:send|post|publish|notify|email|sms)(?:_|\z)/

    module_function

    def normalize_reversibility(x)
      return 'irreversible' unless x.is_a?(String)
      return 'reversible' if %w[reversible read].include?(x)
      return 'rate_limited' if %w[rate_limited costly].include?(x)

      'irreversible'
    end

    def legacy_operations_class(r) = r == 'rate_limited' ? 'costly' : r

    def max_rev_of(a, b) = A::REV_RANK.fetch(a) >= A::REV_RANK.fetch(b) ? a : b

    def unit_tag_of(u)
      return { 'kind' => u['kind'] } if u['kind'] != 'money'
      return nil unless u['ccy'].is_a?(String)

      out = { 'kind' => 'money', 'currency' => u['ccy'] }
      out['exponent'] = u['exp'] if u.key?('exp')
      out
    end

    def js_round(v)
      return v unless v.finite? # Math.round leaves NaN and the infinities as they are

      f = v.floor
      v - f >= 0.5 ? f + 1 : f
    end

    def ppm_of(x)
      finite = (x.is_a?(Integer) || (x.is_a?(Float) && x.finite?))
      [A::PPM_MAX, [0, js_round((finite ? x : 1) * 1_000_000)].max].min
    end

    def blast_of_float(x)
      ppm = ppm_of(x)
      { 'radius' => A::BLAST_RADII.find { |r| A::BLAST_PPM[r] >= ppm } || 'global', 'ppm' => ppm }
    end

    def blast_exact_of_float(x)
      ppm = ppm_of(x)
      { 'radius' => A::BLAST_RADII.reverse.find { |r| A::BLAST_PPM[r] <= ppm } || 'one', 'ppm' => ppm }
    end

    def from_catalog_spec(s, o = nil)
      o ||= {}
      has_amount = s.key?('amountField')
      effects = []
      effects << 'pay' if has_amount
      effects << 'read' if READ_RE.match?(s['action'])
      effects << 'delete' if DELETE_RE.match?(s['action'])
      effects << 'send' if SEND_RE.match?(s['action'])
      effects << 'update' if effects.empty?
      params = {}
      if has_amount
        params[s['amountField']] = {
          'type' => 'integer', 'role' => 'money.amount', 'min' => 0, 'max' => o['maxAmount'].nil? ? 100_000_000_000 : o['maxAmount'],
          'unit' => { 'kind' => 'money', 'ccy' => o['ccy'].nil? ? 'USD' : o['ccy'], 'exp' => o['exp'].nil? ? 2 : o['exp'] }
        }
        params['idempotency_key'] = { 'type' => 'string', 'max_len' => 128 }
      end
      b = blast_of_float(s['blastRadius'])
      wildcard = !s.key?('resource') || s['resource'] == '*'
      desc = s['description']
      title = U16.len(desc) > 120 ? "#{U16.slice(desc, 117)}..." : desc
      out = {
        'v' => 1, 'kind' => 'pca-action-def', 'verb' => s['verb'], 'title' => title, 'description' => desc, 'effects' => effects,
        'resource' => { 'type' => s['connector'], 'id' => wildcard ? '*' : { 'prefix' => '', 'class' => 'any_safe', 'len' => [1, 128] },
                        'scope' => wildcard ? 'set' : 'one' },
        'params' => params, 'reversibility' => normalize_reversibility(s['reversibility']), 'blast' => { 'radius' => b['radius'], 'ppm' => b['ppm'] }
      }
      out['idempotency'] = { 'mode' => 'key_param', 'param' => 'idempotency_key' } if has_amount
      out['review'] = { 'state' => 'authored' }
      out
    end

    def from_catalog(specs, o = nil) = specs.map { |s| from_catalog_spec(s, o) }
  end
end
