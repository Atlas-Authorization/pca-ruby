# frozen_string_literal: true

# e10: F10 - the stateful layer (packages/pca/conformance/stateful-vectors.json). Each sequence runs against ONE fresh state store:
# replay, counter ordering, revocation mid-sequence, trust-budget depletion, expiry and per-holder streams. The reference is TypeScript
# requirePCA (scripts/stateful-sequence.mjs); the Ruby counterpart is AtlasPca.authorize with the same store, risk inputs, plan and
# revocation set. A step passes when its failed checks (the ones the reference reports) equal the expected list and allow matches.

module MutationKill
  module E10
    module_function

    CONF = File.expand_path('../../conformance', __dir__)
    # the checks the reference reports; this SDK's pipeline has more (operation, provenance_flow, ...), which the vectors do not pin
    REFERENCE = %w[replay threshold revocation leaf_signature plan_inclusion validity].freeze

    def doc = (@doc ||= AtlasPca.parse_json(File.read(File.join(CONF, 'stateful-vectors.json'), encoding: 'UTF-8'), loose: true))

    def leaf_holder(pc) = pc['cap_chain'].last['holder']

    def run(seq)
      setup = seq['setup']
      grants = setup['grants'].to_h { |g| [g['id'], g] }
      revoked = (setup['revoked'] || []).dup
      store = AtlasPca::MemoryStateStore.new
      # the resource server's budget store: every holder stream the sequence touches starts with the initial trust budget
      if setup['initial_budget']
        seq['steps'].select { |s| s['op'] == 'present' }.each do |s|
          key = AtlasPca.state_key(s['pcactn']['grant_ref'], leaf_holder(s['pcactn']))
          store.budget_cas(key, nil, setup['initial_budget'].dup) if store.budget(key).nil?
        end
      end
      seq['steps'].map do |s|
        if s['op'] == 'revoke'
          revoked << s['id']
          next nil
        end
        pc = s['pcactn']
        op = { 'verb' => pc['action']['verb'], 'resource' => pc['action']['resource'], 'params' => s['params'] }
        r = AtlasPca.authorize(pc, operation: op, audience: setup['audience'], resolve_grant: ->(ref) { grants[ref] }, state_store: store,
                                   is_revoked: ->(p, _g) { (p['cap_chain'] || []).any? { |c| revoked.include?(c['id']) } }, now: s['now'],
                                   context: ->(_p) { { 'plan' => setup['plan_nodes'], 'plan_authorized' => true, 'risk' => setup['risk'].dup } },
                                   seed_budget: ->(_g, _n) {}, provenance: ProvHarness::OPTION)
        failed = r.failed_checks.map { |k| k == 'chain' ? 'cap_chain' : k }.select { |k| REFERENCE.include?(k) }
        [r.allow, failed]
      end
    end
  end

  t('e10 stateful vectors: replay, counters, revocation, trust budget, expiry, holder streams') do
    f = ENV['MUT_FILE']
    next true unless f.nil? || f.empty? || %w[authorize.rb risk.rb].include?(f)

    seqs = E10.doc['stateful']
    raise "sequences: #{seqs.length}" unless seqs.length >= 20

    seqs.all? do |seq|
      got = E10.run(seq)
      seq['steps'].each_with_index.all? do |s, i|
        next true unless s['op'] == 'present'

        want = [s['expect']['allow'], s['expect']['failed'].sort]
        (got[i] == want) || raise("#{seq['name']} step #{i}: got #{got[i].inspect}, want #{want.inspect}")
      end
    end
  end
end
