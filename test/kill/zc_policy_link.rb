# frozen_string_literal: true

# zc policy link: verify_linked_policy against the shared policy-link vectors (a real signed template and its registry).
module MutationKill
  module ZCLink
    module_function

    PATH = File.expand_path('../../conformance/policy-link-vectors.json', __dir__)

    # a fresh deep copy each call: the first "resolve" vector (a reference that resolves, its registry and the instantiation)
    def fixture
      @doc ||= AtlasPca.parse_json(File.read(PATH, encoding: 'UTF-8'), loose: true)
      Marshal.load(Marshal.dump(@doc['resolve'][0]))
    end
  end

  t('zc policy link: verify_linked_policy accepts exactly the policy the reference denotes') do
    next true unless ZC.gate?('policy_link.rb')

    fx = ZCLink.fixture
    ref = fx['ref']
    reg = fx['registry']
    pol = fx['expect']['policy']
    env = ->(over = {}) { { 'template_ref' => ref, 'predicates' => pol['predicates'], 'caveats' => pol['caveats'] }.merge(over) }
    differs = { 'ok' => false, 'reason' => 'grant policy differs from the linked template instantiation' }
    ZC.eq('fixture resolves', fx['expect']['ok'], true) && !pol['caveats'].empty? &&
      ZC.eq('no template_ref', AtlasPca.verify_linked_policy({ 'predicates' => [] }, reg), { 'ok' => true }) &&
      ZC.eq('a template_ref that is not an object', AtlasPca.verify_linked_policy({ 'template_ref' => nil }, reg),
            { 'ok' => false, 'reason' => 'template_ref must be an object' }) &&
      ZC.eq('a reference that does not resolve', AtlasPca.verify_linked_policy(env.call({ 'template_ref' => ref.merge('version_digest' => 'zzz') }), reg),
            { 'ok' => false, 'reason' => 'template version is not in the registry' }) &&
      ZC.eq('matches', AtlasPca.verify_linked_policy(env.call, reg), { 'ok' => true, 'template' => ref['version_digest'] }) &&
      ZC.eq('other predicates', AtlasPca.verify_linked_policy(env.call({ 'predicates' => [] }), reg), differs) &&
      ZC.eq('other caveats', AtlasPca.verify_linked_policy(env.call({ 'caveats' => [] }), reg), differs) &&
      ZC.eq('no caveats', AtlasPca.verify_linked_policy(env.call({ 'caveats' => nil }), reg), differs) &&
      ZC.eq('extra caveat', AtlasPca.verify_linked_policy(env.call({ 'caveats' => pol['caveats'] + [{ 'type' => 'rate', 'max' => 1, 'per_secs' => 1 }] }), reg), differs)
  end

  t('zc policy link: verify_linked_policy is total') do
    next true unless ZC.gate?('policy_link.rb')

    fault = { 'ok' => false, 'reason' => 'link verification error (fail closed)' }
    ZC.eq('nil envelope', AtlasPca.verify_linked_policy(nil, {}), fault) && ZC.eq('int envelope', AtlasPca.verify_linked_policy(5, {}), fault) &&
      ZC.eq('array envelope', AtlasPca.verify_linked_policy([], {}), fault)
  end
end
