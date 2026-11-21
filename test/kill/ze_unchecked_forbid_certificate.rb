# frozen_string_literal: true

# ze: authorize_unchecked called with its trailing positional arguments omitted: an omitted forbid_certificate is "no certificate"
# (nil), never a value that is merely falsy. Reuses the C06 and F06 helpers; AtlasPca is resolved at call time.

module MutationKill
  t('ze authorize_unchecked: an omitted forbid_certificate is no certificate when the forbid policy requires one') do
    next true if (mf = ENV['MUT_FILE']) && !mf.empty? && mf != 'authorize.rb'

    c = C06.base
    s = c['steps'][0]
    permit = F06.clause('p', 'permit')
    need = F06.forbid([permit], 'requireCertificate' => true)
    # positional arguments up to and including forbid; forbid_certificate and contracts are omitted
    upto_forbid = [s['pcactn'], s['operation'], C06.aud, ->(_r) { c['grant'] }, AtlasPca::MemoryStateStore.new, ->(_p, _g) { false }, C06::NOW,
                   'single-step', nil, nil, nil, nil, nil] + Array.new(9) + [false] + Array.new(12) + [false] + Array.new(8) + [need]
    r = AtlasPca.authorize_unchecked(*upto_forbid)
    msg = 'forbid: the call carries no certificate (fail closed)'
    C06.ck('omitted', [r.allow, r.checks['forbid'], r.reasons.include?(msg)], [false, 'fail', true])
  end
end
