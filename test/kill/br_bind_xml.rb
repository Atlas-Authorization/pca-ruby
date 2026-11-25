# frozen_string_literal: true
# missing-context.ts bindContext (08f482520): a bound top-level env / subject / action that is not an object is never replaced.
# NVIDIA RIM XML character references: digits only (a sign or a space is refused), leading zeros accepted, and the code point
# must be an XML 1.0 Char (no NUL, surrogate or overflow).
module MutationKill
  t('bind_context: a bound non-object env, subject or action blocks a supplied path below it (a conflict, the bound value stays)') do
    sup = { 'env' => { 'region' => 'eu' }, 'subject' => { 'id' => 'u' }, 'action' => { 'params' => { 'amount' => 5 } } }
    [['env', 'x', 'env.region'], ['env', [1], 'env.region'], ['env', nil, 'env.region'], ['subject', 7, 'subject.id'],
     ['action', nil, 'action.params.amount'], ['action', 'x', 'action.params.amount']].all? do |k, v, path|
      r = AtlasPca.bind_context({ k => v }, sup, {})
      r['context'][k] == v && r['context'].key?(k) && r['conflicts'].include?(path)
    end
  end

  t('xml: character references take digits only, leading zeros included, and must name an XML Char') do
    x = AtlasPca::Attest::Xml
    refused = lambda do |r|
      x.unescape(r, false)
      false
    rescue AtlasPca::Attest::XmlError
      true
    end
    x.unescape('&#65;&#000065;&#x41;&#x0041;&#9;&#x10FFFF;', false) == "AAAA\t\u{10FFFF}" &&
      %w[&#+65; &#-65; &#x+41; &#\ 65; &#99999999999; &#x110000; &#0; &#55296; &#xD800; &#65534; &#; &#x;].all?(&refused)
  end
end

module MutationKill
  t('verify_pcactn: a fault in the last step after every core check passed denies (pcactn.ts:843, seam)') do
    i = Intent
    g = i.grant
    p = i.pcactn(g)
    ok = i.verify(p, g)
    late = Seam.with(AtlasPca, { decide_fresh_at: ->(*) { raise 'seam fault' } }) { i.verify(p, g) }
    v2 = Seam.with(AtlasPca::IntentV2, { decide_intent_v2: ->(*) { raise 'seam fault' } }) { i.verify(p, g) }
    ok.allow == true && [late, v2].all? { |v| v.allow == false && v.checks == { 'wire' => false } && v.reason == 'wire: malformed input (RuntimeError)' }
  end
end
