# frozen_string_literal: true

# Linked policy templates (security contract C-242, C-243). Port of packages/pca/src/policy-link.ts (the TypeScript is
# authoritative): template definitions, instantiation with closed slot domains, signed templates and tighten overlays, and
# resolution of a grant's `template_ref`. Total: anything malformed fails closed. Inputs are JSON values with String keys.
# Results are Hashes {'ok' => true, ...} / {'ok' => false, 'reason' => ...}.
module AtlasPca
  TEMPLATE_SIG_DOMAIN = "atlas-pca/policy-template/v1\0"
  TIGHTEN_SIG_DOMAIN = "atlas-pca/template-tighten/v1\0"
  MAX_TEMPLATE_SLOTS = 32
  MAX_SLOT_STRING = 256
  MAX_SLOT_SET = 64
  TEMPLATE_NAME_RE = /\A[a-z][a-z0-9_]{0,63}\z/
  TEMPLATE_NAME_SOURCE = '^[a-z][a-z0-9_]{0,63}$'

  class LinkRefusal < StandardError; end

  module_function

  def link_safe_int?(v) = decision_safe_int?(v)

  def link_message(domain, digest) = domain.b + sha(digest.b)

  def link_js_string(x)
    x.nil? ? 'null' : x.to_s
  end

  def link_scan(v, decl, used)
    case v
    when Array
      v.each { |x| (e = link_scan(x, decl, used)) && (return e) }
      nil
    when Hash
      bad = v.keys.find { |k| %w[__proto__ constructor prototype].include?(k) }
      return "body has the forbidden key '#{bad}'" if bad

      if v.key?('$slot')
        extra = v.keys.find { |k| !%w[$slot pre post].include?(k) }
        return "placeholder has unknown member '#{extra}'" if extra
        return "placeholder names undeclared slot '#{link_js_string(v['$slot'])}'" unless v['$slot'].is_a?(String) && decl.key?(v['$slot'])

        %w[pre post].each { |k| return "placeholder #{k} must be a string" if v.key?(k) && !v[k].is_a?(String) }
        used << v['$slot']
        return nil
      end
      v.each_value { |x| (e = link_scan(x, decl, used)) && (return e) }
      nil
    end
  end

  def template_def_error(d)
    return 'template must be an object' unless d.is_a?(Hash)
    return 'template v / kind mismatch' unless d['v'] == 1 && d['kind'] == 'pca-policy-template'
    return "template id must match #{TEMPLATE_NAME_SOURCE}" unless d['id'].is_a?(String) && TEMPLATE_NAME_RE.match?(d['id'])
    return 'template version must be a string of 1..64 characters' unless d['version'].is_a?(String) && !d['version'].empty? && utf16_len(d['version']) <= 64
    return 'slots must be an object' unless d['slots'].is_a?(Hash)

    slots = d['slots']
    return "more than #{MAX_TEMPLATE_SLOTS} slots" if slots.length > MAX_TEMPLATE_SLOTS

    slots.each do |n, s|
      return "slot name '#{n}' must match #{TEMPLATE_NAME_SOURCE}" unless TEMPLATE_NAME_RE.match?(n)
      return "slot '#{n}' must be an object" unless s.is_a?(Hash)
      return "slot '#{n}'.type must be string, integer or set" unless %w[string integer set].include?(s['type'])
      return "set slot '#{n}' needs a closed values list" if s['type'] == 'set' && !s['values'].is_a?(Array)
      if s.key?('values') && (!s['values'].is_a?(Array) || s['values'].length > MAX_SLOT_SET || s['values'].any? { |x| !x.is_a?(String) })
        return "slot '#{n}'.values must be a list of strings"
      end
      next unless s['type'] == 'integer'

      %w[min max].each { |k| return "slot '#{n}'.#{k} must be a safe integer" if s.key?(k) && !link_safe_int?(s[k]) }
    end
    body = d['body']
    return 'body.predicates must be an array' unless body.is_a?(Hash) && body['predicates'].is_a?(Array)
    return 'body.caveats must be an array' if body.key?('caveats') && !body['caveats'].is_a?(Array)

    used = []
    e = link_scan(body, slots, used)
    return e if e

    slots.each_key { |n| return "slot '#{n}' is declared but never used" unless used.include?(n) }
    nil
  end

  def template_digest(d) = hash_canonical(d)

  def link_signed_ok?(signer, domain, digest, sig)
    pk = b64d(signer, 32)
    sg = sig.is_a?(String) ? b64d(sig, 64) : nil
    !pk.nil? && !sg.nil? && Ed25519Strict.verify(pk, link_message(domain, digest), sg)
  end

  def verify_template(t, trusted)
    t = {} unless t.is_a?(Hash)
    e = template_def_error(t['def'])
    return { 'ok' => false, 'reason' => e } if e
    return { 'ok' => false, 'reason' => 'template signer is not trusted' } unless t['signer'].is_a?(String) && Array(trusted).include?(t['signer'])
    return { 'ok' => false, 'reason' => 'bad template signature' } unless link_signed_ok?(t['signer'], TEMPLATE_SIG_DOMAIN, template_digest(t['def']), t['sig'])

    { 'ok' => true }
  rescue StandardError
    { 'ok' => false, 'reason' => 'template verification error (fail closed)' }
  end

  def tighten_overlay_error(o)
    return 'overlay must be an object' unless o.is_a?(Hash)
    return 'overlay v / kind mismatch' unless o['v'] == 1 && o['kind'] == 'pca-template-tighten'

    o.each_key do |k|
      return "overlay has unknown member '#{k}' (an overlay can only add where conditions and caveats)" unless %w[v kind template_id version_digest add_where add_caveats].include?(k)
    end
    return 'overlay template_id invalid' unless o['template_id'].is_a?(String) && TEMPLATE_NAME_RE.match?(o['template_id'])
    return 'overlay version_digest invalid' unless o['version_digest'].is_a?(String) && !o['version_digest'].empty?
    return 'overlay add_where must be a list of conditions' if o.key?('add_where') && (!o['add_where'].is_a?(Array) || o['add_where'].any? { |c| !c.is_a?(Hash) })
    if o.key?('add_caveats') && (!o['add_caveats'].is_a?(Array) || o['add_caveats'].any? { |c| !c.is_a?(Hash) || !c['type'].is_a?(String) })
      return 'overlay add_caveats must be a list of caveats'
    end

    nil
  end

  def verify_tighten(t, trusted)
    t = {} unless t.is_a?(Hash)
    e = tighten_overlay_error(t['overlay'])
    return { 'ok' => false, 'reason' => e } if e
    return { 'ok' => false, 'reason' => 'overlay signer is not trusted' } unless t['signer'].is_a?(String) && Array(trusted).include?(t['signer'])
    return { 'ok' => false, 'reason' => 'bad overlay signature' } unless link_signed_ok?(t['signer'], TIGHTEN_SIG_DOMAIN, hash_canonical(t['overlay']), t['sig'])

    { 'ok' => true }
  rescue StandardError
    { 'ok' => false, 'reason' => 'overlay verification error (fail closed)' }
  end

  def link_slot_value_error(name, d, v)
    case d['type']
    when 'string'
      return "slot '#{name}' must be a string of 1..#{MAX_SLOT_STRING} characters" unless v.is_a?(String) && !v.empty? && utf16_len(v) <= MAX_SLOT_STRING
      return "slot '#{name}' is outside its closed value set" if d['values'] && !d['values'].include?(v)
    when 'integer'
      return "slot '#{name}' must be a safe integer" unless link_safe_int?(v)
      return "slot '#{name}' is below its minimum" if d.key?('min') && v < d['min']
      return "slot '#{name}' is above its maximum" if d.key?('max') && v > d['max']
    else
      return "slot '#{name}' must be a non-empty list of strings" unless v.is_a?(Array) && !v.empty? && v.length <= MAX_SLOT_SET && v.all? { |x| x.is_a?(String) }
      return "slot '#{name}' has duplicate members" if v.uniq.length != v.length
      return "slot '#{name}' has a member outside its closed set" if d['values'] && v.any? { |x| !d['values'].include?(x) }
    end
    nil
  end

  def link_matcher_safe(name, val)
    Array(val.is_a?(Array) ? val : [val]).each do |x|
      raise LinkRefusal, "slot '#{name}' would inject a wildcard or regex matcher into a verb or resource" if x.is_a?(String) && (x.include?('*') || x.start_with?('re:'))
    end
  end

  def link_fill(v, slots, key = nil)
    case v
    when Array then v.map { |x| link_fill(x, slots, key) }
    when Hash
      if v.key?('$slot')
        name = v['$slot']
        val = slots[name]
        link_matcher_safe(name, val) if %w[verb resource].include?(key)
        pre = v['pre'].is_a?(String) ? v['pre'] : ''
        post = v['post'].is_a?(String) ? v['post'] : ''
        return val if pre.empty? && post.empty?
        raise LinkRefusal, "slot '#{name}' cannot be spliced into a string (wildcard or non-string)" if !val.is_a?(String) || val.include?('*') || val.include?("\0")

        out = pre + val + post
        raise LinkRefusal, "slot '#{name}' would inject a regex matcher" if pre.empty? && out.start_with?('re:')

        out
      else
        v.to_h { |k, x| [k, link_fill(x, slots, k)] }
      end
    else v
    end
  end

  def instantiate_template(d, slots)
    e = template_def_error(d)
    return { 'ok' => false, 'reason' => e } if e
    return { 'ok' => false, 'reason' => 'slots must be an object' } unless slots.is_a?(Hash)

    slots.each_key { |k| return { 'ok' => false, 'reason' => "slot '#{k}' is not declared by the template" } unless d['slots'].key?(k) }
    d['slots'].each do |n, decl|
      return { 'ok' => false, 'reason' => "slot '#{n}' is not filled" } unless slots.key?(n)

      se = link_slot_value_error(n, decl, slots[n])
      return { 'ok' => false, 'reason' => se } if se
    end
    pol = link_fill(d['body'], slots)
    { 'ok' => true, 'policy' => { 'predicates' => pol['predicates'], 'caveats' => pol['caveats'] || [] } }
  rescue LinkRefusal => e
    { 'ok' => false, 'reason' => e.message }
  rescue StandardError
    { 'ok' => false, 'reason' => 'instantiation error (fail closed)' }
  end

  def template_ref_error(r)
    return 'template_ref must be an object' unless r.is_a?(Hash)

    r.each_key { |k| return "template_ref has unknown member '#{k}'" unless %w[template_id version_digest slots bind_params_digest].include?(k) }
    return 'template_ref.template_id invalid' unless r['template_id'].is_a?(String) && TEMPLATE_NAME_RE.match?(r['template_id'])
    return 'template_ref.version_digest invalid' unless r['version_digest'].is_a?(String) && !r['version_digest'].empty? && r['version_digest'].length <= 128
    return 'template_ref has both slots and bind_params_digest' if r.key?('slots') && r.key?('bind_params_digest')

    if r.key?('bind_params_digest')
      d = r['bind_params_digest']
      return d.is_a?(String) && !d.empty? && d.length <= 128 ? nil : 'template_ref.bind_params_digest invalid'
    end
    return 'template_ref.slots must be an object' unless r['slots'].is_a?(Hash)

    nil
  end

  def resolve_link(ref, reg)
    re = template_ref_error(ref)
    return { 'ok' => false, 'reason' => re } if re

    t = reg['templates'][ref['version_digest']]
    return { 'ok' => false, 'reason' => 'template version is not in the registry' } if t.nil?

    v = verify_template(t, reg['trusted'])
    return { 'ok' => false, 'reason' => v['reason'] || 'template refused' } unless v['ok']
    return { 'ok' => false, 'reason' => 'registry entry does not match its digest' } unless template_digest(t['def']) == ref['version_digest']
    return { 'ok' => false, 'reason' => 'template id does not match the reference' } unless t['def']['id'] == ref['template_id']

    slots = ref['slots']
    if ref.key?('bind_params_digest')
      params = reg['params']
      bound = params.is_a?(Hash) ? params[ref['bind_params_digest']] : nil
      return { 'ok' => false, 'reason' => 'parameter object is not available' } unless bound.is_a?(Hash)
      return { 'ok' => false, 'reason' => 'parameter object does not match bind_params_digest' } unless hash_canonical(bound) == ref['bind_params_digest']

      slots = bound
    end
    inst = instantiate_template(t['def'], slots)
    return inst unless inst['ok']

    predicates = inst['policy']['predicates']
    caveats = inst['policy']['caveats']
    applied = 0
    (reg['overlays'] || []).each do |o|
      ov = o.is_a?(Hash) ? o['overlay'] : nil
      next unless ov.is_a?(Hash) && ov['version_digest'] == ref['version_digest'] && ov['template_id'] == ref['template_id']

      vv = verify_tighten(o, reg['trusted'])
      return { 'ok' => false, 'reason' => vv['reason'] || 'overlay refused' } unless vv['ok']

      add = ov['add_where'] || []
      predicates = predicates.map { |p| p.merge('where' => (p['where'] || []) + add) }
      caveats += (ov['add_caveats'] || [])
      applied += 1
    end
    { 'ok' => true, 'policy' => { 'predicates' => predicates, 'caveats' => caveats }, 'overlays' => applied }
  rescue StandardError
    { 'ok' => false, 'reason' => 'link resolution error (fail closed)' }
  end
end
