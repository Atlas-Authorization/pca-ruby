# frozen_string_literal: true

# What you see is what you sign (track K7): a port of packages/pca/src/approval-render.ts (render shape, H(R), the approval
# challenge, the speakable match code) and packages/pca-actions/src/approval-render.ts + approval-profiles.ts (the canonical render of an
# action, the PSD2 RTS Art. 5 linking view, the batch commitment). A render that cannot be made completely raises
# AtlasPca::Actions::ActionKitError rather than returning something partial.
require 'digest'

module AtlasPca
  APPROVAL_RENDER_DOMAIN = 'atlas-pca/approval-render/v1'
  APPROVAL_CHALLENGE_DOMAIN = "atlas-pca/approval-challenge/v1\x00"
  APPROVAL_BATCH_DOMAIN = 'atlas-pca/approval-batch/v1'
  APPROVAL_ITEM_DOMAIN = 'atlas-pca/approval-batch-item/v1'
  APPROVAL_PAYEE_DOMAIN = 'atlas-pca/approval-payee/v1'
  MAX_RENDER_FIELDS = 64
  RENDER_MAX_PATH_DEPTH = 3
  BINDING_WORDS = [
    'able', 'acid', 'aged', 'also', 'area', 'army', 'atom', 'aunt',
    'away', 'baby', 'back', 'ball', 'band', 'bank', 'base', 'bath',
    'bear', 'beat', 'beef', 'bell', 'belt', 'bend', 'bird', 'blue',
    'boat', 'body', 'bold', 'bone', 'book', 'boot', 'born', 'both',
    'bowl', 'bulb', 'burn', 'bush', 'busy', 'cafe', 'cake', 'calm',
    'camp', 'card', 'care', 'cart', 'case', 'cash', 'cast', 'cave',
    'cell', 'chat', 'chef', 'chip', 'city', 'clay', 'clip', 'club',
    'coal', 'coat', 'code', 'coin', 'cold', 'cook', 'cool', 'cope',
    'copy', 'cord', 'core', 'cost', 'crew', 'crop', 'dark', 'data',
    'date', 'dawn', 'deal', 'dear', 'deck', 'deep', 'deer', 'desk',
    'dial', 'dice', 'diet', 'dish', 'dive', 'door', 'dose', 'down',
    'draw', 'drop', 'drum', 'duck', 'dust', 'duty', 'each', 'earn',
    'east', 'easy', 'edge', 'echo', 'else', 'even', 'ever', 'exit',
    'face', 'fact', 'fair', 'fall', 'farm', 'fast', 'fate', 'fern',
    'file', 'fill', 'film', 'find', 'fine', 'fire', 'firm', 'fish',
    'five', 'flag', 'flat', 'flow', 'foam', 'fold', 'folk', 'food',
    'foot', 'fork', 'form', 'fort', 'four', 'free', 'frog', 'fuel',
    'full', 'fund', 'gain', 'game', 'gate', 'gear', 'gift', 'girl',
    'glad', 'glow', 'goat', 'gold', 'golf', 'good', 'grab', 'gray',
    'grid', 'grip', 'grow', 'gulf', 'hair', 'half', 'hall', 'hand',
    'hard', 'harp', 'hawk', 'head', 'heat', 'help', 'herb', 'hill',
    'hint', 'hold', 'hole', 'home', 'hood', 'hook', 'hope', 'horn',
    'host', 'hour', 'huge', 'hunt', 'idea', 'inch', 'iron', 'isle',
    'item', 'jade', 'jazz', 'join', 'joke', 'jump', 'jury', 'just',
    'keen', 'keep', 'kind', 'king', 'kite', 'knee', 'knot', 'lake',
    'lamp', 'land', 'lane', 'last', 'late', 'lawn', 'lead', 'leaf',
    'lean', 'left', 'lens', 'less', 'lift', 'lime', 'line', 'link',
    'lion', 'list', 'live', 'load', 'loan', 'lock', 'logo', 'long',
    'loop', 'lord', 'loud', 'love', 'luck', 'lung', 'made', 'mail',
    'main', 'mask', 'mass', 'mate', 'meal', 'melt', 'menu', 'mild',
    'milk', 'mind', 'mint', 'mole', 'moon', 'more', 'moss', 'move',
    'much', 'nail', 'navy', 'neat', 'neck', 'nest', 'news', 'nice'
  ].freeze

  module_function

  def render_digest?(v) = v.is_a?(String) && !b64d(v, 32).nil?

  def render_safe_int?(v)
    return false if v == true || v == false

    (v.is_a?(Integer) || (v.is_a?(Float) && v.finite? && v == v.floor && !(v.zero? && 1.0 / v < 0))) && v.abs <= 9_007_199_254_740_991
  end

  def render_bounded?(v, n) = v.is_a?(String) && !v.empty? && v.bytesize <= n

  def render_closed(o, required, optional = [])
    o.each_key { |k| return "unknown member '#{k}'" unless required.include?(k) || optional.include?(k) }
    required.each { |k| return "missing member '#{k}'" unless o.key?(k) }
    nil
  end

  def render_u16(s) = s.dup.force_encoding(Encoding::UTF_8).scrub("\uFFFD").encode('UTF-16BE').b

  # nil if `r` is a well-formed render (closed members, sorted unique ids, bounded), else the reason.
  def approval_render_shape_error(r)
    return 'render must be an object' unless r.is_a?(Hash)

    e = render_closed(r, %w[v kind verb def_digest unreviewed fields])
    return e if e
    return 'not a pca-approval-render v1' unless render_safe_int?(r['v']) && r['v'] == 1 && r['kind'] == 'pca-approval-render'
    return 'verb must be a bounded string' unless render_bounded?(r['verb'], 128)
    return 'def_digest must be canonical base64url (32 bytes)' unless render_digest?(r['def_digest'])
    return 'unreviewed must be a boolean' unless [true, false].include?(r['unreviewed'])
    return "fields must be an array of at most #{MAX_RENDER_FIELDS}" unless r['fields'].is_a?(Array) && r['fields'].length <= MAX_RENDER_FIELDS

    prev = nil
    r['fields'].each do |f|
      return 'a field must be an object' unless f.is_a?(Hash)

      e = render_closed(f, %w[id class value], %w[unit])
      return e if e
      return 'field id and class must be bounded strings' unless render_bounded?(f['id'], 192) && render_bounded?(f['class'], 128)
      return 'fields must be sorted by id and unique' if !prev.nil? && (render_u16(prev) <=> render_u16(f['id'])) >= 0

      prev = f['id']
      next unless f.key?('unit')

      u = f['unit']
      return 'unit must be an object' unless u.is_a?(Hash)

      if u['kind'] == 'money'
        unless render_closed(u, %w[kind ccy exp]).nil? && render_bounded?(u['ccy'], 16) && render_safe_int?(u['exp']) && u['exp'] >= 0 && u['exp'] <= 18
          return 'a money unit needs ccy and exp'
        end
      elsif !%w[count bytes duration ratio].include?(u['kind']) || !render_closed(u, %w[kind]).nil?
        return 'unknown unit'
      end
    end
    nil
  end

  # H(R). A malformed render raises (a digest is never made over a shapeless value).
  def approval_render_digest(render)
    e = approval_render_shape_error(render)
    raise ArgumentError, "approvalRenderDigest: #{e}" if e

    hash_canonical({ 'd' => APPROVAL_RENDER_DOMAIN, 'render' => render })
  end

  # b64u(SHA-256(domain || action_digest || H(R))); both digests must be canonical 32-byte values.
  def approval_challenge(action_digest, render_digest)
    a = action_digest.is_a?(String) ? b64d(action_digest, 32) : nil
    r = render_digest.is_a?(String) ? b64d(render_digest, 32) : nil
    raise ArgumentError, 'approvalChallenge: both digests must be canonical 32-byte values' if a.nil? || r.nil?

    b64e(Digest::SHA256.digest(APPROVAL_CHALLENGE_DOMAIN.b + a.b + r.b))
  end

  def binding_words(render_digest)
    r = render_digest.is_a?(String) ? b64d(render_digest, 32) : nil
    raise ArgumentError, 'bindingWords: render digest must be a canonical 32-byte value' if r.nil?

    r.bytes.first(6).map { |b| BINDING_WORDS[b] }.join('-')
  end

  # ---- the render ---------------------------------------------------------------------------------------------------------
  def render_error(code, msg) = raise(Actions::ActionKitError.new(code, msg))

  def render_flatten(params)
    out = {}
    walk = lambda do |prefix, depth, v|
      if v.is_a?(Hash) && depth < RENDER_MAX_PATH_DEPTH && !v.empty?
        v.each do |k, x|
          render_error('render_bad_params', "the parameter key '#{k}' contains a dot") if k.include?('.')
          walk.call(prefix.empty? ? k : "#{prefix}.#{k}", depth + 1, x)
        end
      else
        out[prefix] = v
      end
    end
    params.each do |k, v|
      render_error('render_bad_params', "the parameter key '#{k}' contains a dot") if k.include?('.')
      walk.call(k, 1, v)
    end
    out
  end

  def render_leaf?(v)
    case v
    when String then v.valid_encoding?
    when true, false then true
    when Array then v.all? { |x| render_leaf?(x) }
    else render_safe_int?(v)
    end
  end

  def render_value_ok?(type, v)
    case type
    when 'integer', 'duration' then render_safe_int?(v)
    when 'boolean' then [true, false].include?(v)
    when 'string', 'date', 'datetime', 'object_ref' then v.is_a?(String) && v.valid_encoding?
    when 'set', 'array' then v.is_a?(Array) && v.all? { |x| render_leaf?(x) }
    else false
    end
  end

  # The canonical approval render of `d` for `params`. `confirmed`: whether the definition carries a valid signed confirmation
  # (the caller decides, as for `effective`); an unconfirmed render carries unreviewed: true.
  def render_approval(d, params, confirmed = false)
    render_error('render_bad_params', 'params must be an object') unless params.is_a?(Hash)

    n = Actions.normalize(d)
    flat = render_flatten(params)
    flat.each_key { |k| render_error('render_undeclared_param', "'#{k}' is not a parameter of #{n['verb']}") unless n['params'].key?(k) }
    n['params'].each { |k, p| render_error('render_missing_param', "required parameter '#{k}' of #{n['verb']} is missing") if p['required'] && !flat.key?(k) }
    fields = flat.keys.sort_by { |k| render_u16(k) }.map do |id|
      p = n['params'][id]
      render_error('render_bad_value', "'#{id}' is not a #{p['type']} in the canonical domain") unless render_value_ok?(p['type'], flat[id])
      v = flat[id]
      v = v.to_i if v.is_a?(Float)
      f = { 'id' => id, 'class' => p.fetch('role', 'param'), 'value' => v }
      if (u = p['unit'])
        if u['kind'] == 'money'
          ccy = u['ccy'].is_a?(String) ? u['ccy'] : flat[u['ccy']['from']]
          render_error('render_unresolved_currency', "the currency of '#{id}' is not a string") unless ccy.is_a?(String) && !ccy.empty?
          f['unit'] = { 'kind' => 'money', 'ccy' => ccy, 'exp' => u['exp'] }
        else
          f['unit'] = { 'kind' => u['kind'] }
        end
      end
      f
    end
    { 'v' => 1, 'kind' => 'pca-approval-render', 'verb' => n['verb'], 'def_digest' => Actions.def_digest(d), 'unreviewed' => !confirmed, 'fields' => fields }
  end

  # ---- PSD2 RTS Art. 5 ----------------------------------------------------------------------------------------------------
  def psd2_unlinkable(msg) = render_error('psd2_unlinkable', msg)

  def psd2_linking(r)
    psd2_unlinkable('an unreviewed definition cannot be a payment approval') if r['unreviewed']
    amts = r['fields'].select { |f| f['class'] == 'money.amount' }
    psd2_unlinkable('a payment approval needs exactly one money.amount parameter') unless amts.length == 1
    a = amts[0]
    psd2_unlinkable('the money.amount parameter has no money unit') unless a['unit'].is_a?(Hash) && a['unit']['kind'] == 'money'
    psd2_unlinkable('the amount must be a non-negative integer in minor units') unless render_safe_int?(a['value']) && a['value'] >= 0
    payees = r['fields'].select { |f| f['class'] == 'party.payee' }
    psd2_unlinkable('a payment approval needs exactly one non-empty party.payee parameter') unless payees.length == 1 && payees[0]['value'].is_a?(String) && !payees[0]['value'].empty?
    { 'amount_minor' => a['value'].to_i, 'currency' => a['unit']['ccy'], 'exp' => a['unit']['exp'].to_i, 'payee' => payees[0]['value'] }
  end

  def minor_to_decimal(minor, exp)
    psd2_unlinkable('minor units must be a non-negative safe integer') unless render_safe_int?(minor) && minor >= 0 && render_safe_int?(exp) && exp >= 0 && exp <= 18
    return minor.to_s if exp.zero?

    s = minor.to_s.rjust(exp + 1, '0')
    "#{s[0...-exp]}.#{s[-exp..]}"
  end

  def approval_batch(items)
    psd2_unlinkable('a batch needs at least one payment') if items.empty?
    totals = {}
    payees = {}
    items.each do |it|
      link = psd2_linking(it['render'])
      t = totals[link['currency']]
      psd2_unlinkable("currency #{link['currency']} appears with two exponents") if t && t['exp'] != link['exp']
      minor = (t ? t['minor'] : 0) + link['amount_minor']
      psd2_unlinkable('the batch total exceeds the safe integer range') if minor > 9_007_199_254_740_991
      totals[link['currency']] = { 'exp' => link['exp'], 'minor' => minor }
      payees[link['payee']] = true
    end
    batch = {
      'v' => 1, 'kind' => 'pca-approval-batch', 'n' => items.length,
      'totals' => totals.keys.sort_by { |c| render_u16(c) }.map { |c| { 'ccy' => c, 'exp' => totals[c]['exp'], 'minor' => totals[c]['minor'] } },
      'payees_root' => merkle_root(payees.keys.sort_by { |p| render_u16(p) }.map { |p| { 'd' => APPROVAL_PAYEE_DOMAIN, 'payee' => p } }),
      'items_root' => merkle_root(items.map { |it| { 'd' => APPROVAL_ITEM_DOMAIN, 'a' => it['action_digest'], 'r' => approval_render_digest(it['render']) } })
    }
    rd = hash_canonical({ 'd' => APPROVAL_BATCH_DOMAIN, 'batch' => batch })
    { 'batch' => batch, 'action_digest' => batch['items_root'], 'render_digest' => rd, 'challenge' => approval_challenge(batch['items_root'], rd), 'words' => binding_words(rd) }
  end
end
