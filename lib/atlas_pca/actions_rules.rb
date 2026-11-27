# frozen_string_literal: true

# A platform's own business rules for one action, compiled into tighten rules and count accumulators (native port of
# business-rules.ts of the TypeScript reference @atlasauth/pca-actions). Every compiled rule signals `escalate` or `deny`, never
# `allow`: a rule can only lower a decision. Anything the evaluator cannot decide fires the rule (fail closed). Time zones come
# from the tzinfo gem (the IANA database).
require 'set'
require_relative 'actions'
require_relative 'js_compat'

module AtlasPca
  module ActionsRules
    A = AtlasPca::Actions
    UNDEF = Object.new.freeze
    RULE_DAYS = %w[sun mon tue wed thu fri sat].freeze
    RATE_PERIODS = { 'hour' => 3_600_000, 'day' => 86_400_000 }.freeze
    MAX_RULE_CURRENCIES = 32
    MAX_RULE_LIST = 64
    MAX_RULE_APPROVERS = 16
    MAX_RULE_EXAMPLES = 32
    CCY_RE = /\A[A-Z]{3}\z/
    NAME_RE = /\A[a-z][a-z0-9_]{0,63}\z/
    HHMM_RE = /\A([01][0-9]|2[0-3]):([0-5][0-9])\z/
    DOMAIN_RE = /\A(?=.{1,253}\z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z/
    ADDRESS_RE = /\A[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\z/
    DEC_RE = /\A(0|[1-9][0-9]{0,14})(?:\.([0-9]{1,6}))?\z/
    AT_RE = /\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z/
    TZ_RE = %r{\A[A-Za-z0-9_+\-/]+\z}
    RULE_KEYS = %w[amount approval scope rate hours recipients required examples].freeze
    BUSINESS_RULES_DOMAIN = 'atlas-pca/action-business-rules/v1'
    RULES_REVIEW_DOMAIN = 'atlas-pca/action-rules-review/v1'
    DEFAULT_EXAMPLE_AT = '2026-01-07T15:00:00Z'
    DAY_NAMES = { 'sun' => 'Sun', 'mon' => 'Mon', 'tue' => 'Tue', 'wed' => 'Wed', 'thu' => 'Thu', 'fri' => 'Fri', 'sat' => 'Sat' }.freeze
    DECISION_RANK = { 'deny' => 0, 'escalate' => 1, 'allow' => 2 }.freeze
    ZONE_CACHE = {} # rubocop:disable Style/MutableConstant
    ZONE_LOCK = Mutex.new

    module_function

    def isobj?(v) = v.is_a?(Hash)
    def isnum?(v) = v.is_a?(Integer) || v.is_a?(Float)

    # Number.isSafeInteger
    def isi?(v)
      return false unless isnum?(v)
      return false if v.is_a?(Float) && (!v.finite? || v != v.floor)

      v.abs <= 9_007_199_254_740_991
    end

    def negzero?(v) = v.is_a?(Float) && v.zero? && (1.0 / v).negative?
    def js_str(v) = v.equal?(UNDEF) ? 'undefined' : Js.string(v)
    def u16key(s) = A.u16key(s)

    def bad(msg) = raise(A::ActionKitError.new('bad_rules', msg))

    def closed(o, allowed, at)
      o.each_key { |k| bad("#{at}: unknown member '#{k}'") unless allowed.include?(k) }
    end

    # The parameter a reference names ({param} or {role}), with its definition. Raises bad_rules for none or several.
    def resolve_param_ref(d, r, at)
      bad("#{at}: name a parameter ({param} or {role})") unless isobj?(r)
      has_p = r['param'].is_a?(String)
      has_r = r['role'].is_a?(String)
      bad("#{at}: give exactly one of param or role") if has_p == has_r
      if has_p
        p = d['params'][r['param']]
        bad("#{at}: '#{d['verb']}' has no parameter '#{js_str(r['param'])}'") if p.nil?
        return { 'name' => r['param'], 'p' => p }
      end
      hits = d['params'].keys.select { |n| d['params'][n]['role'] == r['role'] }.sort_by { |n| u16key(n) }
      if hits.length != 1
        bad("#{at}: '#{d['verb']}' has #{hits.empty? ? 'no' : 'several'} parameter#{hits.empty? ? '' : 's'} with role #{js_str(r['role'])}")
      end
      { 'name' => hits[0], 'p' => d['params'][hits[0]] }
    end

    # The money parameters of an action: {amount, exp, ccy: {literal} | {param}}.
    def money_of(d)
      hits = d['params'].keys.select { |n| d['params'][n]['role'] == 'money.amount' }.sort_by { |n| u16key(n) }
      if hits.length != 1
        bad("'#{d['verb']}' needs exactly one parameter with role money.amount for an amount or approval-above rule (has #{hits.length})")
      end
      name = hits[0]
      p = d['params'][name]
      bad("'#{d['verb']}': the money.amount parameter '#{name}' must be an integer") if p['type'] != 'integer'
      u = p['unit']
      bad("'#{d['verb']}': the amount parameter '#{name}' declares no money unit (its currency)") if u.nil? || u['kind'] != 'money'
      return { 'amount' => name, 'exp' => u['exp'], 'ccy' => { 'literal' => u['ccy'] } } if u['ccy'].is_a?(String)

      frm = u['ccy']['from']
      bad("'#{d['verb']}': the currency parameter '#{frm}' does not exist") unless d['params'].key?(frm)
      { 'amount' => name, 'exp' => u['exp'], 'ccy' => { 'param' => frm } }
    end

    # Integer minor units of a money value under exponent `exp`. Raises bad_rules for a non-integer or over-precise value.
    def minor_units(v, exp, at)
      if isnum?(v)
        bad("#{at}: an amount is a non-negative integer of minor units, or a decimal string") if !isi?(v) || v.negative? || negzero?(v)
        return v.to_i
      end
      bad("#{at}: an amount is a number of minor units or a decimal string") unless v.is_a?(String)

      m = DEC_RE.match(v)
      bad("#{at}: '#{v}' is not a decimal amount") unless m
      frac = m[2] || ''
      bad("#{at}: '#{v}' has more decimals than the currency's #{exp}") if frac.length > exp
      n = (m[1].to_i * (10**exp)) + (frac.ljust(exp, '0').empty? ? 0 : frac.ljust(exp, '0').to_i)
      bad("#{at}: '#{v}' is too large") if n > 9_007_199_254_740_991
      n
    end

    def mins(hhmm) = (hhmm[0, 2].to_i * 60) + hhmm[3, 2].to_i

    # A TZInfo timezone for an IANA name, matched case-insensitively like the reference's Intl; nil when unknown.
    def zone(tz)
      ZONE_LOCK.synchronize do
        return ZONE_CACHE[tz] if ZONE_CACHE.key?(tz)

        z = begin
          require 'tzinfo'
          begin
            TZInfo::Timezone.get(tz)
          rescue TZInfo::InvalidTimezoneIdentifier
            low = tz.downcase
            hit = TZInfo::Timezone.all_identifiers.find { |n| n.downcase == low }
            hit && TZInfo::Timezone.get(hit)
          end
        rescue StandardError, LoadError
          nil
        end
        ZONE_CACHE[tz] = z
      end
    end

    # Is this a time zone the runtime knows (IANA name)?
    def known_time_zone(tz)
      return false if !tz.is_a?(String) || tz.empty? || tz.length > 64 || !TZ_RE.match?(tz)

      !zone(tz).nil?
    rescue StandardError
      false
    end

    def days_from_civil(y, m, d)
      y -= 1 if m <= 2
      era = (y >= 0 ? y : y - 399) / 400
      yoe = y - (era * 400)
      doy = (((153 * (m + (m > 2 ? -3 : 9))) + 2) / 5) + d - 1
      doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy
      (era * 146_097) + doe - 719_468
    end

    # Date.parse of an RFC 3339 `...Z` second-precision time: day 1..31 rolls over the month, 24:00:00 is the next day; else nil.
    def parse_utc_ms(s)
      return nil if !s.is_a?(String) || !AT_RE.match?(s)

      y = s[0, 4].to_i
      mo = s[5, 2].to_i
      d = s[8, 2].to_i
      h = s[11, 2].to_i
      mi = s[14, 2].to_i
      se = s[17, 2].to_i
      return nil unless mo.between?(1, 12) && d.between?(1, 31) && mi <= 59 && se <= 59 && (h <= 23 || (h == 24 && mi.zero? && se.zero?))

      ((days_from_civil(y, mo, 1) + d - 1) * 86_400_000) + (h * 3_600_000) + (mi * 60_000) + (se * 1000)
    end

    # nil iff `rules` is a well-formed rules block for `d`; the reason otherwise.
    def business_rules_error(d, rules)
      validate_rules(d, rules)
      nil
    rescue StandardError => e
      e.message
    end

    def ccy_map(d, m, at)
      bad("#{at}: a map of 1..#{MAX_RULE_CURRENCIES} currencies to amounts") if !isobj?(m) || m.empty? || m.length > MAX_RULE_CURRENCIES
      money = money_of(d)
      m.each do |c, v|
        bad("#{at}: '#{c}' is not an ISO 4217 currency code") unless CCY_RE.match?(c)
        minor_units(v, money['exp'], "#{at}.#{c}")
      end
    end

    def ref_of(s) = s.slice('param', 'role')

    def validate_rules(d, r)
      bad('rules must be an object') unless isobj?(r)
      closed(r, RULE_KEYS, 'rules')
      bad('rules: name at least one rule') if r.keys.none? { |k| k != 'examples' }
      validate_amount_approval(d, r)
      validate_scope_rate_hours(d, r)
      validate_recipients_required_examples(d, r)
    end

    def validate_amount_approval(d, r)
      if r.key?('amount')
        a = r['amount']
        bad('rules.amount must be {max: {CCY: amount}}') unless isobj?(a)
        closed(a, ['max'], 'rules.amount')
        ccy_map(d, a['max'], 'rules.amount.max')
      end
      return unless r.key?('approval')

      ap = r['approval']
      bad('rules.approval must be an object') unless isobj?(ap)
      closed(ap, %w[above always approvers group], 'rules.approval')
      bad('rules.approval.always is true or absent') if ap.key?('always') && ap['always'] != true
      bad('rules.approval: give exactly one of above or always') if !ap.key?('above') == !ap.key?('always')
      ccy_map(d, ap['above'], 'rules.approval.above') if ap.key?('above')
      if ap.key?('approvers') && (!isi?(ap['approvers']) || ap['approvers'] < 1 || ap['approvers'] > MAX_RULE_APPROVERS)
        bad("rules.approval.approvers is 1..#{MAX_RULE_APPROVERS}")
      end
      bad('rules.approval.group is a lowercase name') if ap.key?('group') && (!ap['group'].is_a?(String) || !NAME_RE.match?(ap['group']))
    end

    def validate_scope_rate_hours(d, r)
      if r.key?('scope')
        sc = r['scope']
        bad("rules.scope is a list of 1..#{MAX_RULE_LIST} bindings") if !sc.is_a?(Array) || sc.empty? || sc.length > MAX_RULE_LIST
        sc.each_with_index do |s, i|
          bad("rules.scope[#{i}] must be an object") unless isobj?(s)
          closed(s, %w[param role caller], "rules.scope[#{i}]")
          p = resolve_param_ref(d, ref_of(s), "rules.scope[#{i}]")['p']
          bad("rules.scope[#{i}]: the bound parameter must be a string or integer id") unless %w[string integer].include?(p['type'])
          bad("rules.scope[#{i}].caller is a lowercase attribute name of the caller") if !s['caller'].is_a?(String) || !NAME_RE.match?(s['caller'])
        end
      end
      if r.key?('rate')
        rt = r['rate']
        bad('rules.rate is a list of 1..4 limits') if !rt.is_a?(Array) || rt.empty? || rt.length > 4
        rt.each_with_index do |x, i|
          bad("rules.rate[#{i}] must be an object") unless isobj?(x)
          closed(x, %w[max per by], "rules.rate[#{i}]")
          bad("rules.rate[#{i}].max is 1..1000000") if !isi?(x['max']) || x['max'] < 1 || x['max'] > 1_000_000
          bad("rules.rate[#{i}].per is hour or day") if !x['per'].is_a?(String) || !RATE_PERIODS.key?(x['per'])
          bad("rules.rate[#{i}].by is principal or org") if x.key?('by') && !%w[principal org].include?(x['by'])
        end
      end
      return unless r.key?('hours')

      h = r['hours']
      bad('rules.hours must be an object') unless isobj?(h)
      closed(h, %w[days from to tz outside], 'rules.hours')
      days = h['days']
      if !days.is_a?(Array) || days.empty? || !days.all? { |x| x.is_a?(String) && RULE_DAYS.include?(x) } || days.uniq.length != days.length
        bad("rules.hours.days is a list of distinct days (#{RULE_DAYS.join(', ')})")
      end
      if !h['from'].is_a?(String) || !HHMM_RE.match?(h['from']) || !h['to'].is_a?(String) || !HHMM_RE.match?(h['to'])
        bad('rules.hours.from and .to are HH:MM (24 h)')
      end
      bad("rules.hours.tz '#{js_str(h.key?('tz') ? h['tz'] : UNDEF)}' is not a known IANA time zone") if !h['tz'].is_a?(String) || !known_time_zone(h['tz'])
      bad('rules.hours.outside is escalate or deny') if h.key?('outside') && !%w[escalate deny].include?(h['outside'])
    end

    def validate_recipients_required_examples(d, r)
      if r.key?('recipients')
        x = r['recipients']
        bad('rules.recipients must be an object') unless isobj?(x)
        closed(x, %w[param role domains addresses], 'rules.recipients')
        res = resolve_param_ref(d, ref_of(x), 'rules.recipients')
        name = res['name']
        p = res['p']
        if %w[array set].include?(p['type'])
          bad("rules.recipients: '#{name}' must hold strings") if !p['items'].nil? && p['items'] != 'string'
          mi = p['max_items']
          if !isi?(mi) || negzero?(mi) || mi > MAX_RULE_LIST
            bad("rules.recipients: the list parameter '#{name}' needs max_items <= #{MAX_RULE_LIST} so every entry can be checked")
          end
        elsif p['type'] != 'string'
          bad("rules.recipients: '#{name}' must be a string or a bounded list of strings")
        end
        bad('rules.recipients: give domains and/or addresses') if !x.key?('domains') && !x.key?('addresses')
        if x.key?('domains') && !list_of?(x['domains'], DOMAIN_RE)
          bad('rules.recipients.domains is a list of lowercase domain names')
        end
        if x.key?('addresses') && !list_of?(x['addresses'], ADDRESS_RE)
          bad('rules.recipients.addresses is a list of lowercase email addresses')
        end
      end
      if r.key?('required')
        rq = r['required']
        if !rq.is_a?(Array) || rq.empty? || rq.length > MAX_RULE_LIST || rq.map(&:inspect).uniq.length != rq.length
          bad('rules.required is a list of distinct parameter names')
        end
        rq.each { |n| bad("rules.required: '#{d['verb']}' has no parameter '#{js_str(n)}'") if !n.is_a?(String) || !d['params'].key?(n) }
      end
      return unless r.key?('examples')

      ex = r['examples']
      bad("rules.examples is a list of at most #{MAX_RULE_EXAMPLES}") if !ex.is_a?(Array) || ex.length > MAX_RULE_EXAMPLES
      ex.each_with_index do |e, i|
        bad("rules.examples[#{i}] must be an object") unless isobj?(e)
        closed(e, %w[params caller at recent expect], "rules.examples[#{i}]")
        bad("rules.examples[#{i}].params must be an object") unless isobj?(e['params'])
        bad("rules.examples[#{i}].caller must be an object") if e.key?('caller') && !isobj?(e['caller'])
        bad("rules.examples[#{i}].at is an RFC 3339 UTC time (…Z)") if e.key?('at') && parse_utc_ms(e['at']).nil?
        if e.key?('recent') && (!isobj?(e['recent']) || !e['recent'].values.all? { |n| isi?(n) && n >= 0 && !negzero?(n) })
          bad("rules.examples[#{i}].recent maps rate indexes to counts")
        end
        bad("rules.examples[#{i}].expect is allow, escalate or deny") unless %w[allow escalate deny].include?(e['expect'])
      end
    end

    def list_of?(v, re) = v.is_a?(Array) && !v.empty? && v.length <= MAX_RULE_LIST && v.all? { |x| x.is_a?(String) && re.match?(x) }

    # ---- compiled form
    # Digest of a rules block (examples are tests, not rules).
    def business_rules_digest(verb, rules)
      AtlasPca.hash_canonical({ 'd' => BUSINESS_RULES_DOMAIN, 'verb' => verb, 'rules' => rules.reject { |k, _| k == 'examples' } })
    end

    def pp_(n) = "action.params.#{n}"

    def ccy_cond(m, c)
      return { 'field' => pp_(m['ccy']['param']), 'op' => 'eq', 'value' => c } if m['ccy'].key?('param')

      m['ccy']['literal'] == c ? nil : { 'field' => 'action.verb', 'op' => 'eq', 'value' => "\u0000never" }
    end

    def and_(cs)
      xs = cs.compact
      xs.length == 1 ? xs[0] : { 'all_of' => xs }
    end

    def always(verb) = { 'field' => 'action.verb', 'op' => 'eq', 'value' => verb }
    def rule_id(s) = s.downcase.gsub(/[^a-z0-9_]/, '_')[0, 64]

    # `12345` minor units of USD (exp 2) -> "123.45 USD". Deterministic (no locale).
    def format_money(minor, ccy, exp)
      s = minor.to_s.rjust(exp + 1, '0')
      "#{exp.positive? ? "#{s[0...-exp]}.#{s[-exp..]}" : s} #{ccy}"
    end

    def hours_text(h)
      ds = h['days'].sort_by { |x| RULE_DAYS.index(x) }
      idx = ds.map { |x| RULE_DAYS.index(x) }
      run = idx.length > 2 && idx.each_with_index.all? { |x, k| k.zero? || x == idx[k - 1] + 1 }
      days = run ? "#{DAY_NAMES[ds[0]]}-#{DAY_NAMES[ds[-1]]}" : ds.map { |x| DAY_NAMES[x] }.join(', ')
      "#{days} #{h['from']}-#{h['to']} (#{h['tz']})"
    end

    def recipients_text(x) = ((x['domains'] || []).map { |dm| "addresses at #{dm}" } + (x['addresses'] || [])).join(' or ')

    def truncate_reason(s)
      return s if Js.len16(s) <= 256

      out = +''
      units = 0
      s.each_char do |ch|
        w = ch.ord > 0xffff ? 2 : 1
        break if units + w > 253

        out << ch
        units += w
      end
      "#{out}..."
    end

    # Compile a rules block for `d` into tighten rules and accumulators. Raises bad_rules for a malformed block. Deterministic.
    def compile_business_rules(d, rules)
      validate_rules(d, rules)
      t = []
      acc = []
      out = { 'v' => 1, 'verb' => d['verb'], 'rules_digest' => business_rules_digest(d['verb'], rules), 'def_digest' => A.def_digest(d),
              'tighten' => t, 'accumulators' => acc }
      money = rules.key?('amount') || (rules['approval'] || {}).key?('above') ? money_of(d) : nil
      unlisted = lambda do |listed|
        next nil if money.nil?
        next { 'not' => { 'field' => pp_(money['ccy']['param']), 'op' => 'in', 'value' => listed } } if money['ccy'].key?('param')

        listed.include?(money['ccy']['literal']) ? nil : always(d['verb'])
      end
      compile_amount_approval(d, rules, t, out, money, unlisted)
      (rules['scope'] || []).each_with_index do |s, i|
        name = resolve_param_ref(d, s.key?('param') ? { 'param' => s['param'] } : { 'role' => s['role'] }, "rules.scope[#{i}]")['name']
        # `not eq`: an absent caller attribute or parameter is undecided, so the rule fires
        t << { 'id' => "scope_#{i}", 'when' => { 'not' => { 'field' => pp_(name), 'op' => 'eq', 'ref' => "subject.#{s['caller']}" } }, 'signal' => 'deny',
               'reason' => "#{name} must be the caller's own #{s['caller']}" }
      end
      (rules['rate'] || []).each_with_index do |r, i|
        rid = "rate_#{i}"
        by = r['by'] || 'principal'
        acc << { 'id' => rid, 'agg' => 'count', 'sel' => { 'verbs' => [d['verb']] }, 'win' => { 'kind' => 'sliding', 'ms' => RATE_PERIODS[r['per']] }, 'key' => nil,
                 'domain_max' => r['max'], 'cap' => r['max'], 'holder' => { 'kind' => 'site_local' }, 'scope' => by }
        t << { 'id' => rid, 'when' => { 'field' => "env.acc.#{rid}", 'op' => 'gte', 'value' => r['max'] }, 'signal' => 'deny', 'reason' => "at most #{r['max']} per #{r['per']} per #{by}" }
      end
      compile_hours(rules, t, out) if rules.key?('hours')
      compile_recipients(d, rules, t) if rules.key?('recipients')
      (rules['required'] || []).each_with_index do |n, i|
        pr = d['params'][n]
        missing = if pr['type'] == 'string'
                    { 'any_of' => [{ 'field' => pp_(n), 'op' => 'exists', 'value' => false }, { 'field' => pp_(n), 'op' => 'eq', 'value' => '' }] }
                  else
                    { 'field' => pp_(n), 'op' => 'exists', 'value' => false }
                  end
        t << { 'id' => "required_#{i}", 'when' => missing, 'signal' => 'deny', 'reason' => "#{n} is required" }
      end
      t.each { |r| r['reason'] = truncate_reason(r['reason']) unless r['reason'].nil? }
      out
    end

    def compile_amount_approval(d, rules, t, out, money, unlisted)
      if rules.key?('amount')
        listed = rules['amount']['max'].keys.sort_by { |c| u16key(c) }
        listed.each do |c|
          mx = minor_units(rules['amount']['max'][c], money['exp'], "rules.amount.max.#{c}")
          t << { 'id' => rule_id("amount_max_#{c}"), 'when' => and_([ccy_cond(money, c), { 'field' => pp_(money['amount']), 'op' => 'gt', 'value' => mx }]), 'signal' => 'deny',
                 'reason' => "the amount is above the #{format_money(mx, c, money['exp'])} ceiling" }
        end
        u = unlisted.call(listed)
        t << { 'id' => 'amount_currency', 'when' => u, 'signal' => 'deny', 'reason' => "only #{listed.join(', ')} amounts are allowed" } if u
      end
      return unless rules.key?('approval')

      ap = rules['approval']
      out['approval'] = { 'approvers' => ap['approvers'].nil? ? 1 : ap['approvers'] }
      out['approval']['group'] = ap['group'] if ap.key?('group')
      if ap['always']
        t << { 'id' => 'approval_always', 'when' => always(d['verb']), 'signal' => 'escalate', 'reason' => 'this action always needs approval' }
        return
      end
      listed = ap['above'].keys.sort_by { |c| u16key(c) }
      listed.each do |c|
        x = minor_units(ap['above'][c], money['exp'], "rules.approval.above.#{c}")
        t << { 'id' => rule_id("approval_above_#{c}"), 'when' => and_([ccy_cond(money, c), { 'field' => pp_(money['amount']), 'op' => 'gt', 'value' => x }]), 'signal' => 'escalate',
               'reason' => "amounts above #{format_money(x, c, money['exp'])} need approval" }
      end
      u = unlisted.call(listed)
      t << { 'id' => 'approval_currency', 'when' => u, 'signal' => 'escalate', 'reason' => "amounts in a currency other than #{listed.join(', ')} need approval" } if u
    end

    def compile_hours(rules, t, out)
      h = rules['hours']
      frm = mins(h['from'])
      to = mins(h['to'])
      dows = h['days'].map { |x| RULE_DAYS.index(x) }.sort
      if frm < to
        in_time = { 'all_of' => [{ 'field' => 'env.clock.min', 'op' => 'gte', 'value' => frm }, { 'field' => 'env.clock.min', 'op' => 'lt', 'value' => to }] }
        day = { 'field' => 'env.clock.dow', 'op' => 'in', 'value' => dows }
      else
        # an overnight window (22:00-06:00): the day named is the day the window starts
        in_time = { 'any_of' => [{ 'field' => 'env.clock.min', 'op' => 'gte', 'value' => frm }, { 'field' => 'env.clock.min', 'op' => 'lt', 'value' => to }] }
        day = { 'any_of' => [{ 'all_of' => [{ 'field' => 'env.clock.dow', 'op' => 'in', 'value' => dows }, { 'field' => 'env.clock.min', 'op' => 'gte', 'value' => frm }] },
                             { 'all_of' => [{ 'field' => 'env.clock.dow', 'op' => 'in', 'value' => dows.map { |x| (x + 1) % 7 } }, { 'field' => 'env.clock.min', 'op' => 'lt', 'value' => to }] }] }
      end
      out['clock_tz'] = h['tz']
      t << { 'id' => 'hours', 'when' => { 'not' => { 'all_of' => [day, in_time] } }, 'signal' => h['outside'] || 'escalate', 'reason' => "outside #{hours_text(h)}" }
    end

    def compile_recipients(d, rules, t)
      x = rules['recipients']
      res = resolve_param_ref(d, x.key?('param') ? { 'param' => x['param'] } : { 'role' => x['role'] }, 'rules.recipients')
      name = res['name']
      p = res['p']
      ok_at = lambda do |path|
        alts = (x['domains'] || []).map { |dm| { 'field' => path, 'op' => 'like', 'value' => "*@#{dm.gsub(/[\\*?]/) { |c| "\\#{c}" }}" } }
        alts << { 'field' => path, 'op' => 'in', 'value' => x['addresses'].sort_by { |a| u16key(a) } } unless x['addresses'].nil?
        { 'any_of' => alts }
      end
      ok = if p['type'] == 'string'
             ok_at.call(pp_(name))
           else
             n = p['max_items']
             { 'all_of' => (0...n).map { |i| { 'any_of' => [{ 'field' => pp_("#{name}.#{i}"), 'op' => 'exists', 'value' => false }, ok_at.call(pp_("#{name}.#{i}"))] } } +
                           [{ 'field' => pp_("#{name}.#{n}"), 'op' => 'exists', 'value' => false }] }
           end
      t << { 'id' => 'recipients', 'when' => { 'not' => ok }, 'signal' => 'deny', 'reason' => "#{name} may only name #{recipients_text(x)}" }
    end

    # ---- evaluation
    # Meet in the order deny < escalate < allow.
    def meet_decision(a, b) = DECISION_RANK[a] <= DECISION_RANK[b] ? a : b

    # Day of week (0 = Sunday) and minute of day at `now` (ms since the epoch) in `tz`, or nil when it cannot be computed.
    def clock_at(now, tz)
      return nil if !isnum?(now) || (now.is_a?(Float) && !now.finite?)

      z = zone(tz)
      return nil if z.nil?

      t = z.utc_to_local(Time.at(Rational(now.to_i, 1000)).utc)
      { 'dow' => t.wday, 'min' => (t.hour * 60) + t.min }
    rescue StandardError
      nil
    end

    # The predicate context the compiled rules are evaluated in: verifier-computed `env` members only.
    def rules_context(c, i)
      env = {}
      unless c['clock_tz'].nil?
        k = clock_at(i['now'], c['clock_tz'])
        env['clock'] = k if k
      end
      acc = {}
      c['accumulators'].each do |a|
        n = (i['counts'] || {})[a['id']]
        acc[a['id']] = n if isi?(n) && n >= 0
      end
      env['acc'] = acc
      { 'action' => { 'verb' => c['verb'], 'resource' => i['resource'].nil? ? '' : i['resource'], 'params' => i['params'] },
        'subject' => i['subject'].nil? ? {} : i['subject'], 'env' => env }
    end

    # Evaluate compiled rules: `allow` unless a rule fires; a fired rule caps the decision at its signal. Never raises.
    def evaluate_business_rules(c, i)
      ctx = rules_context(c, i)
      decision = 'allow'
      reasons = []
      fired = []
      approval = false
      raise TypeError, 'c.tighten is not iterable' unless c['tighten'].is_a?(Array)

      c['tighten'].each do |r|
        next if AtlasPca.evaluate_condition_tri(r['when'], ctx) == 'false'

        decision = meet_decision(decision, r['signal'])
        fired << r['id']
        reasons << "#{r['id']}: #{r['reason'].nil? ? r['signal'] : r['reason']}"
        approval = true if r['signal'] == 'escalate' && r['id'].start_with?('approval_')
      end
      out = { 'decision' => decision, 'reasons' => reasons, 'fired' => fired }
      out['approval'] = c['approval'] if approval && c['approval']
      out
    rescue StandardError => e
      { 'decision' => 'deny', 'reasons' => ["rules: evaluation error (fail closed): #{e.message}"], 'fired' => [] }
    end

    # The decision with rules applied to a base decision: the meet, so rules never raise it.
    def with_business_rules(base, v) = meet_decision(base, v['decision'])

    def run_rule_examples(d, rules)
      c = compile_business_rules(d, rules)
      (rules['examples'] || []).each_with_index.map do |e, index|
        counts = c['accumulators'].each_with_index.to_h { |a, k| [a['id'], (e['recent'] || {}).fetch(k.to_s, 0)] }
        inp = { 'params' => e['params'], 'now' => parse_utc_ms(e.key?('at') ? e['at'] : DEFAULT_EXAMPLE_AT), 'counts' => counts }
        inp['subject'] = e['caller'] unless e['caller'].nil?
        v = evaluate_business_rules(c, inp)
        { 'index' => index, 'expect' => e['expect'], 'got' => v['decision'], 'ok' => v['decision'] == e['expect'],
          'why' => v['reasons'].empty? ? 'no rule fired' : v['reasons'].join('; ') }
      end
    end

    # One plain sentence per rule, for the policy card and the dashboard. Raises bad_rules for a malformed block.
    def explain_business_rules(d, rules)
      validate_rules(d, rules)
      out = []
      m = rules.key?('amount') || (rules['approval'] || {}).key?('above') ? money_of(d) : nil
      lst = ->(mp) { mp.keys.sort_by { |c| u16key(c) }.map { |c| format_money(minor_units(mp[c], m['exp'], c), c, m['exp']) }.join(', ') }
      out << "Refuses amounts above #{lst.call(rules['amount']['max'])}; any other currency is refused." if rules.key?('amount')
      if rules.key?('approval')
        ap = rules['approval']
        n = ap['approvers'].nil? ? 1 : ap['approvers']
        who = "#{n} approver#{n == 1 ? '' : 's'}#{ap['group'] ? " from the #{ap['group']} group" : ''}"
        out << (ap['always'] ? "Always needs approval by #{who}." : "Needs approval by #{who} when the amount is above #{lst.call(ap['above'])} (or in another currency).")
      end
      (rules['scope'] || []).each do |s|
        name = resolve_param_ref(d, s.key?('param') ? { 'param' => s['param'] } : { 'role' => s['role'] }, 'rules.scope')['name']
        out << "Only the caller's own records: #{name} must be the caller's #{s['caller']}."
      end
      (rules['rate'] || []).each { |r| out << "At most #{r['max']} per #{r['per']} per #{r['by'] == 'org' ? 'organisation' : 'principal'}." }
      out << "Only #{hours_text(rules['hours'])}; outside those hours it #{rules['hours']['outside'] == 'deny' ? 'is refused' : 'needs approval'}." if rules.key?('hours')
      if rules.key?('recipients')
        x = rules['recipients']
        name = resolve_param_ref(d, x.key?('param') ? { 'param' => x['param'] } : { 'role' => x['role'] }, 'rules.recipients')['name']
        out << "#{name} may only name #{recipients_text(x)}."
      end
      out << "Requires #{rules['required'].join(', ')}." if rules.key?('required')
      out
    end

    # ---- lint (contradictions and dead rules)
    BUSINESS_RULE_LINTS = [
      ['LR-001', 'error', 'a rules block is malformed or names a parameter the action does not have'],
      ['LR-002', 'error', 'a contradiction: under the rules the action can never be allowed'],
      ['LR-003', 'warning', 'a rule that can never fire or that another rule already covers'],
      ['LR-004', 'error', 'a rules example does not decide as it expects']
    ].freeze

    def lint_business_rules(d, rules)
      f = ->(rule, severity, message) { { 'rule' => rule, 'severity' => severity, 'verb' => d['verb'], 'message' => message } }
      e = business_rules_error(d, rules)
      return [f.call('LR-001', 'error', e)] if e

      r = rules
      out = []
      m = r.key?('amount') || (r['approval'] || {}).key?('above') ? money_of(d) : nil
      amt = m ? d['params'][m['amount']] : nil
      ccy_values = nil
      if m
        ccy_values = m['ccy'].key?('param') ? d['params'][m['ccy']['param']]['values'] : [m['ccy']['literal']]
      end
      if r.key?('amount') && m
        listed = r['amount']['max'].keys
        if !ccy_values.nil? && listed.none? { |c| ccy_values.include?(c) }
          out << f.call('LR-002', 'error', "rules.amount: none of the action's currencies (#{ccy_values.join(', ')}) has a ceiling, so every call is refused")
        end
        listed.each do |c|
          mx = minor_units(r['amount']['max'][c], m['exp'], c)
          out << f.call('LR-003', 'warning', "rules.amount.max.#{c}: the action never uses #{c}") if !ccy_values.nil? && !ccy_values.include?(c)
          if !amt.nil? && !amt['min'].nil? && mx < amt['min']
            out << f.call('LR-002', 'error', "rules.amount.max.#{c}: the ceiling #{format_money(mx, c, m['exp'])} is below the parameter's minimum, so every #{c} call is refused")
          end
          if !amt.nil? && !amt['max'].nil? && mx >= amt['max']
            out << f.call('LR-003', 'warning', "rules.amount.max.#{c}: the parameter's own maximum already bounds the amount below this ceiling")
          end
        end
      end
      if (r['approval'] || {}).key?('above') && m
        r['approval']['above'].each_key do |c|
          x = minor_units(r['approval']['above'][c], m['exp'], c)
          ceil = r.key?('amount') ? r['amount']['max'][c] : nil
          if !ceil.nil? && x >= minor_units(ceil, m['exp'], c)
            out << f.call('LR-003', 'warning', "rules.approval.above.#{c}: above the amount ceiling, so the approval can never be asked for")
          end
          out << f.call('LR-003', 'warning', "rules.approval.above.#{c}: #{c} has no ceiling, so it is always refused before an approval") if r.key?('amount') && ceil.nil?
        end
      end
      if r.key?('hours') && r['hours']['from'] == r['hours']['to']
        h = r['hours']
        out << f.call('LR-002', 'error', "rules.hours: the window #{h['from']}-#{h['to']} is empty, so the action is #{h['outside'] == 'deny' ? 'always refused' : 'always escalated'}")
      end
      (r['required'] || []).each do |n|
        if d['params'][n]['required'] != false && d['params'][n]['type'] != 'string'
          out << f.call('LR-003', 'warning', "rules.required: '#{n}' is already required by the definition")
        end
      end
      lint_rate(r, f, out) if r.key?('rate')
      begin
        run_rule_examples(d, r).each do |x|
          out << f.call('LR-004', 'error', "rules.examples[#{x['index']}]: expected #{x['expect']}, got #{x['got']} (#{x['why']})") unless x['ok']
        end
      rescue StandardError => err
        out << f.call('LR-001', 'error', err.message)
      end
      out
    end

    def lint_rate(r, f, out)
      seen = {}
      r['rate'].each do |x|
        k = "#{x['per']}|#{x['by'] || 'principal'}"
        if seen.key?(k)
          out << f.call('LR-003', 'warning', "rules.rate: two limits per #{x['per']} per #{x['by'] || 'principal'}; only the lower (#{[seen[k], x['max']].min}) matters")
        end
        seen[k] = [seen.fetch(k, Float::INFINITY), x['max']].min
      end
      h = seen['hour|principal']
      dd = seen['day|principal']
      out << f.call('LR-003', 'warning', 'rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires') if !h.nil? && !dd.nil? && dd <= h
    end

    # ---- semantic diff of rules (widening needs a reviewer)
    def set_rel(a, b)
      sa = Set.new(a)
      sb = Set.new(b)
      a_in_b = sa <= sb
      b_in_a = sb <= sa
      a_in_b && b_in_a ? 'eq' : b_in_a ? 'narrow' : a_in_b ? 'widen' : 'inc'
    end

    def num_rel(a, b) = a == b ? 'eq' : b < a ? 'narrow' : 'widen'

    def presence(a, b)
      return 'eq' if a.equal?(UNDEF) && b.equal?(UNDEF)
      return 'narrow' if a.equal?(UNDEF)
      return 'widen' if b.equal?(UNDEF)

      nil
    end

    def combine(rs)
      return 'inc' if rs.include?('inc') || (rs.include?('narrow') && rs.include?('widen'))
      return 'widen' if rs.include?('widen')

      rs.include?('narrow') ? 'narrow' : 'eq'
    end

    def flip(r) = r == 'narrow' ? 'widen' : r == 'widen' ? 'narrow' : r

    def minutes_of_week(h)
      s = Set.new
      frm = mins(h['from'])
      to = mins(h['to'])
      h['days'].each do |day|
        base = (RULE_DAYS.index(day) || -1) * 1440
        if frm < to
          (frm...to).each { |x| s << base + x }
        elsif frm > to
          (frm...1440).each { |x| s << base + x }
          (0...to).each { |x| s << ((base + 1440) % 10_080) + x }
        end
      end
      s
    end

    # The semantic diff of two rules blocks of one action (either may be absent): {class, reasons}. Conservative: unordered = incomparable.
    def diff_business_rules(d, prev, nxt)
      o = prev.is_a?(Hash) ? prev : {} # a non-object block has no members, as in JS
      n = nxt.is_a?(Hash) ? nxt : {}
      g = ->(x, k) { x.key?(k) ? x[k] : UNDEF }
      uses_money = o.key?('amount') || n.key?('amount') || (o['approval'] || {}).key?('above') || (n['approval'] || {}).key?('above')
      m = uses_money ? money_of(d) : nil
      rels = []
      ccy_map_rel = lambda do |a, b|
        rs = [set_rel(a.keys, b.keys)]
        a.each_key { |c| rs << num_rel(minor_units(a[c], m['exp'], c), minor_units(b[c], m['exp'], c)) if b.key?(c) }
        combine(rs)
      end
      p = presence(g.call(o, 'amount'), g.call(n, 'amount'))
      rels << ['amount', p.nil? ? ccy_map_rel.call(o['amount']['max'], n['amount']['max']) : p]
      p = presence(g.call(o, 'approval'), g.call(n, 'approval'))
      if p.nil?
        a = o['approval']
        b = n['approval']
        rs = []
        if a['always'] && b['always'] then rs << 'eq'
        elsif a['always'] then rs << 'widen'
        elsif b['always'] then rs << 'narrow'
        else rs << ccy_map_rel.call(a['above'], b['above'])
        end
        rs << num_rel(-(a['approvers'].nil? ? 1 : a['approvers']), -(b['approvers'].nil? ? 1 : b['approvers']))
        rs << (g.call(a, 'group') == g.call(b, 'group') ? 'eq' : 'inc')
        p = combine(rs)
      end
      rels << ['approval', p]
      skey = lambda do |s|
        h = s.is_a?(Hash) ? s : {}
        "#{h['param'].nil? ? '' : h['param']}|#{h['role'].nil? ? '' : h['role']}|#{h.key?('caller') ? js_str(h['caller']) : 'undefined'}"
      end
      rels << ['scope', flip(set_rel((o['scope'] || []).map(&skey), (n['scope'] || []).map(&skey)))]
      best = lambda do |rs|
        mp = {}
        (rs || []).each do |x|
          k = "#{x['per']}|#{x['by'] || 'principal'}"
          mp[k] = [mp.fetch(k, Float::INFINITY), x['max']].min
        end
        mp
      end
      ra = best.call(o['rate'])
      rb = best.call(n['rate'])
      rs = (ra.keys + (rb.keys - ra.keys)).map { |k| !ra.key?(k) ? 'narrow' : !rb.key?(k) ? 'widen' : num_rel(ra[k], rb[k]) }
      rels << ['rate', combine(rs)]
      p = presence(g.call(o, 'hours'), g.call(n, 'hours'))
      if p.nil?
        a = o['hours']
        b = n['hours']
        if a['tz'] != b['tz']
          p = 'inc'
        else
          sa = minutes_of_week(a)
          sb = minutes_of_week(b)
          inner = sa == sb ? 'eq' : sb <= sa ? 'narrow' : sa <= sb ? 'widen' : 'inc'
          p = combine([inner, num_rel(a['outside'] == 'deny' ? 0 : 1, b['outside'] == 'deny' ? 0 : 1)])
        end
      end
      rels << ['hours', p]
      p = presence(g.call(o, 'recipients'), g.call(n, 'recipients'))
      if p.nil?
        a = o['recipients']
        b = n['recipients']
        if a['param'] != b['param'] || a['role'] != b['role']
          p = 'inc'
        else
          allowed_a = (a['domains'] || []).map { |x| "@#{x}" } + (a['addresses'] || [])
          allowed_b = (b['domains'] || []).map { |x| "@#{x}" } + (b['addresses'] || [])
          covered = ->(x, st) { st.include?(x) || (!x.start_with?('@') && st.include?("@#{x.split('@')[1]}")) }
          b_in_a = allowed_b.all? { |x| covered.call(x, allowed_a) }
          a_in_b = allowed_a.all? { |x| covered.call(x, allowed_b) }
          p = b_in_a && a_in_b ? 'eq' : b_in_a ? 'narrow' : a_in_b ? 'widen' : 'inc'
        end
      end
      rels << ['recipients', p]
      rels << ['required', flip(set_rel(o['required'] || [], n['required'] || []))]
      diffs = rels.reject { |_, r| r == 'eq' }
      reasons = diffs.map { |k, r| "rules.#{k}: #{r == 'inc' ? 'incomparable' : r}" }.sort_by { |s| u16key(s) }
      cls = combine(diffs.map { |_, r| r })
      { 'class' => cls == 'eq' ? 'equal' : cls == 'inc' ? 'incomparable' : cls, 'reasons' => reasons }
    end

    # ---- the reviewer's signature over a widened rules block
    def rules_review_message(b)
      body = AtlasPca.canon_bytes({ 'verb' => b['verb'], 'def_digest' => b['def_digest'], 'rules_digest' => b['rules_digest'], 'reviewer_kid' => b['reviewer_kid'], 'ts' => b['ts'] })
      "#{RULES_REVIEW_DOMAIN}\0".b + body
    end

    def sign_rules_review(b, secret)
      b.merge('sig' => AtlasPca.b64e(AtlasPca::KeyPair.new(secret.b).sign(rules_review_message(b))))
    end

    # nil iff `r` is a valid review of exactly these rules on exactly this def (digests, pinned reviewer key, validity, signature). Never raises.
    def rules_review_error(r, d, rules, pins)
      return 'no reviewer keys are pinned' if pins.nil?

      pe = A.reviewer_pins_error(pins)
      return "bad pins: #{pe}" if pe
      return 'no rules review' unless isobj?(r)
      return 'the rules review names another action' if r['verb'] != d['verb']
      return 'the rules review covers another version of the action' if r['def_digest'] != A.def_digest(d)
      return 'the rules review covers other rules' if r['rules_digest'] != business_rules_digest(d['verb'], rules)

      ts = r['ts']
      return 'malformed rules review' if !r['sig'].is_a?(String) || !r['reviewer_kid'].is_a?(String) || !isi?(ts) || negzero?(ts)

      key = pins['keys'].find { |k| k['kid'] == r['reviewer_kid'] }
      return "no pinned key '#{r['reviewer_kid']}'" if key.nil?
      return "key '#{key['kid']}' does not hold the reviewer role" unless key['roles'].include?('reviewer')
      return 'the review time is outside the key validity' if (!key['not_before'].nil? && ts < key['not_before']) || (!key['not_after'].nil? && ts > key['not_after'])

      body = r.reject { |k, _| k == 'sig' }
      AtlasPca.verify_b64u(key['pk'], rules_review_message(body), r['sig']) ? nil : 'the rules review signature is invalid'
    rescue StandardError => e
      "malformed rules review: #{e.message}"
    end
  end
end
