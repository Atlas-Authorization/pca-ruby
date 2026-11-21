# frozen_string_literal: true

require_relative 'ap2'

# AP2, part 2: ISO 4217 minor units, the mandate claim validators and the open-mandate constraint evaluation. See ap2.rb.
module AtlasPca
  module Ap2
    ZERO_DECIMAL = %w[BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF].freeze
    THREE_DECIMAL = %w[BHD IQD JOD KWD LYD OMR TND].freeze
    FOUR_DECIMAL = %w[CLF UYW].freeze

    module_function

    # ---- currencies and minor units -------------------------------------------------------------------------------------

    # ISO 4217 minor-unit exponent for `currency` (2 for any code not in the 0/3/4-digit tables).
    def currency_exponent(currency)
      text = currency.is_a?(String) ? currency : str(currency) # RegExp#test coerces its argument
      unless text.b.match?(/\A[A-Z]{3}\z/n)
        raise Ap2Error, "currency must be an ISO 4217 alpha-3 code, got #{undef?(currency) ? 'undefined' : Js.json(currency)}"
      end

      if currency.is_a?(String)
        return 0 if ZERO_DECIMAL.include?(currency)
        return 3 if THREE_DECIMAL.include?(currency)
        return 4 if FOUR_DECIMAL.include?(currency)
      end
      2
    end

    # A major-unit amount (`120.5` USD) to integer minor units (`12050`). Float drift (`0.1 + 0.2`) is refused rather than rounded away.
    def to_minor_units(major, currency)
      e = currency_exponent(currency)
      raise Ap2Error, "amount must be a finite non-negative number, got #{str(major)}" if !num?(major) || !finite?(major) || major.negative?

      m = major.to_f
      fixed = format('%.*f', e, m.abs)
      raise Ap2Error, "amount #{str(major)} is not exactly representable in #{currency} minor units" if fixed.to_f != m

      minor = fixed.delete('.').to_i
      raise Ap2Error, "amount #{str(major)} is outside the safe integer range in minor units" if minor > MAX_SAFE

      minor
    end

    # Integer minor units to the major-unit number PCA budgets use (exact for any safe integer).
    def from_minor_units(minor, currency)
      e = currency_exponent(currency)
      raise Ap2Error, "minor-unit amount must be a non-negative safe integer, got #{str(minor)}" if !safe_int?(minor) || minor.negative? || neg0?(minor)

      minor.to_f / (10**e)
    end

    # ---- mandate validators: each returns the list of problems (empty = valid) ------------------------------------------

    def merchant_problems(v, at)
      return ["#{at}: not an object"] unless v.is_a?(Hash)

      p = []
      p << "#{at}.id: required string" unless nonempty_str?(v['id'])
      p << "#{at}.name: required string" unless nonempty_str?(v['name'])
      p << "#{at}.website: must be a string" if v.key?('website') && !str?(v['website'])
      p
    end

    def currency_ok?(v) = v.is_a?(String) && v.b.match?(/\A[A-Z]{3}\z/n)

    def amount_problems(v, at)
      return ["#{at}: not an object"] unless v.is_a?(Hash)

      p = []
      p << "#{at}.amount: must be a non-negative integer (minor units)" unless nonneg_int?(v.key?('amount') ? v['amount'] : UNDEF)
      p << "#{at}.currency: must be an ISO 4217 alpha-3 code" unless currency_ok?(v['currency'])
      p
    end

    def instrument_problems(v, at)
      return ["#{at}: not an object"] unless v.is_a?(Hash)

      p = []
      p << "#{at}.id: required string" unless nonempty_str?(v['id'])
      p << "#{at}.type: required string" unless nonempty_str?(v['type'])
      p << "#{at}.description: must be a string" if v.key?('description') && !str?(v['description'])
      p
    end

    def pisp_problems(v, at)
      return ["#{at}: not an object"] unless v.is_a?(Hash)

      %w[legal_name brand_name domain_name].reject { |k| nonempty_str?(v[k]) }.map { |k| "#{at}.#{k}: required string" }
    end

    def time_problems(v) = %w[iat exp].select { |k| v.key?(k) && !nonneg_int?(v[k]) }.map { |k| "#{k}: must be an integer epoch-seconds" }

    def cnf_problems(v)
      return ['cnf: must be { jwk }'] if !v.is_a?(Hash) || !v['jwk'].is_a?(Hash)

      begin
        assert_p256_jwk(v['jwk'], 'cnf.jwk')
        []
      rescue Ap2Error => e
        [e.message]
      end
    end

    def pca_claim_problems(v) = v.key?(PCA_CLAIM) && !v[PCA_CLAIM].is_a?(Hash) ? ["#{PCA_CLAIM}: must be an object"] : []

    def list_problems(v, at, each)
      return ["#{at}: must be an array"] unless v.is_a?(Array)

      v.each_with_index.flat_map { |x, i| send(each, x, "#{at}[#{i}]") }
    end

    def payment_constraint_problems(c, at)
      return ["#{at}: constraint must be an object with a string type"] if !c.is_a?(Hash) || !str?(c['type'])

      t = c['type']
      case t
      when 'payment.agent_recurrence'
        p = []
        p << "#{at}.frequency: not a known frequency" if !str?(c['frequency']) || !FREQUENCIES.include?(c['frequency'])
        p << "#{at}.max_occurrences: must be a positive integer" if c.key?('max_occurrences') && !(int?(c['max_occurrences']) && c['max_occurrences'] > 0)
        p
      when 'payment.allowed_payees' then list_problems(c['allowed'], "#{at}.allowed", :merchant_problems)
      when 'payment.allowed_payment_instruments' then list_problems(c['allowed'], "#{at}.allowed", :instrument_problems)
      when 'payment.allowed_pisps' then list_problems(c['allowed'], "#{at}.allowed", :pisp_problems)
      when 'payment.amount_range'
        p = []
        p << "#{at}.currency: must be an ISO 4217 alpha-3 code" unless currency_ok?(c['currency'])
        p << "#{at}.max: must be a non-negative integer (minor units)" unless nonneg_int?(c.key?('max') ? c['max'] : UNDEF)
        p << "#{at}.min: must be a non-negative integer (minor units)" if c.key?('min') && !nonneg_int?(c['min'])
        p << "#{at}: min exceeds max" if int?(c.key?('max') ? c['max'] : UNDEF) && int?(c.key?('min') ? c['min'] : UNDEF) && c['min'] > c['max']
        p
      when 'payment.budget'
        p = []
        p << "#{at}.currency: must be an ISO 4217 alpha-3 code" unless currency_ok?(c['currency'])
        mx = c.key?('max') ? c['max'] : UNDEF
        p << "#{at}.max: must be a non-negative number (major units)" if !num?(mx) || !finite?(mx) || mx.negative?
        p
      when 'payment.execution_date'
        %w[not_before not_after].select { |k| c.key?(k) && !str?(c[k]) }.map { |k| "#{at}.#{k}: must be a string" }
      when 'payment.reference'
        nonempty_str?(c['conditional_transaction_id']) ? [] : ["#{at}.conditional_transaction_id: required string"]
      else ["#{at}: unknown constraint type #{t}"]
      end
    end

    def acceptable_item_problems(x, ax)
      return ["#{ax}: not an object"] unless x.is_a?(Hash)

      %w[id title].reject { |k| nonempty_str?(x[k]) }.map { |k| "#{ax}.#{k}: required string" }
    end

    def checkout_constraint_problems(c, at)
      return ["#{at}: constraint must be an object with a string type"] if !c.is_a?(Hash) || !str?(c['type'])

      case c['type']
      when 'checkout.allowed_merchants' then list_problems(c['allowed'], "#{at}.allowed", :merchant_problems)
      when 'checkout.line_items'
        items = c['items']
        return ["#{at}.items: must be a non-empty array"] if !items.is_a?(Array) || items.empty?

        out = []
        items.each_with_index do |it, i|
          a = "#{at}.items[#{i}]"
          unless it.is_a?(Hash)
            out << "#{a}: not an object"
            next
          end
          out << "#{a}.id: required string" unless nonempty_str?(it['id'])
          out << "#{a}.quantity: must be a positive integer" if !int?(it.key?('quantity') ? it['quantity'] : UNDEF) || it['quantity'] <= 0
          out.concat(list_problems(it['acceptable_items'], "#{a}.acceptable_items", :acceptable_item_problems))
        end
        out
      else ["#{at}: unknown constraint type #{c['type']}"]
      end
    end

    def vct_problem(v, want) = seq?(v.key?('vct') ? v['vct'] : UNDEF, want) ? [] : ["vct: must be #{want}"]

    def type?(constraints, t) = constraints.is_a?(Array) && constraints.any? { |c| c.is_a?(Hash) && seq?(c.key?('type') ? c['type'] : UNDEF, t) }

    def open_payment_mandate_problems(v)
      return ['mandate: not an object'] unless v.is_a?(Hash)

      p = vct_problem(v, VCT_PAYMENT_OPEN) + time_problems(v) + cnf_problems(v['cnf']) + pca_claim_problems(v)
      p.concat(list_problems(v['constraints'], 'constraints', :payment_constraint_problems))
      p << 'constraints: must contain a payment.reference constraint' if v['constraints'].is_a?(Array) && !type?(v['constraints'], 'payment.reference')
      p.concat(merchant_problems(v['payee'], 'payee')) if v.key?('payee')
      p.concat(amount_problems(v['payment_amount'], 'payment_amount')) if v.key?('payment_amount')
      p.concat(instrument_problems(v['payment_instrument'], 'payment_instrument')) if v.key?('payment_instrument')
      p.concat(pisp_problems(v['pisp'], 'pisp')) if v.key?('pisp')
      p << 'execution_date: must be a string' if v.key?('execution_date') && !str?(v['execution_date'])
      p << 'risk_data: must be an object' if v.key?('risk_data') && !v['risk_data'].is_a?(Hash)
      p
    end

    def payment_mandate_problems(v)
      return ['mandate: not an object'] unless v.is_a?(Hash)

      p = vct_problem(v, VCT_PAYMENT) + time_problems(v) + pca_claim_problems(v)
      p << 'transaction_id: required string' unless nonempty_str?(v['transaction_id'])
      p.concat(merchant_problems(v['payee'], 'payee'))
      p.concat(amount_problems(v['payment_amount'], 'payment_amount'))
      p.concat(instrument_problems(v['payment_instrument'], 'payment_instrument'))
      p.concat(pisp_problems(v['pisp'], 'pisp')) if v.key?('pisp')
      p << 'execution_date: must be a string' if v.key?('execution_date') && !str?(v['execution_date'])
      p << 'risk_data: must be an object' if v.key?('risk_data') && !v['risk_data'].is_a?(Hash)
      p
    end

    def open_checkout_mandate_problems(v)
      return ['mandate: not an object'] unless v.is_a?(Hash)

      p = vct_problem(v, VCT_CHECKOUT_OPEN) + time_problems(v) + cnf_problems(v['cnf']) + pca_claim_problems(v)
      p.concat(list_problems(v['constraints'], 'constraints', :checkout_constraint_problems))
      p << 'constraints: must contain a checkout.line_items constraint' if v['constraints'].is_a?(Array) && !type?(v['constraints'], 'checkout.line_items')
      p
    end

    def checkout_mandate_problems(v)
      return ['mandate: not an object'] unless v.is_a?(Hash)

      p = vct_problem(v, VCT_CHECKOUT) + time_problems(v) + pca_claim_problems(v)
      p << 'checkout_jwt: required string' unless nonempty_str?(v['checkout_jwt'])
      p << 'checkout_hash: required string' unless nonempty_str?(v['checkout_hash'])
      p
    end

    def assert_valid(v, problems, what)
      p = problems.call(v)
      raise Ap2Error, "#{what}: #{p.join('; ')}" unless p.empty?

      v
    end

    # ---- constraint evaluation ------------------------------------------------------------------------------------------

    def merchant_matches(candidate, target)
      cid = g(candidate, 'id')
      tid = g(target, 'id')
      return seq?(cid, tid) if truthy?(cid) && truthy?(tid)

      truthy?(g(candidate, 'name')) && truthy?(g(candidate, 'website')) &&
        seq?(g(candidate, 'name'), g(target, 'name')) && seq?(g(candidate, 'website'), g(target, 'website'))
    end

    def sort_keys(v)
      return v.map { |x| sort_keys(x) } if v.is_a?(Array)
      return v.keys.sort_by { |k| Payments.u16(k) }.to_h { |k| [k, sort_keys(v[k])] } if v.is_a?(Hash)

      v
    end

    # JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b)); two undefined values are equal.
    def same_json?(a, b)
      sa = undef?(a) ? nil : Js.json(sort_keys(a))
      sb = undef?(b) ? nil : Js.json(sort_keys(b))
      sa == sb
    end

    RFC3339 = /\A([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|([+-])([0-9]{2}):([0-9]{2})))?\z/n

    def days_from_civil(y, m, d)
      y -= 1 if m <= 2
      era = y / 400
      yoe = y - (era * 400)
      doy = (((153 * (m + (m > 2 ? -3 : 9))) + 2) / 5) + d - 1
      doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy
      (era * 146_097) + doe - 719_468
    end

    def civil_from_days(z)
      z += 719_468
      era = z / 146_097
      doe = z - (era * 146_097)
      yoe = (doe - (doe / 1460) + (doe / 36_524) - (doe / 146_096)) / 365
      y = yoe + (era * 400)
      doy = doe - ((365 * yoe) + (yoe / 4) - (yoe / 100))
      mp = ((5 * doy) + 2) / 153
      d = doy - (((153 * mp) + 2) / 5) + 1
      m = mp + (mp < 10 ? 3 : -9)
      [y + (m <= 2 ? 1 : 0), m, d]
    end

    def days_in_month(y, m)
      return ((y % 4).zero? && !(y % 100).zero?) || (y % 400).zero? ? 29 : 28 if m == 2

      [4, 6, 9, 11].include?(m) ? 30 : 31
    end

    # Epoch ms of an RFC 3339 instant, or nil. STRICT and independent of the host time zone: `YYYY-MM-DD` (UTC midnight) or
    # `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`, with every component in range.
    def parse_instant(s)
      return nil unless s.is_a?(String)

      m = RFC3339.match(s.b)
      return nil if m.nil?

      y = m[1].to_i
      mo = m[2].to_i
      d = m[3].to_i
      return nil unless mo.between?(1, 12) && d.between?(1, days_in_month(y, mo))

      day = days_from_civil(y, mo, d) * 86_400_000
      return day if m[4].nil?

      h = m[4].to_i
      mi = m[5].to_i
      se = m[6].to_i
      return nil if h > 23 || mi > 59 || se > 59

      ms = m[7].nil? ? 0 : m[7][0, 3].ljust(3, '0').to_i
      offset = 0
      if m[8] != 'Z'
        oh = m[10].to_i
        om = m[11].to_i
        return nil if oh > 23 || om > 59

        offset = (m[9] == '+' ? 1 : -1) * ((oh * 60) + om) * 60_000
      end
      day + ((((h * 60) + mi) * 60) + se) * 1000 + ms - offset
    end

    # Date.UTC: the years 0..99 mean 1900..1999.
    def date_utc(y, month0, d)
      y += 1900 if y.between?(0, 99)
      y += month0 / 12
      days_from_civil(y, (month0 % 12) + 1, d) * 86_400_000
    end

    # Start (epoch ms, UTC) of the calendar period of `frequency` that contains `ms`; nil for an unknown frequency.
    def period_start(ms, frequency)
      t = ms.to_i # TimeClip truncates
      days = t / 86_400_000
      y, mo, d = civil_from_days(days)
      day = date_utc(y, mo - 1, d)
      one_day = 86_400_000
      wd = (days + 4) % 7 # getUTCDay, 0 = Sunday
      case frequency
      when 'ON_DEMAND' then 0
      when 'DAILY' then day
      when 'WEEKLY' then day - (((wd + 6) % 7) * one_day)
      when 'BIWEEKLY'
        week_start = day - (((wd + 6) % 7) * one_day)
        week = 7 * one_day
        epoch_monday = -3 * one_day
        epoch_monday + (((week_start - epoch_monday) / (2 * week)) * 2 * week)
      when 'MONTHLY' then date_utc(y, mo - 1, 1)
      when 'QUARTERLY' then date_utc(y, ((mo - 1) / 3) * 3, 1)
      when 'ANNUALLY' then date_utc(y, 0, 1)
      end
    end

    # A usage context with a NaN, negative or fractional counter would make the cap comparisons fail open: refuse it.
    def context_problem(c)
      last = g(c, 'lastUsedDate')
      if !nonneg_int?(g(c, 'totalAmount')) || !nonneg_int?(g(c, 'totalUses')) || (!undef?(last) && !nonneg_int?(last))
        return 'mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate'
      end

      nil
    end

    def evaluate_payment(c, closed, o)
      amt = g(closed, 'payment_amount')
      t = g(c, 'type')
      ctx = o['context']
      case t
      when 'payment.amount_range'
        v = []
        unless seq?(g(amt, 'currency'), g(c, 'currency'))
          v << "currency mismatch: expected #{str(g(c, 'currency'))}, got #{str(g(amt, 'currency'))}"
        end
        v << "amount #{str(g(amt, 'amount'))} is not finite" unless fin_num?(g(amt, 'amount'))
        mn = g(c, 'min')
        v << "amount #{str(g(amt, 'amount'))} below minimum #{str(mn)}" if !undef?(mn) && !ge?(g(amt, 'amount'), mn)
        v << "amount #{str(g(amt, 'amount'))} exceeds maximum #{str(g(c, 'max'))}" unless le?(g(amt, 'amount'), g(c, 'max'))
        v
      when 'payment.allowed_payees'
        return [] if iter_list(g(c, 'allowed')).any? { |m| merchant_matches(m, g(closed, 'payee')) }

        ["payee #{str(g(g(closed, 'payee'), 'name'))} is not in the allowed list"]
      when 'payment.allowed_payment_instruments'
        inst = g(g(closed, 'payment_instrument'), 'id')
        return [] if iter_list(g(c, 'allowed')).any? { |i| seq?(g(i, 'id'), inst) }

        ["payment instrument #{str(inst)} is not in the allowed list"]
      when 'payment.allowed_pisps'
        p = g(closed, 'pisp')
        return ['missing PISP in the closed mandate'] unless truthy?(p)

        ok = iter_list(g(c, 'allowed')).any? do |a|
          seq?(g(a, 'legal_name'), g(p, 'legal_name')) && seq?(g(a, 'brand_name'), g(p, 'brand_name')) && seq?(g(a, 'domain_name'), g(p, 'domain_name'))
        end
        ok ? [] : ['PISP is not in the allowed list']
      when 'payment.reference'
        h = o['open_checkout_hash']
        return ['openCheckoutHash is required to evaluate a payment.reference constraint'] unless truthy?(h)

        seq?(h, g(c, 'conditional_transaction_id')) ? [] : ['payment.reference does not match the open checkout mandate hash']
      when 'payment.budget'
        unless seq?(g(amt, 'currency'), g(c, 'currency'))
          return ["budget currency mismatch: expected #{str(g(c, 'currency'))}, got #{str(g(amt, 'currency'))}"]
        end
        # the official SDK converts the budget with `int(max * 100)` for every currency; this reads it the same way
        return ['mandate context is required to evaluate a budget'] unless truthy?(ctx)

        bad = context_problem(ctx)
        return [bad] if bad

        scaled = to_number(g(c, 'max')) * 100
        return ['budget.max is not a whole number of minor units'] unless scaled.finite?

        max_minor = js_round(scaled)
        return ['budget.max is not a whole number of minor units'] unless (scaled - max_minor).abs <= 1e-6

        spend = ctx['totalAmount'].to_f + to_number(g(amt, 'amount'))
        return [] if spend.finite? && spend <= max_minor

        ["cumulative spend #{Js.string(spend)} exceeds budget #{Js.string(max_minor)} (past spend #{str(ctx['totalAmount'])})"]
      when 'payment.agent_recurrence'
        v = []
        return ['unknown recurrence frequency'] unless FREQUENCIES.include?(g(c, 'frequency')) # strict, with or without a last-used date

        if truthy?(ctx)
          bad = context_problem(ctx)
          return [bad] if bad
        end
        mo = g(c, 'max_occurrences')
        unless undef?(mo)
          return ['mandate context is required to evaluate recurrence limits'] unless truthy?(ctx)

          v << "maximum occurrences exceeded: #{str(ctx['totalUses'])} >= #{str(mo)}" unless lt?(ctx['totalUses'], mo)
        end
        unless seq?(g(c, 'frequency'), 'ON_DEMAND')
          return ['mandate context is required to evaluate recurrence frequency'] unless truthy?(ctx)

          last = ctx.key?('lastUsedDate') ? ctx['lastUsedDate'] : UNDEF
          unless undef?(last)
            now_ms = Float(o['now']) * 1000
            start = now_ms.finite? ? period_start(now_ms, g(c, 'frequency')) : Float::NAN # a non-finite clock reads as used
            v << "already used in the current #{str(g(c, 'frequency'))} period" if !start.nil? && !lt?(Float(last) * 1000, start)
          end
        end
        v
      when 'payment.execution_date'
        ed = g(closed, 'execution_date')
        at = undef?(ed) ? Float(o['now']) * 1000 : parse_instant(ed)
        return ["execution_date #{str(ed)} is not a valid instant"] if at.nil? || !at.finite?

        v = []
        [['not_before', g(c, 'not_before'), true], ['not_after', g(c, 'not_after'), false]].each do |key, bound, before|
          next if undef?(bound)

          b = parse_instant(bound)
          if b.nil?
            v << "#{key} #{str(bound)} is not a valid instant"
          elsif before ? !(at >= b) : !(at <= b)
            v << "execution date is #{before ? 'before' : 'after'} the allowed window (#{key} #{str(bound)})"
          end
        end
        v
      else ["unknown constraint type #{str(t)}"]
      end
    end

    # Violations of the open payment mandate's constraints and pre-set claims by `closed` (empty = satisfied).
    # o: open_checkout_hash?, context? ({ 'totalAmount', 'totalUses', 'lastUsedDate'? }), now.
    def check_payment_constraints(open_, closed, o)
      v = []
      if !undef?(g(open_, 'payee')) && !merchant_matches(open_['payee'], g(closed, 'payee'))
        v << "pre-set payee mismatch: expected #{str(g(open_['payee'], 'name'))}, got #{str(g(g(closed, 'payee'), 'name'))}"
      end
      if !undef?(g(open_, 'payment_amount')) && !same_json?(open_['payment_amount'], g(closed, 'payment_amount'))
        v << 'pre-set payment_amount mismatch'
      end
      if !undef?(g(open_, 'payment_instrument')) && !same_json?(open_['payment_instrument'], g(closed, 'payment_instrument'))
        v << 'pre-set payment_instrument mismatch'
      end
      v << 'pre-set pisp mismatch' if !undef?(g(open_, 'pisp')) && !same_json?(open_['pisp'], g(closed, 'pisp'))
      v << 'pre-set execution_date mismatch' if !undef?(g(open_, 'execution_date')) && !seq?(open_['execution_date'], g(closed, 'execution_date'))
      constraints = iter_list(g(open_, 'constraints'))
      types = constraints.map { |c| g(c, 'type') }
      if types.include?('payment.agent_recurrence')
        v << 'payment.agent_recurrence requires a payment.amount_range constraint' unless types.include?('payment.amount_range')
        v << 'payment.agent_recurrence requires a payment.budget constraint' unless types.include?('payment.budget')
      end
      constraints.each { |c| v.concat(evaluate_payment(c, closed, o)) }
      v
    end

    # Validate and project the checkout payload (`checkout_jwt`); raises a descriptive message when malformed.
    def project_checkout(payload)
      bad = ->(m) { raise Ap2Error, "checkout_jwt payload: #{m}" }
      pid = g(payload, 'id')
      cur = g(payload, 'currency')
      lis = g(payload, 'line_items')
      totals = g(payload, 'totals')
      bad.call('id is required') if !pid.is_a?(String) || pid.empty?
      bad.call('currency must be ISO 4217') unless currency_ok?(cur)
      bad.call('line_items must be a non-empty array') if !lis.is_a?(Array) || lis.empty?
      bad.call('totals must be an array') unless totals.is_a?(Array)
      line_items = []
      lis.each_with_index do |li, i|
        bad.call("line_items[#{i}] is malformed") if !li.is_a?(Hash) || !li['id'].is_a?(String) || !li['item'].is_a?(Hash)

        item = li['item']
        price = item.key?('price') ? item['price'] : UNDEF
        if !item['id'].is_a?(String) || !item['title'].is_a?(String) || !safe_int?(price) || price.negative? || neg0?(price)
          bad.call("line_items[#{i}].item needs id, title and integer minor-unit price")
        end
        qty = li.key?('quantity') ? li['quantity'] : UNDEF
        bad.call("line_items[#{i}].quantity must be a positive integer") if !safe_int?(qty) || qty < 1
        line_items << { 'id' => li['id'], 'item' => { 'id' => item['id'], 'title' => item['title'], 'price' => price }, 'quantity' => qty }
      end
      tt = []
      totals.each_with_index do |t, i|
        bad.call("totals[#{i}] is malformed") if !t.is_a?(Hash) || !t['type'].is_a?(String) || !safe_int?(t.key?('amount') ? t['amount'] : UNDEF) || neg0?(t['amount'])

        tt << { 'type' => t['type'], 'amount' => t['amount'] }
      end
      merchant = nil
      if payload.key?('merchant')
        m = payload['merchant']
        bad.call('merchant needs id and name') if !m.is_a?(Hash) || !m['id'].is_a?(String) || !m['name'].is_a?(String)

        merchant = { 'id' => m['id'], 'name' => m['name'] }
        merchant['website'] = m['website'] if m['website'].is_a?(String)
      end
      out = { 'id' => pid, 'currency' => cur, 'line_items' => line_items, 'totals' => tt }
      out['merchant'] = merchant unless merchant.nil?
      out
    end

    # The checkout's single `total` entry in minor units, or nil if absent / ambiguous.
    def checkout_total(c)
      t = c['totals'].select { |x| seq?(g(x, 'type'), 'total') }
      t.length == 1 ? t[0]['amount'] : nil
    end

    # Maximal-flow assignment of cart quantities to requirement slots (Edmonds-Karp): satisfied iff the flow equals both the
    # required and the carted total.
    def line_item_violations(cart, reqs)
      qty = {}
      cart.each do |li|
        k = li['item']['id']
        qty[k] = (qty.key?(k) ? qty[k] : 0) + li['quantity']
      end
      skus = qty.keys
      src = 0
      sink = 1 + skus.length + reqs.length
      cap = Array.new(sink + 1) { {} }
      add = lambda do |u, v, c|
        cap[u][v] = (cap[u].key?(v) ? cap[u][v] : 0) + c
        cap[v][u] = cap[v].key?(u) ? cap[v][u] : 0
      end
      inf = MAX_SAFE
      skus.each_with_index { |s, i| add.call(src, 1 + i, qty[s]) }
      reqs.each_with_index do |r, j|
        add.call(1 + skus.length + j, sink, g(r, 'quantity'))
        ok = iter_list(g(r, 'acceptable_items')).map { |a| g(a, 'id') }
        skus.each_with_index { |s, i| add.call(1 + i, 1 + skus.length + j, inf) if ok.any? { |x| seq?(s, x) } }
      end
      flow = 0
      loop do
        parent = { src => src }
        queue = [src]
        h = 0
        while h < queue.length && !parent.key?(sink)
          u = queue[h]
          h += 1
          cap[u].to_a.each do |v, c|
            if c > 0 && !parent.key?(v)
              parent[v] = u
              queue << v
            end
          end
        end
        break unless parent.key?(sink)

        push = inf
        v = sink
        while v != src
          push = [push, cap[parent[v]][v]].min
          v = parent[v]
        end
        v = sink
        while v != src
          u = parent[v]
          cap[u][v] = cap[u][v] - push
          cap[v][u] = cap[v][u] + push
          v = u
        end
        flow += push
      end
      required = 0
      reqs.each { |r| required += g(r, 'quantity') }
      carted = 0
      qty.each_value { |q| carted += q }
      return [] if flow == required && flow == carted

      ["line items do not satisfy the constraint: assigned #{Js.string(flow)} of #{Js.string(required)} required and #{Js.string(carted)} carted units"]
    end

    def evaluate_checkout(c, checkout)
      t = g(c, 'type')
      if t == 'checkout.allowed_merchants'
        m = checkout['merchant']
        return ['missing merchant in the checkout'] unless truthy?(m)

        return [] if iter_list(g(c, 'allowed')).any? { |a| merchant_matches(a, m) }

        return ["merchant #{str(g(m, 'name'))} is not in the allowed list"]
      end
      return ["unknown constraint type #{str(t)}"] unless t == 'checkout.line_items'
      return ['empty cart does not satisfy a line_items constraint'] if checkout['line_items'].empty?

      line_item_violations(checkout['line_items'], iter_list(g(c, 'items')))
    end

    # Violations of the open checkout mandate's constraints by `checkout` (empty = satisfied).
    def check_checkout_constraints(open_, checkout)
      out = []
      iter_list(g(open_, 'constraints')).each { |c| out.concat(evaluate_checkout(c, checkout)) }
      out
    end
  end
end
