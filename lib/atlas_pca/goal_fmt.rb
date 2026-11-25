# frozen_string_literal: true

require_relative 'goal_js'
require_relative 'goal_normalize'

module AtlasPca
  # Rendering helpers for quantities, values and actions (the TypeScript reference is @atlasauth/pca-goal `fmt`).
  module GoalFmt
    J = GoalJs
    # An unknown currency is shown in raw minor units, never guessed.
    CCY_EXPONENT = { 'USD' => 2, 'EUR' => 2, 'GBP' => 2, 'CAD' => 2, 'AUD' => 2, 'CHF' => 2, 'JPY' => 0, 'KRW' => 0 }.freeze

    module_function

    def fmt_money(ccy, minor)
      e = ccy.is_a?(String) ? CCY_EXPONENT[ccy] : nil
      return "#{J.js_str(ccy)} #{J.js_str(minor)} (minor units)" if e.nil?
      return "#{J.js_str(ccy)} #{J.js_str(minor)}" if e.zero?

      s = J.js_str(minor).rjust(e + 1, '0')
      "#{J.js_str(ccy)} #{s[0...-e]}.#{s[-e..]}"
    end

    # The rendered text; UNDEF (JavaScript undefined) for an unknown unit tag.
    def fmt_quantity(q)
      u = J.jget(q, 'u')
      k = J.jget(u, 'k')
      n = J.jget(q, 'n')
      case k
      when 'money' then fmt_money(J.jget(u, 'ccy'), n)
      when 'count' then J.js_str(n)
      when 'duration' then "#{J.js_str(n)}ms"
      when 'instant' then "@#{J.js_str(n)}"
      when 'bytes' then "#{J.js_str(n)}B"
      when 'ratio' then "#{J.js_str(n)}ppm"
      else J::UNDEF
      end
    end

    def fmt_value(v)
      k = J.jget(v, 'k')
      return fmt_quantity(J.jget(v, 'q')) if k == 'q'
      return (J.undef?(J.jget(v, 's')) ? J::UNDEF : GoalNormalize.jq(J.jget(v, 's'))) if k == 's'

      "{#{J.req_list(J.jget(v, 'items')).map { |i| x = fmt_value(i); J.undef?(x) ? '' : x }.join(', ')}}"
    end

    def fmt_act(a)
      params = J.jget(a, 'params')
      ps = J.okeys(params).sort_by { |k| J.u16key(k) }.map { |k| "#{k}=#{J.js_str(fmt_value(J.kget(params, k)))}" }.join(', ')
      "#{J.js_str(J.jget(a, 'verb'))} on #{J.js_str(J.jget(a, 'res'))}#{ps.empty? ? '' : " (#{ps})"}"
    end
  end
end
